import { All, Controller, HttpException, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { AgentsService } from '../agents/agents.service';
import { AuditService } from '../audit/audit.service';
import { BreakerService, hashPrompt } from '../breaker/breaker.service';
import { costUsd, estimateTokens } from '../common/config';
import { IncidentsService } from '../incidents/incidents.service';

function extractPrompt(body: unknown): string {
  if (typeof body === 'string') return body;
  if (body && typeof body === 'object') {
    const b = body as Record<string, unknown>;
    for (const k of ['message', 'prompt', 'input']) if (typeof b[k] === 'string') return b[k] as string;
    return JSON.stringify(body);
  }
  return '';
}

/** Proxy de tráfico hacia agentes: reglas de gateway, bloqueo de IP, métricas de tokens y circuit breaker. */
@Controller('proxy')
export class ProxyController {
  constructor(
    private readonly agents: AgentsService,
    private readonly breaker: BreakerService,
    private readonly incidents: IncidentsService,
    private readonly audit: AuditService,
  ) {}

  @All(':agentId')
  root(@Req() req: Request, @Res() res: Response) {
    return this.handle(req, res, '');
  }

  @All(':agentId/*')
  nested(@Req() req: Request, @Res() res: Response) {
    return this.handle(req, res, (req.params as any)[0] ?? '');
  }

  private async handle(req: Request, res: Response, path: string) {
    const agentId = String(req.params.agentId);
    const agent = this.agents.get(agentId);
    if (!agent) throw new HttpException('unknown agent', 404);
    const ip = req.ip ?? 'unknown';
    const promptText = extractPrompt(req.body);

    if (this.agents.isBlocked(ip)) throw new HttpException('ip blocked by approved mitigation', 403);
    if (agent.paused) throw new HttpException('agent paused by approved containment', 423);
    const rule = this.agents.matchRule(agentId, promptText);
    if (rule) {
      this.audit.append('gateway', 'request.blocked_by_rule', { agentId, rule: rule.id, ip });
      throw new HttpException(`blocked by gateway rule ${rule.id}`, 403);
    }
    const gate = this.breaker.allow(agentId);
    if (!gate.allowed) {
      res.setHeader('Retry-After', String(gate.retryAfterSec ?? 60));
      throw new HttpException('circuit breaker open', 503);
    }

    let status = 502;
    let text = '';
    try {
      const url = `${agent.url}/${path}`.replace(/\/$/, '') + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
      const hasBody = !['GET', 'HEAD'].includes(req.method);
      const upstream = await fetch(url, {
        method: req.method,
        headers: { 'content-type': 'application/json' },
        body: hasBody ? JSON.stringify(req.body ?? {}) : undefined,
        signal: AbortSignal.timeout(30_000),
      });
      status = upstream.status;
      text = await upstream.text();
    } catch {
      status = 502;
    }

    let inTok = estimateTokens(promptText);
    let outTok = estimateTokens(text);
    try {
      const j = JSON.parse(text);
      if (j?.tokens) {
        inTok = Number(j.tokens.input ?? inTok);
        outTok = Number(j.tokens.output ?? outTok);
      }
    } catch {
      /* respuesta no JSON: se mantiene la estimación */
    }
    const cost = costUsd(inTok, outTok);

    const trip = this.breaker.record(agentId, {
      promptHash: hashPrompt(promptText),
      promptPreview: promptText.slice(0, 120),
      costUsd: cost,
      ok: status < 400,
      sourceIp: ip,
      status,
    });
    if (trip) {
      this.audit.append('breaker', 'breaker.tripped', { agentId, reason: trip.reason, detail: trip.detail });
      this.incidents.fromTrip(trip);
    }

    res.status(status).setHeader('x-sf-cost-usd', cost.toFixed(6)).setHeader('x-sf-tokens', `${inTok}/${outTok}`);
    res.type('application/json').send(text || JSON.stringify({ error: 'upstream unavailable' }));
  }
}
