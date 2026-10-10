import { All, Controller, HttpException, Req, Res } from '@nestjs/common';
import { Request, Response } from 'express';
import { AgentsService } from '../agents/agents.service';
import { AuditService } from '../audit/audit.service';
import { BreakerService, hashPrompt, promptWords } from '../breaker/breaker.service';
import { cfg, costUsd, estimateTokens } from '../common/config';
import { EventsService } from '../events/events.service';
import { MetricsService } from '../metrics/metrics.service';
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
    private readonly metrics: MetricsService,
    private readonly events: EventsService,
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
      words: promptWords(promptText),
      promptPreview: promptText.slice(0, 120),
      costUsd: cost,
      ok: status < 400,
      sourceIp: ip,
      status,
    });
    this.metrics.inc('specterflow_proxy_requests_total', { agent: agentId, status: String(status) });
    this.metrics.inc('specterflow_tokens_total', { agent: agentId, direction: 'in' }, inTok);
    this.metrics.inc('specterflow_tokens_total', { agent: agentId, direction: 'out' }, outTok);
    this.metrics.inc('specterflow_cost_usd_total', { agent: agentId }, cost);
    if (trip) {
      this.audit.append('breaker', 'breaker.tripped', { agentId, reason: trip.reason, detail: trip.detail });
      this.metrics.inc('specterflow_breaker_trips_total', { agent: agentId, reason: trip.reason });
      this.events.emit('breaker', { agentId, reason: trip.reason }, `Circuit breaker ABIERTO en ${agentId}: ${trip.detail}`);
      this.incidents.fromTrip(trip);
    }
    if (cfg().liveClassify && status < 400) void this.classifyLive(agentId, promptText, text);

    res.status(status).setHeader('x-sf-cost-usd', cost.toFixed(6)).setHeader('x-sf-tokens', `${inTok}/${outTok}`);
    res.type('application/json').send(text || JSON.stringify({ error: 'upstream unavailable' }));
  }

  /** Evaluación de intención sobre tráfico real vía engine (no bloquea la respuesta). */
  private async classifyLive(agentId: string, prompt: string, rawReply: string): Promise<void> {
    try {
      let reply = rawReply;
      let tool_calls: unknown[] = [];
      try {
        const j = JSON.parse(rawReply);
        reply = String(j.reply ?? rawReply);
        tool_calls = Array.isArray(j.tool_calls) ? j.tool_calls : [];
      } catch {
        /* texto plano */
      }
      const r = await fetch(`${cfg().engineUrl}/v1/classify`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt, reply, tool_calls }),
        signal: AbortSignal.timeout(5000),
      });
      if (!r.ok) return;
      const v = (await r.json()) as { classification: { exploited: boolean; severity: any; indicators: string[] } };
      if (v.classification.exploited) this.incidents.fromLiveTraffic(agentId, v.classification.severity, v.classification.indicators, prompt, reply);
    } catch {
      /* el engine es opcional para el camino caliente */
    }
  }
}
