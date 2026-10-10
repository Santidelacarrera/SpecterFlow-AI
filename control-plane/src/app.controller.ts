import { Body, Controller, Get, Param, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import { Response } from 'express';
import { cfg } from './common/config';
import { EventsService } from './events/events.service';
import { MetricsService } from './metrics/metrics.service';
import { AgentsService } from './agents/agents.service';
import { ApprovalsService } from './approvals/approvals.service';
import { AuditService } from './audit/audit.service';
import { Internal, Public, Roles } from './auth/auth';
import { BreakerService } from './breaker/breaker.service';
import { CampaignsService } from './campaigns/campaigns.service';
import { IncidentsService } from './incidents/incidents.service';

@Controller()
export class AppController {
  constructor(
    private readonly agents: AgentsService,
    private readonly approvals: ApprovalsService,
    private readonly audit: AuditService,
    private readonly breaker: BreakerService,
    private readonly campaigns: CampaignsService,
    private readonly incidents: IncidentsService,
    private readonly events: EventsService,
    private readonly metrics: MetricsService,
  ) {}

  @Public() @Get('health') health() {
    return { status: 'ok', service: 'control-plane' };
  }

  /** Métricas Prometheus. Protegidas con METRICS_TOKEN (Bearer) si está definido; si no, requieren API key. */
  @Public() @Get('metrics') metricsText(@Req() req: any, @Res() res: Response) {
    const token = cfg().metricsToken;
    const ok = token ? req.headers.authorization === `Bearer ${token}` : !!cfg().apiKeys[String(req.headers['x-api-key'])];
    if (!ok) throw new UnauthorizedException();
    res.type('text/plain; version=0.0.4').send(this.metrics.render());
  }

  /** Stream SSE de eventos en vivo (incidentes, breakers, aprobaciones). */
  @Get('api/events') stream(@Req() req: any, @Res() res: Response) {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
    res.write(': connected\n\n');
    const off = this.events.subscribe((e) => res.write(`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`));
    const ping = setInterval(() => res.write(': ping\n\n'), 25_000);
    req.on('close', () => {
      clearInterval(ping);
      off();
    });
  }

  @Get('api/me') me(@Req() req: any) {
    return req.principal;
  }

  // --- Agentes ---
  @Get('api/agents') listAgents() {
    return this.agents.list().map((a) => ({ ...a, breaker: this.breaker.status(a.id) }));
  }
  @Roles('SECOPS', 'FINOPS') @Post('api/agents') registerAgent(@Body() b: { id: string; url: string }, @Req() req: any) {
    const a = this.agents.register(b.id, b.url);
    this.audit.append(`${req.principal.role}:${req.principal.keyId}`, 'agent.registered', { id: a.id, url: a.url });
    return a;
  }
  @Roles('SECOPS') @Post('api/agents/:id/breaker/reset') resetBreaker(@Param('id') id: string, @Req() req: any) {
    this.breaker.reset(id);
    this.audit.append(`${req.principal.role}:${req.principal.keyId}`, 'breaker.reset', { id });
    return this.breaker.status(id);
  }

  // --- Red Teaming ---
  @Get('api/campaigns') listCampaigns() {
    return this.campaigns.list();
  }
  @Roles('SECOPS') @Post('api/campaigns') async startCampaign(@Body() b: { targetUrl: string; attackIds?: string[]; budgetUsd?: number }, @Req() req: any) {
    this.audit.append(`${req.principal.role}:${req.principal.keyId}`, 'campaign.requested', { targetUrl: b.targetUrl });
    return this.campaigns.create(b.targetUrl, b.attackIds, b.budgetUsd);
  }

  // --- Incidentes ---
  @Get('api/incidents') listIncidents() {
    return this.incidents.list();
  }

  // --- Bandeja de aprobación ---
  @Get('api/approvals') listApprovals(@Query('status') status?: string) {
    return this.approvals.list(status);
  }
  @Roles('SECOPS', 'FINOPS') @Post('api/approvals/:id/approve') approve(@Param('id') id: string, @Body() b: { comment?: string }, @Req() req: any) {
    return this.approvals.decide(id, req.principal, 'approve', b?.comment);
  }
  @Roles('SECOPS', 'FINOPS') @Post('api/approvals/:id/reject') reject(@Param('id') id: string, @Body() b: { comment?: string }, @Req() req: any) {
    return this.approvals.decide(id, req.principal, 'reject', b?.comment);
  }

  // --- Auditoría ---
  @Get('api/audit') listAudit(@Query('limit') limit?: string) {
    return this.audit.list(limit ? Number(limit) : 200);
  }
  @Get('api/audit/verify') verifyAudit() {
    return this.audit.verify();
  }

  // --- Mitigaciones activas ---
  @Get('api/mitigations') mitigations() {
    return { blockedIps: this.agents.blocked(), rules: this.agents.listRules() };
  }

  // --- Interno (worker) ---
  @Internal() @Post('internal/campaign-results') campaignResult(@Body() b: { job: any; report?: any; error?: string }) {
    if (b.error || !b.report) {
      this.campaigns.fail(b.job.campaignId, b.error ?? 'no report');
      return { ok: false };
    }
    return { ok: true, ...this.campaigns.complete(b.job, b.report) };
  }
}
