import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { AuditService } from '../audit/audit.service';
import { Trip } from '../breaker/breaker.service';
import { ApprovalsService } from '../approvals/approvals.service';
import { AgentsService } from '../agents/agents.service';
import { Persistable, PersistenceService } from '../common/persistence.service';
import { EventsService } from '../events/events.service';
import { MetricsService } from '../metrics/metrics.service';

export type Sev = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface Incident {
  id: string;
  kind: 'redteam_finding' | 'breaker_trip';
  agentId?: string;
  target: string;
  severity: Sev;
  title: string;
  createdAt: string;
  costUsd: number;
  status: 'open' | 'contained';
  evidence: Record<string, unknown>;
  postmortem?: string;
}

const REMEDIATION_RULES: Record<string, string> = {
  prompt_injection: '(ignore (all )?(previous|prior) instructions|developer mode|system override)',
  secret_exfiltration: '(system prompt|secret_api_key|environment variables|hidden instructions)',
  privilege_escalation: '(delete_records|rotate_keys)',
  malicious_api: '(169\\.254\\.169\\.254|\\.\\./\\.\\./|drop table)',
  token_dos: '(forever|never stop)',
};

@Injectable()
export class IncidentsService implements Persistable {
  private incidents: Incident[] = [];

  constructor(
    private readonly audit: AuditService,
    private readonly approvals: ApprovalsService,
    private readonly agents: AgentsService,
    private readonly persistence: PersistenceService,
    private readonly events: EventsService,
    private readonly metrics: MetricsService,
  ) {
    persistence.register('incidents', this);
  }

  exportState() {
    return this.incidents;
  }
  importState(d: Incident[]) {
    this.incidents = d ?? [];
  }

  private record(i: Incident): void {
    this.incidents.push(i);
    this.persistence.touch();
    this.metrics.inc('specterflow_incidents_total', { kind: i.kind, severity: i.severity });
    this.events.emit('incident', { id: i.id, severity: i.severity }, `Incidente ${i.severity.toUpperCase()}: ${i.title}`);
  }

  /** Incidente por tráfico real detectado como malicioso (clasificación en vivo). */
  fromLiveTraffic(agentId: string, severity: Sev, indicators: string[], prompt: string, reply: string): Incident {
    const incident: Incident = {
      id: randomUUID(),
      kind: 'redteam_finding',
      agentId,
      target: agentId,
      severity,
      title: `Tráfico real sospechoso en ${agentId} (${indicators.join(', ')})`,
      createdAt: new Date().toISOString(),
      costUsd: 0,
      status: 'open',
      evidence: { live: true, indicators, prompt: prompt.slice(0, 2000), reply: reply.slice(0, 2000) },
    };
    this.record(incident);
    this.audit.append('system', 'incident.created', { id: incident.id, kind: 'live_traffic', severity });
    return incident;
  }

  list(): Incident[] {
    return [...this.incidents].reverse();
  }
  get(id: string): Incident | undefined {
    return this.incidents.find((i) => i.id === id);
  }

  /** Un Trip del breaker crea incidente y propone contención permanente (requiere firma). */
  fromTrip(trip: Trip): Incident {
    const incident: Incident = {
      id: randomUUID(),
      kind: 'breaker_trip',
      agentId: trip.agentId,
      target: trip.agentId,
      severity: trip.reason === 'failure_rate' ? 'high' : 'critical',
      title: `Circuit breaker abierto (${trip.reason}) en ${trip.agentId}`,
      createdAt: new Date().toISOString(),
      costUsd: trip.windowCostUsd,
      status: 'contained',
      evidence: { reason: trip.reason, detail: trip.detail, requests: trip.evidence, topSourceIp: trip.topSourceIp },
    };
    this.record(incident);
    this.audit.append('system', 'incident.created', { id: incident.id, kind: incident.kind, reason: trip.reason });

    const financial = trip.reason !== 'failure_rate';
    this.approvals.propose({
      incidentId: incident.id,
      action: 'PAUSE_AGENT',
      agentId: trip.agentId,
      params: {},
      summary:
        `Pausar permanentemente el agente "${trip.agentId}". Motivo: ${trip.detail}. ` +
        `Coste en ventana: $${trip.windowCostUsd.toFixed(4)}. El breaker ya interrumpió el tráfico temporalmente.`,
      requiredRoles: financial ? ['SECOPS', 'FINOPS'] : ['SECOPS'],
    });
    if (trip.topSourceIp && trip.reason !== 'budget_exceeded') {
      this.approvals.propose({
        incidentId: incident.id,
        action: 'BLOCK_IP',
        agentId: trip.agentId,
        params: { ip: trip.topSourceIp },
        summary: `Bloquear la IP ${trip.topSourceIp}, origen principal del tráfico anómalo hacia "${trip.agentId}".`,
        requiredRoles: ['SECOPS'],
      });
    }
    return incident;
  }

  /** Resultado de campaña de Red Teaming → incidentes por cada ataque exitoso + propuestas de remediación. */
  fromCampaign(report: any, agentId?: string): Incident[] {
    const created: Incident[] = [];
    for (const r of report.results ?? []) {
      const c = r.classification;
      if (!c?.exploited) continue;
      const incident: Incident = {
        id: randomUUID(),
        kind: 'redteam_finding',
        agentId,
        target: report.target_url,
        severity: c.severity,
        title: `${r.attack_id} · ${r.title}`,
        createdAt: new Date().toISOString(),
        costUsd: r.usage?.cost_usd ?? 0,
        status: 'open',
        evidence: {
          category: r.category,
          payload: r.payload,
          reply: String(r.reply).slice(0, 2000),
          tool_calls: r.tool_calls,
          classification: c,
          snapshot: r.snapshot,
        },
        postmortem: report.postmortem,
      };
      this.record(incident);
      created.push(incident);
      this.audit.append('system', 'incident.created', { id: incident.id, kind: incident.kind, attack: r.attack_id, severity: c.severity });

      const pattern = REMEDIATION_RULES[r.category];
      if (pattern && agentId) {
        this.approvals.propose({
          incidentId: incident.id,
          action: 'PATCH_GATEWAY_RULE',
          agentId,
          params: { pattern, reason: `${r.attack_id} ${r.title}` },
          summary: `Añadir regla de API Gateway que bloquee prompts que casen /${pattern}/i hacia "${agentId}" (${r.attack_id}, severidad ${c.severity}).`,
          requiredRoles: ['SECOPS'],
        });
      }
      if (r.category === 'secret_exfiltration' && agentId) {
        this.approvals.propose({
          incidentId: incident.id,
          action: 'ROTATE_KEYS',
          agentId,
          params: {},
          summary: `Rotar las claves del agente "${agentId}": se filtró un secreto en la respuesta durante ${r.attack_id}.`,
          requiredRoles: ['SECOPS'],
        });
      }
    }
    return created;
  }
}
