import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { AgentsService } from '../agents/agents.service';
import { AuditService } from '../audit/audit.service';
import { cfg, Role } from '../common/config';
import { Entity, Persistable, PersistenceService } from '../common/persistence.service';
import { EventsService } from '../events/events.service';
import { MetricsService } from '../metrics/metrics.service';

export type ActionType = 'PAUSE_AGENT' | 'BLOCK_IP' | 'ROTATE_KEYS' | 'PATCH_GATEWAY_RULE';

export interface Signature {
  keyId: string;
  role: Role;
  signedAs: Role;
  decision: 'approve' | 'reject';
  at: string;
  comment?: string;
}

export interface Approval {
  id: string;
  incidentId: string;
  action: ActionType;
  agentId: string;
  params: Record<string, unknown>;
  summary: string;
  requiredRoles: Role[];
  signatures: Signature[];
  status: 'pending' | 'approved' | 'rejected';
  createdAt: string;
  appliedAt?: string;
  /** Resultado de la ejecución en sistemas reales (MITIGATION_WEBHOOK_URL → executor). */
  execution?: { status: 'ok' | 'failed'; attempts: number; detail: string; at: string };
}

type Proposal = Pick<Approval, 'incidentId' | 'action' | 'agentId' | 'params' | 'summary' | 'requiredRoles'>;

@Injectable()
export class ApprovalsService implements Persistable {
  private items: Approval[] = [];

  constructor(
    private readonly audit: AuditService,
    private readonly agents: AgentsService,
    private readonly persistence: PersistenceService,
    private readonly events: EventsService,
    private readonly metrics: MetricsService,
  ) {
    persistence.register(this);
    metrics.gauge('specterflow_approvals_pending', {}, () => this.items.filter((a) => a.status === 'pending').length);
  }

  readonly kinds = ['approval'];

  exportEntities(): Entity[] {
    return this.items.map((a) => ({ kind: 'approval', id: a.id, data: a }));
  }
  importEntity(_kind: string, id: string, data: Approval) {
    const i = this.items.findIndex((x) => x.id === id);
    if (i >= 0) this.items[i] = data;
    else this.items.push(data);
  }

  propose(p: Proposal): Approval {
    // Evita saturar la bandeja: una misma acción pendiente sobre el mismo agente/parámetros se reutiliza.
    const dup = this.items.find(
      (x) => x.status === 'pending' && x.action === p.action && x.agentId === p.agentId && JSON.stringify(x.params) === JSON.stringify(p.params),
    );
    if (dup) return dup;
    const a: Approval = { id: randomUUID(), ...p, signatures: [], status: 'pending', createdAt: new Date().toISOString() };
    this.items.push(a);
    this.audit.append('system', 'approval.proposed', { id: a.id, action: a.action, agentId: a.agentId, requiredRoles: a.requiredRoles });
    this.persistence.touch();
    this.events.emit('approval', { id: a.id, status: a.status }, `Aprobación pendiente: ${a.action} sobre ${a.agentId} (firman ${a.requiredRoles.join('+')})`);
    return a;
  }

  list(status?: string): Approval[] {
    return [...this.items].sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1)).filter((a) => !status || a.status === status);
  }

  /** Firma una aprobación. Con Postgres se serializa entre réplicas (lock + refresco) para no perder firmas. */
  decide(id: string, principal: { role: Role; keyId: string }, decision: 'approve' | 'reject', comment?: string): Promise<Approval> {
    return this.persistence.withLock(`approval:${id}`, () => this.decideLocked(id, principal, decision, comment));
  }

  private decideLocked(id: string, principal: { role: Role; keyId: string }, decision: 'approve' | 'reject', comment?: string): Approval {
    const a = this.items.find((x) => x.id === id);
    if (!a) throw new NotFoundException('approval not found');
    if (a.status !== 'pending') throw new ConflictException(`approval already ${a.status}`);
    if (principal.role === 'VIEWER') throw new BadRequestException('viewers cannot sign');
    if (a.signatures.some((s) => s.keyId === principal.keyId)) throw new ConflictException('this key already signed');

    // Rol que cubre esta firma: el propio rol, o el primer rol pendiente si es ADMIN.
    const signed = new Set(a.signatures.filter((s) => s.decision === 'approve').map((s) => s.signedAs));
    const pending = a.requiredRoles.filter((r) => !signed.has(r));
    const signedAs: Role | undefined = principal.role === 'ADMIN' ? pending[0] : pending.find((r) => r === principal.role);
    if (!signedAs) throw new BadRequestException(`role ${principal.role} is not required (or already satisfied) for this approval`);

    a.signatures.push({ keyId: principal.keyId, role: principal.role, signedAs, decision, at: new Date().toISOString(), comment });
    this.audit.append(`${principal.role}:${principal.keyId}`, `approval.${decision}`, { id, signedAs, comment });

    if (decision === 'reject') {
      a.status = 'rejected';
      this.persistence.touch();
      this.events.emit('approval', { id: a.id, status: a.status });
      return a;
    }
    const nowSigned = new Set(a.signatures.filter((s) => s.decision === 'approve').map((s) => s.signedAs));
    if (a.requiredRoles.every((r) => nowSigned.has(r))) {
      a.status = 'approved';
      this.apply(a);
    }
    this.persistence.touch();
    this.events.emit('approval', { id: a.id, status: a.status });
    return a;
  }

  /** Aplica la mitigación permanente únicamente tras reunir todas las firmas requeridas. */
  private apply(a: Approval): void {
    switch (a.action) {
      case 'PAUSE_AGENT':
        this.agents.pause(a.agentId);
        break;
      case 'BLOCK_IP':
        this.agents.blockIp(String(a.params.ip));
        break;
      case 'ROTATE_KEYS':
        a.params.newKeyVersion = this.agents.rotateKeys(a.agentId);
        break;
      case 'PATCH_GATEWAY_RULE':
        this.agents.addRule(a.agentId, String(a.params.pattern), String(a.params.reason ?? ''));
        break;
    }
    a.appliedAt = new Date().toISOString();
    this.audit.append('system', 'mitigation.applied', { id: a.id, action: a.action, agentId: a.agentId, params: a.params });
    this.metrics.inc('specterflow_mitigations_applied_total', { action: a.action });
    this.events.emit('mitigation', { id: a.id, action: a.action, agentId: a.agentId }, `Mitigación aplicada: ${a.action} sobre ${a.agentId}`);
    void this.notifyExecutor(a);
  }

  /** Conector hacia sistemas reales (API Gateway, firewall, gestor de secretos) mediante webhook firmado por el control plane. */
  async notifyExecutor(a: Approval, retryDelayMs = 1000): Promise<void> {
    const url = cfg().mitigationWebhookUrl;
    if (!url || a.status !== 'approved') return;
    let detail = '';
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-internal-token': cfg().internalToken },
          body: JSON.stringify({ approvalId: a.id, action: a.action, agentId: a.agentId, params: a.params, signatures: a.signatures }),
          signal: AbortSignal.timeout(15_000),
        });
        detail = `HTTP ${r.status}: ${(await r.text()).slice(0, 300)}`;
        if (r.ok) {
          a.execution = { status: 'ok', attempts: attempt, detail, at: new Date().toISOString() };
          this.audit.append('system', 'mitigation.executor_ok', { id: a.id, attempts: attempt });
          this.persistence.touch();
          return;
        }
        if (r.status >= 400 && r.status < 500 && r.status !== 429) break; // petición rechazada: reintentar no ayuda
      } catch (e) {
        detail = String(e);
      }
      if (attempt < 3) await new Promise((res) => setTimeout(res, retryDelayMs * 2 ** (attempt - 1)));
    }
    a.execution = { status: 'failed', attempts: 3, detail, at: new Date().toISOString() };
    this.audit.append('system', 'mitigation.executor_failed', { id: a.id, detail });
    this.persistence.touch();
    this.events.emit('mitigation', { id: a.id, executor: 'failed' }, `FALLÓ la ejecución real de ${a.action} sobre ${a.agentId}: ${detail.slice(0, 150)}`);
  }

  /** Reintento manual de la ejecución real (p. ej. tras arreglar el executor). */
  async retryExecution(id: string): Promise<Approval> {
    const a = this.items.find((x) => x.id === id);
    if (!a) throw new NotFoundException('approval not found');
    if (a.status !== 'approved') throw new BadRequestException('only approved mitigations can be executed');
    await this.notifyExecutor(a);
    return a;
  }
}
