import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { AgentsService } from '../agents/agents.service';
import { AuditService } from '../audit/audit.service';
import { Role } from '../common/config';

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
}

type Proposal = Pick<Approval, 'incidentId' | 'action' | 'agentId' | 'params' | 'summary' | 'requiredRoles'>;

@Injectable()
export class ApprovalsService {
  private items: Approval[] = [];

  constructor(
    private readonly audit: AuditService,
    private readonly agents: AgentsService,
  ) {}

  propose(p: Proposal): Approval {
    // Evita saturar la bandeja: una misma acción pendiente sobre el mismo agente/parámetros se reutiliza.
    const dup = this.items.find(
      (x) => x.status === 'pending' && x.action === p.action && x.agentId === p.agentId && JSON.stringify(x.params) === JSON.stringify(p.params),
    );
    if (dup) return dup;
    const a: Approval = { id: randomUUID(), ...p, signatures: [], status: 'pending', createdAt: new Date().toISOString() };
    this.items.push(a);
    this.audit.append('system', 'approval.proposed', { id: a.id, action: a.action, agentId: a.agentId, requiredRoles: a.requiredRoles });
    return a;
  }

  list(status?: string): Approval[] {
    return [...this.items].reverse().filter((a) => !status || a.status === status);
  }

  decide(id: string, principal: { role: Role; keyId: string }, decision: 'approve' | 'reject', comment?: string): Approval {
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
      return a;
    }
    const nowSigned = new Set(a.signatures.filter((s) => s.decision === 'approve').map((s) => s.signedAs));
    if (a.requiredRoles.every((r) => nowSigned.has(r))) {
      a.status = 'approved';
      this.apply(a);
    }
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
  }
}
