export type Severity = 'none' | 'low' | 'medium' | 'high' | 'critical';

export interface Breaker {
  agentId: string;
  state: 'CLOSED' | 'OPEN' | 'HALF_OPEN';
  windowCostUsd: number;
  budgetUsd: number;
  requestsInWindow: number;
  lastTrip: { reason: string; detail: string } | null;
}
export interface Agent {
  id: string;
  url: string;
  paused: boolean;
  keyVersion: number;
  breaker: Breaker;
}
export interface Campaign {
  id: string;
  targetUrl: string;
  agentId?: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  exploited?: number;
  maxSeverity?: string;
  costUsd?: number;
  error?: string;
  createdAt: string;
}
export interface Incident {
  id: string;
  kind: 'redteam_finding' | 'breaker_trip';
  agentId?: string;
  target: string;
  severity: Severity;
  title: string;
  createdAt: string;
  costUsd: number;
  status: string;
  evidence: Record<string, any>;
  postmortem?: string;
}
export interface Signature {
  role: string;
  signedAs: string;
  decision: 'approve' | 'reject';
  at: string;
  comment?: string;
}
export interface Approval {
  id: string;
  incidentId: string;
  action: string;
  agentId: string;
  params: Record<string, unknown>;
  summary: string;
  requiredRoles: string[];
  signatures: Signature[];
  status: 'pending' | 'approved' | 'rejected';
  createdAt: string;
  appliedAt?: string;
}
export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  hash: string;
}

export class Api {
  constructor(private key: string) {}

  private async req<T>(path: string, init?: RequestInit): Promise<T> {
    const r = await fetch(path, {
      ...init,
      headers: { 'content-type': 'application/json', 'x-api-key': this.key, ...(init?.headers ?? {}) },
    });
    if (!r.ok) {
      const body = await r.json().catch(() => ({}));
      throw new Error(body.message ?? `HTTP ${r.status}`);
    }
    return r.json();
  }

  me = () => this.req<{ role: string; keyId: string }>('/api/me');
  agents = () => this.req<Agent[]>('/api/agents');
  registerAgent = (id: string, url: string) => this.req<Agent>('/api/agents', { method: 'POST', body: JSON.stringify({ id, url }) });
  resetBreaker = (id: string) => this.req(`/api/agents/${id}/breaker/reset`, { method: 'POST' });
  campaigns = () => this.req<Campaign[]>('/api/campaigns');
  startCampaign = (targetUrl: string, budgetUsd: number) =>
    this.req<Campaign>('/api/campaigns', { method: 'POST', body: JSON.stringify({ targetUrl, budgetUsd }) });
  incidents = () => this.req<Incident[]>('/api/incidents');
  approvals = () => this.req<Approval[]>('/api/approvals');
  decide = (id: string, decision: 'approve' | 'reject', comment?: string) =>
    this.req<Approval>(`/api/approvals/${id}/${decision}`, { method: 'POST', body: JSON.stringify({ comment }) });
  audit = () => this.req<AuditEntry[]>('/api/audit?limit=100');
  verifyAudit = () => this.req<{ valid: boolean; length: number; brokenAt?: number }>('/api/audit/verify');
}
