import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { cfg } from '../common/config';

export type BreakerState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';
export type TripReason = 'budget_exceeded' | 'infinite_loop' | 'failure_rate';

export interface RequestRecord {
  ts: number;
  promptHash: string;
  promptPreview: string;
  costUsd: number;
  ok: boolean;
  sourceIp: string;
  status: number;
  words?: string[];
}

export interface Trip {
  agentId: string;
  reason: TripReason;
  detail: string;
  windowCostUsd: number;
  evidence: RequestRecord[];
  topSourceIp?: string;
}

interface AgentBreaker {
  state: BreakerState;
  openedAt?: number;
  records: RequestRecord[];
  lastTrip?: Trip;
}

export const promptWords = (p: string): string[] => [...new Set(p.toLowerCase().match(/[\p{L}\p{N}_]+/gu) ?? [])].slice(0, 64);

export const jaccard = (a: string[], b: string[]): number => {
  if (!a.length && !b.length) return 1;
  const B = new Set(b);
  let inter = 0;
  for (const w of a) if (B.has(w)) inter++;
  return inter / (a.length + b.length - inter);
};

export const hashPrompt = (p: string) => createHash('sha1').update(p.trim().toLowerCase()).digest('hex').slice(0, 12);

/** Circuit breaker financiero y de IA, por agente. Lógica pura y determinista (reloj inyectable). */
@Injectable()
export class BreakerService {
  private agents = new Map<string, AgentBreaker>();
  now: () => number = () => Date.now();

  private get(agentId: string): AgentBreaker {
    let a = this.agents.get(agentId);
    if (!a) this.agents.set(agentId, (a = { state: 'CLOSED', records: [] }));
    return a;
  }

  /** ¿Puede pasar la petición? Gestiona OPEN → HALF_OPEN tras el cooldown. */
  allow(agentId: string): { allowed: boolean; retryAfterSec?: number; state: BreakerState } {
    const a = this.get(agentId);
    if (a.state === 'OPEN') {
      const waited = (this.now() - (a.openedAt ?? 0)) / 1000;
      const cool = cfg().breaker.cooldownSec;
      if (waited >= cool) {
        a.state = 'HALF_OPEN';
        return { allowed: true, state: 'HALF_OPEN' };
      }
      return { allowed: false, retryAfterSec: Math.ceil(cool - waited), state: 'OPEN' };
    }
    return { allowed: true, state: a.state };
  }

  /** Registra una petición completada y devuelve un Trip si el breaker se dispara. */
  record(agentId: string, rec: Omit<RequestRecord, 'ts'>): Trip | null {
    const a = this.get(agentId);
    const ts = this.now();
    a.records.push({ ...rec, ts });
    const horizon = ts - cfg().breaker.windowSec * 1000;
    a.records = a.records.filter((r) => r.ts >= horizon).slice(-500);

    if (a.state === 'HALF_OPEN') {
      if (rec.ok) {
        a.state = 'CLOSED';
        a.records = [];
        return null;
      }
      return this.trip(agentId, a, 'failure_rate', 'La petición de prueba (half-open) falló');
    }
    if (a.state === 'OPEN') return null;

    const c = cfg().breaker;
    const windowCost = a.records.reduce((s, r) => s + r.costUsd, 0);
    if (windowCost > c.budgetUsd) {
      return this.trip(agentId, a, 'budget_exceeded', `Gasto $${windowCost.toFixed(4)} > presupuesto $${c.budgetUsd} en ${c.windowSec}s`);
    }
    const counts = new Map<string, number>();
    for (const r of a.records) counts.set(r.promptHash, (counts.get(r.promptHash) ?? 0) + 1);
    const [loopHash, loopN] = [...counts.entries()].sort((x, y) => y[1] - x[1])[0] ?? ['', 0];
    if (loopN >= c.loopRepeat) {
      return this.trip(agentId, a, 'infinite_loop', `Prompt idéntico (${loopHash}) repetido ${loopN} veces en ${c.windowSec}s`);
    }
    // Bucle "semántico": prompts casi idénticos (variaciones mínimas) que un agente reenvía una y otra vez.
    const last = a.records.slice(-100).filter((r) => r.words?.length);
    const cur = last[last.length - 1];
    if (cur?.words) {
      const similar = last.filter((r) => jaccard(cur.words!, r.words!) >= cfg().loopSimilarity).length;
      if (similar >= c.loopRepeat) {
        return this.trip(agentId, a, 'infinite_loop', `${similar} prompts casi idénticos (similitud ≥ ${cfg().loopSimilarity}) en ${c.windowSec}s`);
      }
    }
    if (a.records.length >= c.minRequests) {
      const fails = a.records.filter((r) => !r.ok).length / a.records.length;
      if (fails >= c.failureRate) {
        return this.trip(agentId, a, 'failure_rate', `Tasa de fallos ${(fails * 100).toFixed(0)}% ≥ ${(c.failureRate * 100).toFixed(0)}%`);
      }
    }
    return null;
  }

  private trip(agentId: string, a: AgentBreaker, reason: TripReason, detail: string): Trip {
    a.state = 'OPEN';
    a.openedAt = this.now();
    const ips = new Map<string, number>();
    for (const r of a.records) ips.set(r.sourceIp, (ips.get(r.sourceIp) ?? 0) + 1);
    const top = [...ips.entries()].sort((x, y) => y[1] - x[1])[0]?.[0];
    const trip: Trip = {
      agentId,
      reason,
      detail,
      windowCostUsd: a.records.reduce((s, r) => s + r.costUsd, 0),
      evidence: a.records.slice(-50),
      topSourceIp: top,
    };
    a.lastTrip = trip;
    return trip;
  }

  reset(agentId: string): void {
    this.agents.delete(agentId);
  }

  status(agentId: string) {
    const a = this.get(agentId);
    const c = cfg().breaker;
    const horizon = this.now() - c.windowSec * 1000;
    const recent = a.records.filter((r) => r.ts >= horizon);
    return {
      agentId,
      state: a.state,
      windowCostUsd: recent.reduce((s, r) => s + r.costUsd, 0),
      budgetUsd: c.budgetUsd,
      requestsInWindow: recent.length,
      lastTrip: a.lastTrip ? { reason: a.lastTrip.reason, detail: a.lastTrip.detail } : null,
    };
  }
}
