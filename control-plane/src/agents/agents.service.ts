import { BadRequestException, Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { Entity, Persistable, PersistenceService } from '../common/persistence.service';

export interface Agent {
  id: string;
  url: string;
  paused: boolean; // pausa permanente tras aprobación humana
  keyVersion: number;
  registeredAt: string;
}

export interface GatewayRule {
  id: string;
  agentId: string;
  pattern: string; // regex aplicada al prompt entrante
  reason: string;
  createdAt: string;
}

@Injectable()
export class AgentsService implements Persistable {
  private agents = new Map<string, Agent>();
  private blockedIps = new Set<string>();
  private rules: GatewayRule[] = [];

  readonly kinds = ['agent', 'rule', 'blocked_ip'];

  constructor(private readonly persistence: PersistenceService) {
    persistence.register(this);
  }

  exportEntities(): Entity[] {
    return [
      ...[...this.agents.values()].map((a) => ({ kind: 'agent', id: a.id, data: a })),
      ...this.rules.map((r) => ({ kind: 'rule', id: r.id, data: r })),
      ...[...this.blockedIps].map((ip) => ({ kind: 'blocked_ip', id: ip, data: { ip } })),
    ];
  }
  importEntity(kind: string, id: string, data: any) {
    if (kind === 'agent') this.agents.set(id, data);
    else if (kind === 'blocked_ip') this.blockedIps.add(data.ip);
    else if (kind === 'rule') {
      const i = this.rules.findIndex((r) => r.id === id);
      if (i >= 0) this.rules[i] = data;
      else this.rules.push(data);
    }
  }

  register(id: string, url: string): Agent {
    if (!/^[a-z0-9][a-z0-9-_]{1,40}$/i.test(id)) throw new BadRequestException('invalid agent id');
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      throw new BadRequestException('invalid url');
    }
    if (!['http:', 'https:'].includes(u.protocol)) throw new BadRequestException('invalid url protocol');
    const agent: Agent = { id, url: u.origin + u.pathname.replace(/\/$/, ''), paused: false, keyVersion: 1, registeredAt: new Date().toISOString() };
    this.agents.set(id, agent);
    this.persistence.touch();
    return agent;
  }

  get(id: string): Agent | undefined {
    return this.agents.get(id);
  }
  list(): Agent[] {
    return [...this.agents.values()];
  }
  findByUrl(url: string): Agent | undefined {
    const u = new URL(url);
    const norm = u.origin + u.pathname.replace(/\/$/, '');
    return this.list().find((a) => a.url === norm);
  }

  pause(id: string): void {
    const a = this.agents.get(id);
    if (a) a.paused = true;
    this.persistence.touch();
  }
  resume(id: string): void {
    const a = this.agents.get(id);
    if (a) a.paused = false;
    this.persistence.touch();
  }
  rotateKeys(id: string): number {
    const a = this.agents.get(id);
    if (!a) return 0;
    this.persistence.touch();
    return ++a.keyVersion;
  }

  blockIp(ip: string): void {
    this.blockedIps.add(ip);
    this.persistence.touch();
  }
  isBlocked(ip: string): boolean {
    return this.blockedIps.has(ip);
  }
  blocked(): string[] {
    return [...this.blockedIps];
  }

  addRule(agentId: string, pattern: string, reason: string): GatewayRule {
    new RegExp(pattern); // valida
    const rule = { id: `rule-${randomUUID().slice(0, 8)}`, agentId, pattern, reason, createdAt: new Date().toISOString() };
    this.rules.push(rule);
    this.persistence.touch();
    return rule;
  }
  matchRule(agentId: string, prompt: string): GatewayRule | undefined {
    return this.rules.find((r) => r.agentId === agentId && new RegExp(r.pattern, 'i').test(prompt));
  }
  listRules(): GatewayRule[] {
    return this.rules;
  }
}
