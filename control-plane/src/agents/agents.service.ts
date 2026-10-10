import { BadRequestException, Injectable } from '@nestjs/common';

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
export class AgentsService {
  private agents = new Map<string, Agent>();
  private blockedIps = new Set<string>();
  private rules: GatewayRule[] = [];

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
  }
  resume(id: string): void {
    const a = this.agents.get(id);
    if (a) a.paused = false;
  }
  rotateKeys(id: string): number {
    const a = this.agents.get(id);
    if (!a) return 0;
    return ++a.keyVersion;
  }

  blockIp(ip: string): void {
    this.blockedIps.add(ip);
  }
  isBlocked(ip: string): boolean {
    return this.blockedIps.has(ip);
  }
  blocked(): string[] {
    return [...this.blockedIps];
  }

  addRule(agentId: string, pattern: string, reason: string): GatewayRule {
    new RegExp(pattern); // valida
    const rule = { id: `rule-${this.rules.length + 1}`, agentId, pattern, reason, createdAt: new Date().toISOString() };
    this.rules.push(rule);
    return rule;
  }
  matchRule(agentId: string, prompt: string): GatewayRule | undefined {
    return this.rules.find((r) => r.agentId === agentId && new RegExp(r.pattern, 'i').test(prompt));
  }
  listRules(): GatewayRule[] {
    return this.rules;
  }
}
