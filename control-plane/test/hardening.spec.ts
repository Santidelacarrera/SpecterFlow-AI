import { mkdtempSync, readFileSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import express from 'express';
import request from 'supertest';
import { AgentsService } from '../src/agents/agents.service';
import { ApprovalsService } from '../src/approvals/approvals.service';
import { AuditService } from '../src/audit/audit.service';
import { BreakerService, jaccard, promptWords } from '../src/breaker/breaker.service';
import { assertProductionConfig } from '../src/common/config';
import { PersistenceService } from '../src/common/persistence.service';
import { rateLimiter, securityHeaders } from '../src/common/security';
import { EventsService } from '../src/events/events.service';
import { MetricsService } from '../src/metrics/metrics.service';

describe('semantic loop detection', () => {
  it('jaccard / words', () => {
    expect(jaccard(promptWords('a b c'), promptWords('a b c'))).toBe(1);
    expect(jaccard(promptWords('a b c d'), promptWords('a b'))).toBeCloseTo(0.5);
  });

  it('trips on near-identical prompts with tiny variations', () => {
    process.env.LOOP_REPEAT_THRESHOLD = '4';
    process.env.BUDGET_USD = '100';
    const b = new BreakerService();
    let trip = null;
    for (let i = 0; i < 4; i++) {
      const p = `please retry the failed deployment of service alpha now attempt ${i} with the same parameters as before`;
      trip = b.record('a', { promptHash: 'h' + i, promptPreview: p, words: promptWords(p), costUsd: 0.001, ok: true, sourceIp: '1.1.1.1', status: 200 });
    }
    expect(trip?.reason).toBe('infinite_loop');
  });
});

describe('persistence', () => {
  it('survives a restart: agents, mitigations and approvals', () => {
    const file = join(mkdtempSync(join(tmpdir(), 'sf-')), 'state.json');
    process.env.STATE_FILE = file;
    const build = () => {
      const p = new PersistenceService();
      const audit = new AuditService();
      const agents = new AgentsService(p);
      const ap = new ApprovalsService(audit, agents, p, new EventsService(), new MetricsService());
      return { p, agents, ap };
    };
    const a = build();
    a.agents.register('x1', 'http://localhost:9');
    const prop = a.ap.propose({ incidentId: 'i', action: 'BLOCK_IP', agentId: 'x1', params: { ip: '6.6.6.6' }, summary: 's', requiredRoles: ['SECOPS'] });
    a.ap.decide(prop.id, { role: 'SECOPS', keyId: 'k1' }, 'approve');
    a.p.flush();
    expect(JSON.parse(readFileSync(file, 'utf8')).agents.blockedIps).toContain('6.6.6.6');

    const b = build();
    expect(b.agents.get('x1')).toBeDefined();
    expect(b.agents.isBlocked('6.6.6.6')).toBe(true);
    expect(b.ap.list()[0]).toMatchObject({ status: 'approved' });
    delete process.env.STATE_FILE;
  });
});

describe('http hardening', () => {
  it('rate limits and sets security headers', async () => {
    const app = express();
    app.use(securityHeaders);
    app.use(rateLimiter(3));
    app.get('/x', (_q, r) => r.send('ok'));
    const h = request(app);
    for (let i = 0; i < 3; i++) await h.get('/x').set('x-api-key', 'k').expect(200);
    const r = await h.get('/x').set('x-api-key', 'k').expect(429);
    expect(r.headers['retry-after']).toBeDefined();
    expect(r.headers['x-content-type-options']).toBe('nosniff');
    await h.get('/x').set('x-api-key', 'other').expect(200);
  });
});

describe('production config guard', () => {
  const env = { ...process.env };
  afterEach(() => (process.env = { ...env }));
  it('rejects default keys in production', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.API_KEYS;
    expect(() => assertProductionConfig()).toThrow(/insegura/);
  });
  it('accepts strong config', () => {
    process.env.NODE_ENV = 'production';
    process.env.API_KEYS = 'a'.repeat(32) + ':SECOPS';
    process.env.INTERNAL_TOKEN = 'b'.repeat(32);
    expect(() => assertProductionConfig()).not.toThrow();
  });
});

describe('metrics', () => {
  it('renders prometheus text', () => {
    const m = new MetricsService();
    m.inc('c_total', { a: 'x' }, 2);
    m.gauge('g', {}, () => 7);
    expect(m.render()).toContain('c_total{a="x"} 2');
    expect(m.render()).toContain('g{} 7');
  });
});
