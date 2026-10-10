import { AuditService, hashEntry } from '../src/audit/audit.service';
import { BreakerService } from '../src/breaker/breaker.service';

const rec = (over: Partial<Parameters<BreakerService['record']>[1]> = {}) => ({
  promptHash: 'h' + Math.random(),
  promptPreview: 'p',
  costUsd: 0.01,
  ok: true,
  sourceIp: '1.1.1.1',
  status: 200,
  ...over,
});

describe('BreakerService', () => {
  let b: BreakerService;
  let t: number;
  beforeEach(() => {
    process.env.BUDGET_USD = '1';
    process.env.LOOP_REPEAT_THRESHOLD = '3';
    process.env.BREAKER_COOLDOWN_SEC = '30';
    b = new BreakerService();
    t = 1_000_000;
    b.now = () => t;
  });

  it('trips on budget and blocks traffic', () => {
    expect(b.record('a', rec({ costUsd: 0.6 }))).toBeNull();
    const trip = b.record('a', rec({ costUsd: 0.6 }));
    expect(trip?.reason).toBe('budget_exceeded');
    expect(b.allow('a')).toMatchObject({ allowed: false, state: 'OPEN' });
  });

  it('trips on identical-prompt loop', () => {
    b.record('a', rec({ promptHash: 'same' }));
    b.record('a', rec({ promptHash: 'same' }));
    expect(b.record('a', rec({ promptHash: 'same' }))?.reason).toBe('infinite_loop');
  });

  it('trips on failure rate and reports top source ip', () => {
    let trip = null;
    for (let i = 0; i < 10; i++) trip = b.record('a', rec({ ok: false, status: 500, sourceIp: '9.9.9.9' }));
    expect(trip?.reason).toBe('failure_rate');
    expect(trip?.topSourceIp).toBe('9.9.9.9');
  });

  it('half-opens after cooldown, closes on success, re-opens on failure', () => {
    b.record('a', rec({ costUsd: 2 }));
    t += 31_000;
    expect(b.allow('a')).toMatchObject({ allowed: true, state: 'HALF_OPEN' });
    expect(b.record('a', rec({ ok: false, status: 500 }))).not.toBeNull();
    t += 31_000;
    b.allow('a');
    expect(b.record('a', rec())).toBeNull();
    expect(b.status('a').state).toBe('CLOSED');
  });

  it('expires old records from the window', () => {
    b.record('a', rec({ costUsd: 0.9 }));
    t += 120_000;
    expect(b.record('a', rec({ costUsd: 0.9 }))).toBeNull();
  });
});

describe('AuditService', () => {
  it('detects tampering', () => {
    const a = new AuditService();
    a.append('x', 'one');
    a.append('x', 'two');
    a.append('x', 'three');
    expect(a.verify().valid).toBe(true);
    (a as any).entries[1].detail = { forged: true };
    expect(a.verify()).toMatchObject({ valid: false, brokenAt: 1 });
  });

  it('hash is deterministic', () => {
    const e = { seq: 0, ts: 't', actor: 'a', action: 'b', detail: {}, prevHash: '0' };
    expect(hashEntry(e)).toBe(hashEntry({ ...e }));
  });
});
