/**
 * Pruebas de alta disponibilidad con Postgres real: dos "réplicas" (instancias independientes de los servicios)
 * comparten estado, serializan firmas concurrentes y mantienen una única cadena de auditoría.
 * Se omiten si no hay TEST_DATABASE_URL.
 */
import { Pool } from 'pg';
import { AgentsService } from '../src/agents/agents.service';
import { ApprovalsService } from '../src/approvals/approvals.service';
import { AuditService } from '../src/audit/audit.service';
import { BreakerService } from '../src/breaker/breaker.service';
import { PersistenceService } from '../src/common/persistence.service';
import { PgService } from '../src/common/pg.service';
import { EventsService } from '../src/events/events.service';
import { MetricsService } from '../src/metrics/metrics.service';

const url = process.env.TEST_DATABASE_URL;
const d = url ? describe : describe.skip;

async function replica() {
  const pg = new PgService();
  const p = new PersistenceService(pg);
  const audit = new AuditService(pg);
  const agents = new AgentsService(p);
  const breaker = new BreakerService(p);
  const ap = new ApprovalsService(audit, agents, p, new EventsService(), new MetricsService());
  await p.init();
  await audit.onModuleInit();
  return { pg, p, audit, agents, breaker, ap };
}

d('postgres HA', () => {
  beforeAll(async () => {
    process.env.DATABASE_URL = url;
    process.env.SYNC_INTERVAL_MS = '100000'; // la sincronización se fuerza a mano en el test
    const pool = new Pool({ connectionString: url });
    await pool.query('DROP TABLE IF EXISTS sf_entities, sf_audit; DROP SEQUENCE IF EXISTS sf_entity_seq');
    await pool.end();
  });
  afterAll(() => {
    delete process.env.DATABASE_URL;
  });

  it('shares state between replicas and keeps a single valid audit chain', async () => {
    const A = await replica();
    const B = await replica();

    A.agents.register('shared-agent', 'http://localhost:9');
    A.agents.blockIp('7.7.7.7');
    await A.p.flush();
    await B.p.refresh();
    expect(B.agents.get('shared-agent')).toBeDefined();
    expect(B.agents.isBlocked('7.7.7.7')).toBe(true);

    // Auditoría concurrente desde ambas réplicas → una sola cadena válida
    for (let i = 0; i < 10; i++) {
      A.audit.append('A', 'evt', { zeta: i, alpha: 'x', mid: { b: 1, a: 2 } }); // claves desordenadas a propósito (regresión jsonb)
      B.audit.append('B', 'evt', { i });
    }
    await Promise.all([A.audit.drain(), B.audit.drain()]);
    await A.audit.sync();
    await B.audit.sync();
    expect(A.audit.verify()).toMatchObject({ valid: true });
    expect(B.audit.verify()).toMatchObject({ valid: true });
    expect(A.audit.verify().length).toBe(20);
    expect(B.audit.verify().length).toBe(20);

    await A.pg.onModuleDestroy();
    await B.pg.onModuleDestroy();
  });

  it('does not lose signatures when two replicas sign at the same time', async () => {
    const A = await replica();
    const B = await replica();
    const prop = A.ap.propose({ incidentId: 'i', action: 'PAUSE_AGENT', agentId: 'shared-agent', params: {}, summary: 's', requiredRoles: ['SECOPS', 'FINOPS'] });
    await A.p.flush();
    await B.p.refresh();

    const [r1, r2] = await Promise.all([
      A.ap.decide(prop.id, { role: 'SECOPS', keyId: 'sec' }, 'approve'),
      B.ap.decide(prop.id, { role: 'FINOPS', keyId: 'fin' }, 'approve'),
    ]);
    await A.p.refresh();
    await B.p.refresh();
    const finalA = A.ap.list().find((x) => x.id === prop.id)!;
    const finalB = B.ap.list().find((x) => x.id === prop.id)!;
    for (const f of [finalA, finalB]) {
      expect(f.status).toBe('approved');
      expect(f.signatures).toHaveLength(2);
    }
    expect([r1.status, r2.status]).toContain('approved');
    // la mitigación se aplicó en la réplica que completó la firma y se propaga a la otra
    expect(A.agents.get('shared-agent')?.paused || B.agents.get('shared-agent')?.paused).toBe(true);
    await A.p.refresh();
    await B.p.refresh();
    expect(A.agents.get('shared-agent')?.paused).toBe(true);
    expect(B.agents.get('shared-agent')?.paused).toBe(true);

    await A.pg.onModuleDestroy();
    await B.pg.onModuleDestroy();
  });

  it('propagates an open circuit breaker to other replicas', async () => {
    process.env.BUDGET_USD = '1';
    const A = await replica();
    const B = await replica();
    A.breaker.record('hot', { promptHash: 'h', promptPreview: 'p', costUsd: 5, ok: true, sourceIp: '1.1.1.1', status: 200 });
    await A.p.flush();
    await B.p.refresh();
    expect(B.breaker.allow('hot').allowed).toBe(false);
    A.breaker.reset('hot');
    await A.p.flush();
    await B.p.refresh();
    expect(B.breaker.allow('hot').allowed).toBe(true);
    await A.pg.onModuleDestroy();
    await B.pg.onModuleDestroy();
  });
});
