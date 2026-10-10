import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { Pool } from 'pg';
import { cfg } from './config';

const SCHEMA = `
CREATE SEQUENCE IF NOT EXISTS sf_entity_seq;
CREATE TABLE IF NOT EXISTS sf_entities (
  kind text NOT NULL,
  id text NOT NULL,
  data jsonb NOT NULL,
  seq bigint NOT NULL DEFAULT nextval('sf_entity_seq'),
  PRIMARY KEY (kind, id)
);
CREATE INDEX IF NOT EXISTS sf_entities_seq_idx ON sf_entities (seq);
CREATE TABLE IF NOT EXISTS sf_audit (
  seq bigint PRIMARY KEY,
  ts text NOT NULL,
  actor text NOT NULL,
  action text NOT NULL,
  detail json NOT NULL, -- json (no jsonb): conserva el orden de claves del que depende el hash
  prev_hash text NOT NULL,
  hash text NOT NULL
);
`;

/** Pool de Postgres compartido (null si no hay DATABASE_URL → modo fichero/memoria). */
@Injectable()
export class PgService implements OnModuleDestroy {
  readonly pool: Pool | null = cfg().databaseUrl ? new Pool({ connectionString: cfg().databaseUrl, max: Number(process.env.PG_POOL_MAX ?? 8) }) : null;
  private schema?: Promise<void>;

  /** Crea el esquema (idempotente, protegido con lock para arranques concurrentes de réplicas). */
  ready(): Promise<void> {
    if (!this.pool) return Promise.resolve();
    this.schema ??= (async () => {
      const c = await this.pool!.connect();
      try {
        await c.query('SELECT pg_advisory_lock(7000)');
        await c.query(SCHEMA);
        await c.query('SELECT pg_advisory_unlock(7000)');
      } finally {
        c.release();
      }
    })();
    return this.schema;
  }

  async onModuleDestroy() {
    await this.pool?.end();
  }
}
