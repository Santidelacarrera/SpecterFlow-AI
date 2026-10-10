import { Injectable, OnApplicationShutdown, OnModuleInit } from '@nestjs/common';
import { createHash } from 'crypto';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { cfg } from './config';
import { PgService } from './pg.service';

export interface Entity {
  kind: string;
  id: string;
  data: unknown;
}

export interface Persistable {
  /** Tipos de entidad que gestiona este servicio. */
  readonly kinds: string[];
  exportEntities(): Entity[];
  importEntity(kind: string, id: string, data: any): void;
}

const stable = (v: unknown): string =>
  JSON.stringify(v, (_k, val) =>
    val && typeof val === 'object' && !Array.isArray(val) ? Object.fromEntries(Object.entries(val).sort(([a], [b]) => (a < b ? -1 : 1))) : val,
  );
const digest = (v: unknown) => createHash('sha1').update(stable(v)).digest('hex');

/**
 * Persistencia del estado por entidades.
 *  - DATABASE_URL: Postgres (multi-réplica). Escribe solo lo que cambió, sincroniza cambios de otras réplicas
 *    por sondeo de una secuencia global y serializa operaciones críticas con advisory locks.
 *  - STATE_FILE: fichero JSON (una sola instancia).
 *  - Ninguno: solo memoria.
 */
@Injectable()
export class PersistenceService implements OnModuleInit, OnApplicationShutdown {
  private parts: Persistable[] = [];
  private byKind = new Map<string, Persistable>();
  private hashes = new Map<string, string>(); // kind/id -> hash de lo ya sincronizado
  private timer?: NodeJS.Timeout;
  private poller?: NodeJS.Timeout;
  private lastSeq = 0;
  private flushing: Promise<void> = Promise.resolve();
  private readonly file = cfg().stateFile;

  constructor(private readonly pg: PgService = new PgService()) {}

  register(part: Persistable): void {
    this.parts.push(part);
    for (const k of part.kinds) this.byKind.set(k, part);
  }

  get mode(): 'postgres' | 'file' | 'memory' {
    return this.pg.pool ? 'postgres' : this.file ? 'file' : 'memory';
  }

  async onModuleInit() {
    await this.init();
  }

  /** Carga el estado persistido y arranca la sincronización entre réplicas. */
  async init(): Promise<void> {
    if (this.pg.pool) {
      await this.pg.ready();
      await this.refresh();
      const ms = Number(process.env.SYNC_INTERVAL_MS ?? 1500);
      this.poller = setInterval(() => void this.refresh().catch(() => undefined), ms);
      this.poller.unref();
    } else if (this.file && existsSync(this.file)) {
      try {
        const rows: Entity[] = JSON.parse(readFileSync(this.file, 'utf8'));
        for (const e of rows) this.apply(e);
      } catch {
        /* fichero corrupto: se ignora y se reescribe en el siguiente flush */
      }
    }
  }

  private apply(e: Entity): void {
    this.byKind.get(e.kind)?.importEntity(e.kind, e.id, e.data);
    this.hashes.set(`${e.kind}/${e.id}`, digest(e.data));
  }

  /** Trae los cambios hechos por otras réplicas desde la última sincronización. */
  async refresh(): Promise<void> {
    if (!this.pg.pool) return;
    const { rows } = await this.pg.pool.query('SELECT kind, id, data, seq FROM sf_entities WHERE seq > $1 ORDER BY seq', [this.lastSeq]);
    for (const r of rows) {
      this.apply({ kind: r.kind, id: r.id, data: r.data });
      this.lastSeq = Math.max(this.lastSeq, Number(r.seq));
    }
  }

  touch(): void {
    if (this.mode === 'memory' || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.flush().catch((e) => console.error('[persistence] flush failed', e));
    }, 100);
    this.timer.unref();
  }

  /** Escribe las entidades cambiadas. Las llamadas se encadenan para no solaparse. */
  flush(): Promise<void> {
    this.flushing = this.flushing.catch(() => undefined).then(() => this.doFlush());
    return this.flushing;
  }

  private async doFlush(): Promise<void> {
    if (this.mode === 'memory') return;
    const all = this.parts.flatMap((p) => p.exportEntities());
    const changed = all.filter((e) => this.hashes.get(`${e.kind}/${e.id}`) !== digest(e.data));
    if (this.pg.pool) {
      if (!changed.length) return;
      const c = await this.pg.pool.connect();
      try {
        await c.query('BEGIN');
        for (const e of changed) {
          const r = await c.query(
            `INSERT INTO sf_entities (kind, id, data) VALUES ($1, $2, $3)
             ON CONFLICT (kind, id) DO UPDATE SET data = EXCLUDED.data, seq = nextval('sf_entity_seq') RETURNING seq`,
            [e.kind, e.id, JSON.stringify(e.data)],
          );
          this.lastSeq = Math.max(this.lastSeq, Number(r.rows[0].seq)); // nuestras propias escrituras no se reimportan
        }
        await c.query('COMMIT');
        for (const e of changed) this.hashes.set(`${e.kind}/${e.id}`, digest(e.data));
      } catch (err) {
        await c.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        c.release();
      }
    } else if (this.file) {
      const tmp = `${this.file}.tmp`;
      writeFileSync(tmp, JSON.stringify(all), { mode: 0o600 });
      renameSync(tmp, this.file);
      for (const e of all) this.hashes.set(`${e.kind}/${e.id}`, digest(e.data));
    }
  }

  /**
   * Sección crítica entre réplicas: toma un advisory lock, refresca el estado, ejecuta `fn` y
   * persiste antes de soltar el lock. Sin Postgres solo ejecuta `fn`.
   */
  async withLock<T>(name: string, fn: () => T | Promise<T>): Promise<T> {
    if (!this.pg.pool) {
      const r = await fn();
      this.touch();
      return r;
    }
    const c = await this.pg.pool.connect();
    try {
      await c.query('SELECT pg_advisory_lock(hashtext($1))', [`sf:${name}`]);
      try {
        await this.refresh();
        const r = await fn();
        await this.flush();
        return r;
      } finally {
        await c.query('SELECT pg_advisory_unlock(hashtext($1))', [`sf:${name}`]);
      }
    } finally {
      c.release();
    }
  }

  async onApplicationShutdown() {
    if (this.timer) clearTimeout(this.timer);
    if (this.poller) clearInterval(this.poller);
    await this.flush().catch(() => undefined);
  }
}
