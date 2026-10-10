import { Injectable, OnApplicationShutdown, OnModuleInit, Optional } from '@nestjs/common';
import { createHash } from 'crypto';
import { appendFileSync, existsSync, readFileSync } from 'fs';
import { cfg } from '../common/config';
import { PgService } from '../common/pg.service';

export interface AuditEntry {
  seq: number;
  ts: string;
  actor: string;
  action: string;
  detail: Record<string, unknown>;
  prevHash: string;
  hash: string;
}

const GENESIS = '0'.repeat(64);

export const hashEntry = (e: Omit<AuditEntry, 'hash'>): string =>
  createHash('sha256')
    .update(JSON.stringify([e.seq, e.ts, e.actor, e.action, e.detail, e.prevHash]))
    .digest('hex');

/**
 * Registro de auditoría append-only encadenado por hash (cualquier alteración rompe la cadena).
 *  - Fichero (AUDIT_FILE) o memoria: una sola instancia.
 *  - Postgres: la cadena es única y compartida. `append` es síncrono (entrada provisional) y un escritor
 *    en segundo plano, bajo advisory lock, re-encadena las pendientes sobre el último hash almacenado.
 */
@Injectable()
export class AuditService implements OnModuleInit, OnApplicationShutdown {
  private entries: AuditEntry[] = [];
  private pending: AuditEntry[] = [];
  private readonly file = cfg().auditFile;
  private writing: Promise<void> = Promise.resolve();
  private poller?: NodeJS.Timeout;

  constructor(@Optional() private readonly pg?: PgService) {
    if (!this.pg?.pool && this.file && existsSync(this.file)) {
      this.entries = readFileSync(this.file, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as AuditEntry);
    }
  }

  async onModuleInit() {
    if (!this.pg?.pool) return;
    await this.pg.ready();
    await this.sync();
    this.poller = setInterval(() => void this.sync().catch(() => undefined), Number(process.env.SYNC_INTERVAL_MS ?? 1500));
    this.poller.unref();
  }

  async onApplicationShutdown() {
    if (this.poller) clearInterval(this.poller);
    await this.drain();
  }

  private last(): AuditEntry | undefined {
    return this.pending[this.pending.length - 1] ?? this.entries[this.entries.length - 1];
  }

  append(actor: string, action: string, detail: Record<string, unknown> = {}): AuditEntry {
    const prev = this.last();
    const base = {
      seq: this.entries.length + this.pending.length,
      ts: new Date().toISOString(),
      actor,
      action,
      detail,
      prevHash: prev?.hash ?? GENESIS,
    };
    const entry: AuditEntry = { ...base, hash: hashEntry(base) };
    if (this.pg?.pool) {
      this.pending.push(entry);
      setImmediate(() => void this.drain().catch((e) => console.error('[audit] write failed', e)));
    } else {
      this.entries.push(entry);
      if (this.file) appendFileSync(this.file, JSON.stringify(entry) + '\n', { mode: 0o600 });
    }
    return entry;
  }

  /** Persiste las entradas pendientes encadenándolas tras el último hash almacenado (Postgres). */
  drain(): Promise<void> {
    this.writing = this.writing.catch(() => undefined).then(() => this.doDrain());
    return this.writing;
  }

  private async doDrain(): Promise<void> {
    if (!this.pg?.pool || !this.pending.length) return;
    const c = await this.pg.pool.connect();
    try {
      await c.query('SELECT pg_advisory_lock(7001)');
      try {
        await this.pull(c);
        const batch = this.pending.splice(0);
        await c.query('BEGIN');
        for (const p of batch) {
          const base = { seq: this.entries.length, ts: p.ts, actor: p.actor, action: p.action, detail: p.detail, prevHash: this.entries[this.entries.length - 1]?.hash ?? GENESIS };
          const e: AuditEntry = { ...base, hash: hashEntry(base) };
          await c.query('INSERT INTO sf_audit (seq, ts, actor, action, detail, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7)', [
            e.seq, e.ts, e.actor, e.action, JSON.stringify(e.detail), e.prevHash, e.hash,
          ]);
          this.entries.push(e);
        }
        await c.query('COMMIT');
      } catch (err) {
        await c.query('ROLLBACK').catch(() => undefined);
        throw err;
      } finally {
        await c.query('SELECT pg_advisory_unlock(7001)');
      }
    } finally {
      c.release();
    }
  }

  private async pull(c: { query: (q: string, v?: unknown[]) => Promise<{ rows: any[] }> }): Promise<void> {
    const { rows } = await c.query('SELECT seq, ts, actor, action, detail, prev_hash, hash FROM sf_audit WHERE seq >= $1 ORDER BY seq', [this.entries.length]);
    for (const r of rows) {
      if (Number(r.seq) !== this.entries.length) continue; // ya incorporada (carrera sync/drain) o hueco
      this.entries.push({ seq: Number(r.seq), ts: r.ts, actor: r.actor, action: r.action, detail: r.detail, prevHash: r.prev_hash, hash: r.hash });
    }
  }

  /** Incorpora las entradas escritas por otras réplicas. */
  sync(): Promise<void> {
    if (!this.pg?.pool) return Promise.resolve();
    // Se encadena con drain() para que nunca haya dos lecturas/escrituras mutando `entries` a la vez.
    this.writing = this.writing.catch(() => undefined).then(() => this.pull(this.pg!.pool as any));
    return this.writing;
  }

  list(limit = 200): AuditEntry[] {
    return [...this.entries, ...this.pending].slice(-limit);
  }

  verify(): { valid: boolean; length: number; brokenAt?: number } {
    let prev = GENESIS;
    for (const e of this.entries) {
      const { hash, ...rest } = e;
      if (e.prevHash !== prev || hashEntry(rest) !== hash) return { valid: false, length: this.entries.length, brokenAt: e.seq };
      prev = hash;
    }
    return { valid: true, length: this.entries.length };
  }
}
