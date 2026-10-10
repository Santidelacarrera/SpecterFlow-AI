import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { appendFileSync, existsSync, readFileSync } from 'fs';
import { cfg } from '../common/config';

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

/** Registro de auditoría append-only encadenado por hash (cualquier alteración rompe la cadena). */
@Injectable()
export class AuditService {
  private entries: AuditEntry[] = [];
  private readonly file = cfg().auditFile;

  constructor() {
    if (this.file && existsSync(this.file)) {
      this.entries = readFileSync(this.file, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as AuditEntry);
    }
  }

  append(actor: string, action: string, detail: Record<string, unknown> = {}): AuditEntry {
    const prev = this.entries[this.entries.length - 1];
    const base = {
      seq: this.entries.length,
      ts: new Date().toISOString(),
      actor,
      action,
      detail,
      prevHash: prev?.hash ?? GENESIS,
    };
    const entry: AuditEntry = { ...base, hash: hashEntry(base) };
    this.entries.push(entry);
    if (this.file) appendFileSync(this.file, JSON.stringify(entry) + '\n');
    return entry;
  }

  list(limit = 200): AuditEntry[] {
    return this.entries.slice(-limit);
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
