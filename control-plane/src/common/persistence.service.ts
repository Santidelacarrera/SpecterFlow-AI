import { Injectable, OnApplicationShutdown } from '@nestjs/common';
import { existsSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { cfg } from '../common/config';

export interface Persistable {
  exportState(): unknown;
  importState(data: any): void;
}

/** Persistencia del estado en un fichero JSON (STATE_FILE) con escritura atómica y debounce. */
@Injectable()
export class PersistenceService implements OnApplicationShutdown {
  private parts = new Map<string, Persistable>();
  private timer?: NodeJS.Timeout;
  private readonly file = cfg().stateFile;
  private loaded: Record<string, unknown> = {};

  constructor() {
    if (this.file && existsSync(this.file)) {
      try {
        this.loaded = JSON.parse(readFileSync(this.file, 'utf8'));
      } catch {
        this.loaded = {};
      }
    }
  }

  register(key: string, part: Persistable): void {
    this.parts.set(key, part);
    if (this.loaded[key] !== undefined) part.importState(this.loaded[key]);
  }

  touch(): void {
    if (!this.file || this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      this.flush();
    }, 200);
    this.timer.unref();
  }

  flush(): void {
    if (!this.file) return;
    const out: Record<string, unknown> = {};
    for (const [k, p] of this.parts) out[k] = p.exportState();
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, JSON.stringify(out), { mode: 0o600 });
    renameSync(tmp, this.file);
  }

  onApplicationShutdown(): void {
    if (this.timer) clearTimeout(this.timer);
    this.flush();
  }
}
