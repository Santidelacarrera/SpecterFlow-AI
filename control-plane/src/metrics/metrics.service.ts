import { Injectable } from '@nestjs/common';

type Labels = Record<string, string>;
const key = (name: string, l: Labels) => `${name}{${Object.entries(l).map(([k, v]) => `${k}="${String(v).replace(/"/g, '')}"`).join(',')}}`;

/** Métricas en formato Prometheus (sin dependencias). */
@Injectable()
export class MetricsService {
  private counters = new Map<string, number>();
  private gauges = new Map<string, () => number>();

  inc(name: string, labels: Labels = {}, by = 1): void {
    const k = key(name, labels);
    this.counters.set(k, (this.counters.get(k) ?? 0) + by);
  }

  gauge(name: string, labels: Labels, fn: () => number): void {
    this.gauges.set(key(name, labels), fn);
  }

  render(): string {
    const lines: string[] = [];
    for (const [k, v] of [...this.counters].sort()) lines.push(`${k} ${v}`);
    for (const [k, fn] of [...this.gauges].sort()) lines.push(`${k} ${fn()}`);
    return lines.join('\n') + '\n';
  }
}
