import { Injectable } from '@nestjs/common';
import { EventEmitter } from 'events';
import { cfg } from '../common/config';

export interface SfEvent {
  type: 'incident' | 'approval' | 'campaign' | 'breaker' | 'mitigation';
  data: Record<string, unknown>;
  ts: string;
}

/** Bus interno de eventos (SSE hacia la UI) + alertas salientes por webhook. */
@Injectable()
export class EventsService {
  private bus = new EventEmitter().setMaxListeners(200);

  emit(type: SfEvent['type'], data: Record<string, unknown>, alert?: string): void {
    const ev: SfEvent = { type, data, ts: new Date().toISOString() };
    this.bus.emit('event', ev);
    const url = cfg().alertWebhookUrl;
    if (alert && url) {
      // Compatible con Slack/Mattermost/Teams incoming webhooks (campo "text").
      void fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ text: `[SpecterFlow] ${alert}`, event: ev }),
        signal: AbortSignal.timeout(5000),
      }).catch(() => undefined);
    }
  }

  subscribe(fn: (e: SfEvent) => void): () => void {
    this.bus.on('event', fn);
    return () => this.bus.off('event', fn);
  }
}
