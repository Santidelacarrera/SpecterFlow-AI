import { BadRequestException, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';
import { randomUUID } from 'crypto';
import { AgentsService } from '../agents/agents.service';
import { AuditService } from '../audit/audit.service';
import { cfg } from '../common/config';
import { IncidentsService } from '../incidents/incidents.service';

export interface CampaignJob {
  campaignId: string;
  targetUrl: string;
  agentId?: string;
  attackIds?: string[];
  budgetUsd: number;
}

export interface Campaign {
  id: string;
  targetUrl: string;
  agentId?: string;
  status: 'queued' | 'running' | 'done' | 'failed';
  createdAt: string;
  exploited?: number;
  maxSeverity?: string;
  costUsd?: number;
  error?: string;
}

/** Ejecuta una campaña contra el engine. Compartido por el worker BullMQ y el modo inline. */
export async function runCampaignJob(job: CampaignJob, engineUrl: string): Promise<any> {
  const r = await fetch(`${engineUrl}/v1/campaigns/run`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ target_url: job.targetUrl, attack_ids: job.attackIds, budget_usd: job.budgetUsd }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!r.ok) throw new Error(`engine responded ${r.status}: ${await r.text()}`);
  return r.json();
}

@Injectable()
export class CampaignsService implements OnModuleInit, OnModuleDestroy {
  private campaigns = new Map<string, Campaign>();
  private queue?: Queue;
  private worker?: Worker;
  private conn?: IORedis;

  constructor(
    private readonly agents: AgentsService,
    private readonly incidents: IncidentsService,
    private readonly audit: AuditService,
  ) {}

  onModuleInit() {
    const { redisUrl } = cfg();
    if (!redisUrl) return; // modo inline (dev/tests)
    this.conn = new IORedis(redisUrl, { maxRetriesPerRequest: null });
    this.queue = new Queue('campaigns', { connection: this.conn });
    // El worker real corre en su propio proceso (dist/worker.js). Con RUN_WORKER=true también aquí.
    if (process.env.RUN_WORKER === 'true') {
      this.worker = new Worker('campaigns', async (j) => runCampaignJob(j.data, cfg().engineUrl).then((report) => this.complete(j.data, report)), {
        connection: this.conn,
      });
    }
  }

  async onModuleDestroy() {
    await this.worker?.close();
    await this.queue?.close();
    this.conn?.disconnect();
  }

  list(): Campaign[] {
    return [...this.campaigns.values()].reverse();
  }

  async create(targetUrl: string, attackIds?: string[], budgetUsd = 1): Promise<Campaign> {
    let host: string;
    try {
      host = new URL(targetUrl).hostname;
    } catch {
      throw new BadRequestException('invalid target url');
    }
    const agent = this.agents.findByUrl(targetUrl);
    if (!agent && !cfg().targetAllowlist.includes(host)) {
      throw new BadRequestException(`target ${host} is not a registered agent or in TARGET_ALLOWLIST (sandbox only)`);
    }
    const c: Campaign = { id: randomUUID(), targetUrl, agentId: agent?.id, status: 'queued', createdAt: new Date().toISOString() };
    this.campaigns.set(c.id, c);
    this.audit.append('system', 'campaign.queued', { id: c.id, targetUrl });
    const job: CampaignJob = { campaignId: c.id, targetUrl, agentId: agent?.id, attackIds, budgetUsd };

    if (this.queue) {
      await this.queue.add('run', job, { attempts: 2, removeOnComplete: 100 });
    } else {
      void this.runInline(job);
    }
    return c;
  }

  private async runInline(job: CampaignJob) {
    try {
      this.campaigns.get(job.campaignId)!.status = 'running';
      this.complete(job, await runCampaignJob(job, cfg().engineUrl));
    } catch (e) {
      this.fail(job.campaignId, e);
    }
  }

  /** Llamado con el reporte del engine (desde el worker interno o el endpoint /internal). */
  complete(job: CampaignJob, report: any) {
    const c = this.campaigns.get(job.campaignId);
    const created = this.incidents.fromCampaign(report, job.agentId);
    if (c) {
      c.status = 'done';
      c.exploited = report.exploited_count;
      c.maxSeverity = report.max_severity;
      c.costUsd = report.total_usage?.cost_usd;
    }
    this.audit.append('system', 'campaign.completed', { id: job.campaignId, exploited: report.exploited_count, incidents: created.length });
    return { incidents: created.length };
  }

  fail(campaignId: string, err: unknown) {
    const c = this.campaigns.get(campaignId);
    if (c) {
      c.status = 'failed';
      c.error = err instanceof Error ? err.message : String(err);
    }
    this.audit.append('system', 'campaign.failed', { id: campaignId, error: String(err) });
  }
}
