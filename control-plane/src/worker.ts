/** Proceso worker independiente: consume la cola BullMQ, llama al engine y reporta al control plane. */
import { Worker } from 'bullmq';
import IORedis from 'ioredis';
import { runCampaignJob } from './campaigns/campaigns.service';
import { cfg } from './common/config';

const { redisUrl, engineUrl, internalToken } = cfg();
const controlPlane = process.env.CONTROL_PLANE_URL ?? 'http://localhost:3000';
if (!redisUrl) throw new Error('REDIS_URL is required for the worker');

const post = (path: string, body: unknown) =>
  fetch(`${controlPlane}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-internal-token': internalToken },
    body: JSON.stringify(body),
  });

const worker = new Worker(
  'campaigns',
  async (job) => {
    try {
      const report = await runCampaignJob(job.data, engineUrl);
      const r = await post('/internal/campaign-results', { job: job.data, report });
      if (!r.ok) throw new Error(`control plane responded ${r.status}`);
    } catch (e) {
      await post('/internal/campaign-results', { job: job.data, error: String(e) }).catch(() => undefined);
      throw e;
    }
  },
  { connection: new IORedis(redisUrl, { maxRetriesPerRequest: null }), concurrency: 2 },
);
worker.on('ready', () => console.log('[worker] ready'));
worker.on('failed', (j, e) => console.error('[worker] job failed', j?.id, e.message));
process.on('SIGTERM', () => void worker.close().then(() => process.exit(0)));
