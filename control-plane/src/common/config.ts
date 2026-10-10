export type Role = 'SECOPS' | 'FINOPS' | 'ADMIN' | 'VIEWER';

export const cfg = () => ({
  port: Number(process.env.PORT ?? 3000),
  redisUrl: process.env.REDIS_URL,
  engineUrl: process.env.ENGINE_URL ?? 'http://localhost:8000',
  internalToken: process.env.INTERNAL_TOKEN ?? 'dev-internal-token',
  auditFile: process.env.AUDIT_FILE,
  apiKeys: parseKeys(process.env.API_KEYS ?? 'secops-key:SECOPS,finops-key:FINOPS,admin-key:ADMIN,viewer-key:VIEWER'),
  targetAllowlist: (process.env.TARGET_ALLOWLIST ?? 'localhost,127.0.0.1,vulnerable-agent').split(',').map((s) => s.trim()),
  breaker: {
    budgetUsd: Number(process.env.BUDGET_USD ?? 5),
    windowSec: Number(process.env.BUDGET_WINDOW_SEC ?? 60),
    loopRepeat: Number(process.env.LOOP_REPEAT_THRESHOLD ?? 5),
    failureRate: Number(process.env.FAILURE_RATE_THRESHOLD ?? 0.5),
    minRequests: Number(process.env.FAILURE_MIN_REQUESTS ?? 10),
    cooldownSec: Number(process.env.BREAKER_COOLDOWN_SEC ?? 60),
  },
  priceInPerMtok: Number(process.env.PRICE_IN_PER_MTOK ?? 3),
  priceOutPerMtok: Number(process.env.PRICE_OUT_PER_MTOK ?? 15),
});

export function parseKeys(raw: string): Record<string, Role> {
  const out: Record<string, Role> = {};
  for (const pair of raw.split(',')) {
    const [key, role] = pair.split(':').map((s) => s.trim());
    if (key && ['SECOPS', 'FINOPS', 'ADMIN', 'VIEWER'].includes(role)) out[key] = role as Role;
  }
  return out;
}

export const estimateTokens = (text: string): number => (text ? Math.max(1, Math.ceil(text.length / 4)) : 0);

export const costUsd = (inTok: number, outTok: number, c = cfg()): number =>
  Math.round(((inTok * c.priceInPerMtok + outTok * c.priceOutPerMtok) / 1_000_000) * 1e6) / 1e6;
