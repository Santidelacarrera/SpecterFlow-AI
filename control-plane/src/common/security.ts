import { NextFunction, Request, Response } from 'express';
import { cfg } from './config';

export function securityHeaders(_req: Request, res: Response, next: NextFunction): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
  res.removeHeader('X-Powered-By');
  next();
}

/** Rate limit en memoria por clave API (o IP) con ventana fija de 1 minuto. */
export function rateLimiter(limit = cfg().rateLimitPerMin) {
  const hits = new Map<string, { n: number; reset: number }>();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
  }, 60_000).unref();
  return (req: Request, res: Response, next: NextFunction): void => {
    if (req.path === '/health') return next();
    const id = String(req.headers['x-api-key'] ?? req.ip);
    const now = Date.now();
    let h = hits.get(id);
    if (!h || h.reset < now) hits.set(id, (h = { n: 0, reset: now + 60_000 }));
    h.n++;
    res.setHeader('X-RateLimit-Limit', String(limit));
    res.setHeader('X-RateLimit-Remaining', String(Math.max(0, limit - h.n)));
    if (h.n > limit) {
      res.setHeader('Retry-After', String(Math.ceil((h.reset - now) / 1000)));
      res.status(429).json({ statusCode: 429, message: 'rate limit exceeded' });
      return;
    }
    next();
  };
}
