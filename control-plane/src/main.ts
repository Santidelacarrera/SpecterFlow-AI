import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { json } from 'express';
import { AppModule } from './app.module';
import { assertProductionConfig, cfg } from './common/config';
import { rateLimiter, securityHeaders } from './common/security';

async function bootstrap() {
  assertProductionConfig();
  const app = await NestFactory.create(AppModule, { logger: ['log', 'warn', 'error'], bodyParser: false });
  app.use(securityHeaders);
  app.use(rateLimiter());
  app.use(json({ limit: process.env.BODY_LIMIT ?? '256kb' }));
  app.enableCors({ origin: process.env.CORS_ORIGIN?.split(',') ?? false });
  app.getHttpAdapter().getInstance().set('trust proxy', process.env.TRUST_PROXY === 'true');
  app.enableShutdownHooks();
  await app.listen(cfg().port, '0.0.0.0');
}
void bootstrap();
