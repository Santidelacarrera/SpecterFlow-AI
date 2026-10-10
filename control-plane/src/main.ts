import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { cfg } from './common/config';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { logger: ['log', 'warn', 'error'] });
  app.enableCors({ origin: process.env.CORS_ORIGIN?.split(',') ?? true });
  app.getHttpAdapter().getInstance().set('trust proxy', true);
  await app.listen(cfg().port, '0.0.0.0');
}
void bootstrap();
