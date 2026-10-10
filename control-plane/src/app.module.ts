import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { AgentsService } from './agents/agents.service';
import { ApprovalsService } from './approvals/approvals.service';
import { AppController } from './app.controller';
import { AuditService } from './audit/audit.service';
import { AuthGuard } from './auth/auth';
import { BreakerService } from './breaker/breaker.service';
import { CampaignsService } from './campaigns/campaigns.service';
import { IncidentsService } from './incidents/incidents.service';
import { ProxyController } from './proxy/proxy.controller';

@Module({
  controllers: [AppController, ProxyController],
  providers: [
    AgentsService,
    ApprovalsService,
    AuditService,
    BreakerService,
    CampaignsService,
    IncidentsService,
    { provide: APP_GUARD, useClass: AuthGuard },
  ],
})
export class AppModule {}
