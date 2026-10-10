import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { cfg, Role } from '../common/config';

export const Roles = (...roles: Role[]) => SetMetadata('roles', roles);
export const Public = () => SetMetadata('public', true);
export const Internal = () => SetMetadata('internal', true);

export interface Principal {
  role: Role;
  keyId: string;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const handler = ctx.getHandler();
    const cls = ctx.getClass();
    const req = ctx.switchToHttp().getRequest();
    if (this.reflector.getAllAndOverride<boolean>('public', [handler, cls])) return true;

    if (this.reflector.getAllAndOverride<boolean>('internal', [handler, cls])) {
      if (req.headers['x-internal-token'] !== cfg().internalToken) throw new UnauthorizedException('bad internal token');
      return true;
    }

    const key = req.headers['x-api-key'] as string | undefined;
    const role = key ? cfg().apiKeys[key] : undefined;
    if (!key || !role) throw new UnauthorizedException('missing or invalid x-api-key');
    req.principal = { role, keyId: key.slice(0, 4) + '…' } satisfies Principal;

    const needed = this.reflector.getAllAndOverride<Role[]>('roles', [handler, cls]);
    if (needed && role !== 'ADMIN' && !needed.includes(role)) throw new ForbiddenException(`role ${role} not allowed`);
    return true;
  }
}
