import {
  Controller,
  InternalServerErrorException,
  NotFoundException,
  Post,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { addDays } from 'date-fns';
import { type Request } from 'express';
import { Repository } from 'typeorm';

import { ApiKeyService } from 'src/engine/core-modules/api-key/services/api-key.service';
import { NoPermissionGuard } from 'src/engine/guards/no-permission.guard';
import { PublicEndpointGuard } from 'src/engine/guards/public-endpoint.guard';
import { WorkspaceEntity } from 'src/engine/core-modules/workspace/workspace.entity';
import { RoleEntity } from 'src/engine/metadata-modules/role/role.entity';
import { InjectWorkspaceScopedRepository } from 'src/engine/twenty-orm/workspace-scoped-repository/inject-workspace-scoped-repository.decorator';
import { WorkspaceScopedRepository } from 'src/engine/twenty-orm/workspace-scoped-repository/workspace-scoped-repository';
import { STANDARD_ROLE } from 'src/engine/workspace-manager/twenty-standard-application/constants/standard-role.constant';

const NEVER_EXPIRE_DAYS = 100 * 365;

/**
 * Quiubot-only, operator-triggered one-off: mint an admin-scoped API key for
 * a workspace, the same way Twenty's own `workspace:generate-api-key` CLI
 * command does (engine/core-modules/api-key/commands/generate-api-key.
 * command.ts) — that command refuses to run outside development/test, and
 * this deployment is production, so it can't be exec'd here. Reuses the
 * exact same ApiKeyService calls, just reachable over HTTP.
 *
 * Gated by a shared secret (QUIUBOT_OPS_SECRET), checked in addition to
 * relying on twenty-server having no public Railway domain — this mints a
 * genuinely sensitive credential, so it gets its own header check rather
 * than piggybacking on the trusted-proxy-auth controller's identity-header
 * trust. Meant to be used a handful of times (initial bootstrap, key
 * rotation), not on every request.
 */
@Controller('quiubot-ops')
export class QuiubotMintApiKeyController {
  constructor(
    @InjectRepository(WorkspaceEntity)
    private readonly workspaceRepository: Repository<WorkspaceEntity>,
    @InjectWorkspaceScopedRepository(RoleEntity)
    private readonly roleRepository: WorkspaceScopedRepository<RoleEntity>,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  @Post('mint-api-key')
  @UseGuards(PublicEndpointGuard, NoPermissionGuard)
  async mintApiKey(@Req() req: Request) {
    const opsSecret = process.env.QUIUBOT_OPS_SECRET;

    if (!opsSecret || req.header('x-quiubot-ops-secret') !== opsSecret) {
      throw new UnauthorizedException('Invalid or missing ops secret');
    }

    const workspaceId = process.env.QUIUBOT_DEFAULT_WORKSPACE_ID;

    if (!workspaceId) {
      throw new InternalServerErrorException(
        'QUIUBOT_DEFAULT_WORKSPACE_ID is not configured',
      );
    }

    const workspace = await this.workspaceRepository.findOne({
      where: { id: workspaceId },
    });

    if (!workspace) {
      throw new NotFoundException(`Workspace ${workspaceId} not found`);
    }

    const adminRole = await this.roleRepository.findOne(workspace.id, {
      where: {
        universalIdentifier: STANDARD_ROLE.admin.universalIdentifier,
      },
    });

    if (!adminRole) {
      throw new NotFoundException(
        `No Admin role found for workspace ${workspace.id}`,
      );
    }

    const expiresAt = addDays(new Date(), NEVER_EXPIRE_DAYS);

    const apiKey = await this.apiKeyService.create({
      name: 'Quiubot backend (leads sync)',
      expiresAt,
      workspaceId: workspace.id,
      roleId: adminRole.id,
    });

    const tokenResult = await this.apiKeyService.generateApiKeyToken(
      workspace.id,
      apiKey.id,
      expiresAt,
    );

    if (!tokenResult) {
      throw new InternalServerErrorException('Failed to generate token');
    }

    return { token: tokenResult.token, apiKeyId: apiKey.id, workspaceId: workspace.id };
  }
}
