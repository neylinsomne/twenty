import {
  Controller,
  Get,
  InternalServerErrorException,
  Query,
  Req,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { addDays } from 'date-fns';
import { type Request } from 'express';
import { Repository } from 'typeorm';

import { type AuthContextUser } from 'src/engine/core-modules/auth/types/auth-context.type';
import { SignInUpService } from 'src/engine/core-modules/auth/services/sign-in-up.service';
import { ApiKeyService } from 'src/engine/core-modules/api-key/services/api-key.service';
import { NoPermissionGuard } from 'src/engine/guards/no-permission.guard';
import { PublicEndpointGuard } from 'src/engine/guards/public-endpoint.guard';
import { WorkspaceEntity } from 'src/engine/core-modules/workspace/workspace.entity';
import { WorkspaceService } from 'src/engine/core-modules/workspace/services/workspace.service';
import { RoleEntity } from 'src/engine/metadata-modules/role/role.entity';
import { InjectWorkspaceScopedRepository } from 'src/engine/twenty-orm/workspace-scoped-repository/inject-workspace-scoped-repository.decorator';
import { WorkspaceScopedRepository } from 'src/engine/twenty-orm/workspace-scoped-repository/workspace-scoped-repository';
import { STANDARD_ROLE } from 'src/engine/workspace-manager/twenty-standard-application/constants/standard-role.constant';

const NEVER_EXPIRE_DAYS = 100 * 365;

// Twenty requires SELECT option `value`s to be UPPER_SNAKE_CASE (verified
// live against the "Salto Angel" workspace — see backend/scripts/
// twenty_setup_channel_field.py, whose fields this mirrors exactly so
// every auto-provisioned workspace starts with the same 3 custom fields
// that script sets up by hand today).
const CHANNEL_OPTIONS = [
  { value: 'WEB', label: 'Web', position: 0, color: 'blue' },
  { value: 'WHATSAPP', label: 'WhatsApp', position: 1, color: 'green' },
  { value: 'UNKNOWN', label: 'Unknown', position: 2, color: 'gray' },
];
const LEAD_STATUS_OPTIONS = [
  { value: 'NEW', label: 'Nuevo', position: 0, color: 'gray' },
  { value: 'INTERESTED', label: 'Interesado', position: 1, color: 'blue' },
  { value: 'CART_ACTIVE', label: 'Carrito activo', position: 2, color: 'yellow' },
  { value: 'NEEDS_FOLLOWUP', label: 'Requiere seguimiento', position: 3, color: 'red' },
  { value: 'CUSTOMER', label: 'Cliente', position: 4, color: 'green' },
];

/**
 * Quiubot-only, control-plane-triggered: provision a brand-new, fully
 * isolated Twenty workspace for one SaaS tenant — a new user (the tenant's
 * own admin email), a new workspace owned by them, activated (standard
 * objects/roles provisioned — same as the `activateWorkspace` GraphQL
 * mutation a real signup flow calls), the same 3 custom Person fields
 * `scripts/twenty_setup_channel_field.py` sets up by hand for the shared
 * "Salto Angel" workspace, and a never-expiring admin API key. Same
 * shared-secret gate and same "call internal services directly, skip the
 * public GraphQL guards" posture as the sibling
 * QuiubotMintApiKeyController — see that file's docstring for why
 * (production has no shell/exec access to run Twenty's own
 * `workspace:generate-api-key` CLI command).
 *
 * Requires IS_MULTIWORKSPACE_ENABLED=true on this deployment — with a
 * single workspace already live ("Salto Angel"), signUpOnNewWorkspace's own
 * internal assertSignUpEnabled() throws SIGNUP_DISABLED otherwise. Also
 * requires IS_WORKSPACE_CREATION_LIMITED_TO_SERVER_ADMINS unset/false: the
 * caller here is always a brand-new user, never an existing admin, so that
 * restriction (meant for the public self-serve signup form) would otherwise
 * always reject it.
 */
@Controller('quiubot-ops')
export class QuiubotProvisionWorkspaceController {
  constructor(
    @InjectRepository(WorkspaceEntity)
    private readonly workspaceRepository: Repository<WorkspaceEntity>,
    @InjectWorkspaceScopedRepository(RoleEntity)
    private readonly roleRepository: WorkspaceScopedRepository<RoleEntity>,
    private readonly signInUpService: SignInUpService,
    private readonly workspaceService: WorkspaceService,
    private readonly apiKeyService: ApiKeyService,
  ) {}

  private checkOpsSecret(req: Request): void {
    const opsSecret = process.env.QUIUBOT_OPS_SECRET;
    const provided =
      req.header('x-quiubot-ops-secret') ?? req.query.secret?.toString();

    if (!opsSecret || provided !== opsSecret) {
      throw new UnauthorizedException('Invalid or missing ops secret');
    }
  }

  private async setupPersonFields(apiKeyToken: string): Promise<void> {
    const baseUrl = (process.env.SERVER_URL ?? '').replace(/\/$/, '');
    const headers = {
      Authorization: `Bearer ${apiKeyToken}`,
      'Content-Type': 'application/json',
    };

    const objectsRes = await fetch(
      `${baseUrl}/rest/metadata/objects?limit=200`,
      { headers },
    );

    if (!objectsRes.ok) {
      throw new InternalServerErrorException(
        `Failed to list metadata objects: ${objectsRes.status}`,
      );
    }

    const objectsBody = await objectsRes.json();
    const objectRows: Array<{ id: string; nameSingular: string }> =
      Array.isArray(objectsBody?.data) ? objectsBody.data : [];
    const person = objectRows.find((o) => o.nameSingular === 'person');

    if (!person) {
      throw new InternalServerErrorException(
        'Person object not found on the newly created workspace',
      );
    }

    const fieldsToCreate = [
      {
        objectMetadataId: person.id,
        type: 'SELECT',
        name: 'channel',
        label: 'Channel',
        options: CHANNEL_OPTIONS,
      },
      {
        objectMetadataId: person.id,
        type: 'TEXT',
        name: 'interest',
        label: 'Interest',
      },
      {
        objectMetadataId: person.id,
        type: 'SELECT',
        name: 'leadStatus',
        label: 'Lead status',
        options: LEAD_STATUS_OPTIONS,
      },
    ];

    // Best-effort per field: a brand-new workspace has none of these yet, so
    // unlike the idempotent Python script this never needs to check for an
    // existing field first — but a partial failure here must not fail the
    // whole provisioning call (the workspace + API key are already real and
    // usable; a missing custom field degrades leads_summary()'s
    // classification, it doesn't break lead capture itself).
    for (const field of fieldsToCreate) {
      const created = await fetch(`${baseUrl}/rest/metadata/fields`, {
        method: 'POST',
        headers,
        body: JSON.stringify(field),
      });

      if (!created.ok) {
        // eslint-disable-next-line no-console
        console.error(
          `quiubot-provision-workspace: failed to create field ${field.name}: ${created.status}`,
        );
      }
    }
  }

  @Get('provision-workspace')
  @UseGuards(PublicEndpointGuard, NoPermissionGuard)
  async provisionWorkspace(@Req() req: Request) {
    this.checkOpsSecret(req);

    const email = req.query.email?.toString();
    const displayName = req.query.display_name?.toString();

    if (!email || !displayName) {
      throw new InternalServerErrorException(
        'email and display_name query params are required',
      );
    }

    const { user, workspace: pendingWorkspace } =
      await this.signInUpService.signUpOnNewWorkspace(
        {
          type: 'newUserWithPicture',
          newUserWithPicture: {
            email,
            firstName: displayName,
            lastName: '',
            picture: '',
            locale: 'es',
          },
        },
        { displayName },
      );

    const activatedWorkspace = await this.workspaceService.activateWorkspace(
      user as unknown as AuthContextUser,
      pendingWorkspace,
    );

    const adminRole = await this.roleRepository.findOne(activatedWorkspace.id, {
      where: {
        universalIdentifier: STANDARD_ROLE.admin.universalIdentifier,
      },
    });

    if (!adminRole) {
      throw new InternalServerErrorException(
        `No Admin role found for workspace ${activatedWorkspace.id}`,
      );
    }

    const expiresAt = addDays(new Date(), NEVER_EXPIRE_DAYS);

    const apiKey = await this.apiKeyService.create({
      name: 'Quiubot backend (leads sync)',
      expiresAt,
      workspaceId: activatedWorkspace.id,
      roleId: adminRole.id,
    });

    const tokenResult = await this.apiKeyService.generateApiKeyToken(
      activatedWorkspace.id,
      apiKey.id,
      expiresAt,
    );

    if (!tokenResult) {
      throw new InternalServerErrorException('Failed to generate token');
    }

    await this.setupPersonFields(tokenResult.token);

    return {
      token: tokenResult.token,
      apiKeyId: apiKey.id,
      workspaceId: activatedWorkspace.id,
    };
  }
}
