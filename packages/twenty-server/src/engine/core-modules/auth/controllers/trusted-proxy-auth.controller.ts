import { Controller, Get, Req, Res, UseFilters, UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import { Request, Response } from 'express';
import { ApiPath } from 'twenty-shared/types';
import { Repository } from 'typeorm';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { AuthOAuthExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-oauth-exception.filter';
import { AuthRestApiExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-rest-api-exception.filter';
import { AuthService } from 'src/engine/core-modules/auth/services/auth.service';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';
import { WorkspaceEntity } from 'src/engine/core-modules/workspace/workspace.entity';
import { NoPermissionGuard } from 'src/engine/guards/no-permission.guard';
import { PublicEndpointGuard } from 'src/engine/guards/public-endpoint.guard';

/**
 * Quiubot-specific: sign a user into Twenty using the identity oauth2-proxy
 * already verified (X-Forwarded-Email), so a tenant admin who's already
 * authenticated at the portal/oauth2-proxy layer never sees Twenty's own
 * login form. NOT part of upstream Twenty — genuine SSO (SAML/OIDC) is an
 * Enterprise-licensed feature there (see oidc.auth.strategy.ts), so this
 * reuses the same sign-in-or-create + SSO-exchange-token flow Google/
 * Microsoft login already goes through, just triggered by a trusted
 * reverse-proxy header instead of an OAuth callback.
 *
 * SECURITY: this is only safe because twenty-server has no public ingress
 * of its own on Railway — oauth2-proxy (internal network only) is the sole
 * caller, so X-Forwarded-Email cannot be spoofed by an external request.
 * Do not re-attach a public domain to this service without revisiting this.
 */
@Controller(`${ApiPath.Auth}/trusted-proxy`)
@UseFilters(AuthRestApiExceptionFilter)
export class TrustedProxyAuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectRepository(WorkspaceEntity)
    private readonly workspaceRepository: Repository<WorkspaceEntity>,
  ) {}

  /**
   * Multi-workspace resolution. Two sources, tried in order:
   *
   * 1. control-plane (owns the email->tenant->workspace mapping via
   *    portal_users + tenant_registry.twenty_workspace_id — see
   *    control-plane/app/twenty_crm.py). IMPORTANT: control-plane's Railway
   *    deployment is INTENTIONALLY not the one used in production — the
   *    real control-plane runs locally on the operator's machine (see
   *    docs/vigente/seguridad-infraestructura.md + memory deploy-and-idp),
   *    so RAILWAY_SERVICE_CONTROL_PLANE_URL points at a service kept
   *    stopped on purpose (AUTH_MODE=demo forbidden in production,
   *    restartPolicyType=NEVER). This call will therefore ALWAYS fail/
   *    timeout in production today (hard 3s timeout below so a stopped
   *    service can't hang the whole login flow) — kept as a fast-path in
   *    case control-plane ever does become reachable, but never relied on.
   *
   * 2. Twenty's OWN membership table, queried directly here: any workspace
   *    where a WorkspaceUser with this email already exists. This is the
   *    real fallback in practice, and is why this method exists in this
   *    controller (not just calling signInUpWithSocialSSO with no
   *    workspaceId) — that method's own no-workspaceId branch routes
   *    through a "pick or create a workspace" flow instead
   *    (auth.service.ts's signInUpWithSocialSSO, "Route SSO sign-ins
   *    through the same create-or-select flow as credentials instead of
   *    landing straight on a workspace subdomain"), which would leave an
   *    EXISTING member stuck on that picker instead of their own CRM. We
   *    deliberately do NOT reuse AuthSsoService.
   *    findWorkspaceFromWorkspaceIdOrAuthProvider for this — it additionally
   *    filters by an isGoogleAuthEnabled/isMicrosoftAuthEnabled/
   *    isPasswordAuthEnabled column keyed off `authProvider`, which doesn't
   *    apply to this internal trust boundary (oauth2-proxy/Supabase already
   *    authenticated the caller) and could wrongly return nothing for a
   *    workspace that simply never toggled that specific flag.
   *
   * Only once BOTH miss do we fall back to QUIUBOT_DEFAULT_WORKSPACE_ID —
   * the original single-workspace "Salto Angel" behavior — so a genuinely
   * new email with no membership anywhere still lands somewhere sensible
   * instead of an error. Confirmed live 2026-09-07: without step 2,
   * prueba-ingeniousmind@example.com (a real member of the "ingeniousmind"
   * workspace) was being silently defaulted into Salto Angel's own
   * subdomain and shown ITS onboarding wizard instead of reaching its own
   * workspace, because step 1 always fails as explained above.
   */
  private async resolveWorkspaceId(email: string): Promise<string | null> {
    const controlPlaneUrl = process.env.RAILWAY_SERVICE_CONTROL_PLANE_URL;
    const opsSecret = process.env.TWENTY_OPS_SECRET;

    if (controlPlaneUrl && opsSecret) {
      try {
        const res = await fetch(
          `${controlPlaneUrl}/internal/twenty/workspace-for-email?email=${encodeURIComponent(email)}`,
          { headers: { 'x-twenty-ops-secret': opsSecret }, signal: AbortSignal.timeout(3000) },
        );

        if (res.ok) {
          const body = await res.json();

          if (body?.workspace_id) {
            return body.workspace_id as string;
          }
        }
      } catch {
        // fall through to the direct membership lookup below
      }
    }

    const existingMembership = await this.workspaceRepository.findOne({
      where: { workspaceUsers: { user: { email } } },
      relations: ['workspaceUsers', 'workspaceUsers.user'],
    });

    if (existingMembership) {
      return existingMembership.id;
    }

    return process.env.QUIUBOT_DEFAULT_WORKSPACE_ID ?? null;
  }

  @Get('redirect')
  @UseGuards(PublicEndpointGuard, NoPermissionGuard)
  @UseFilters(AuthOAuthExceptionFilter)
  async trustedProxyAuthRedirect(@Req() req: Request, @Res() res: Response) {
    const email = req.header('x-forwarded-email');

    if (!email) {
      throw new AuthException(
        'Missing trusted proxy identity header',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    // Without a workspaceId, signInUpWithSocialSSO treats every caller as
    // workspace-agnostic (issues a "pick or create a workspace" token) even
    // for a user who already belongs to a workspace — that's what left an
    // already-valid member stuck on a "Welcome, X" / pick-a-workspace screen
    // instead of landing in the CRM. Every caller now has exactly one real
    // workspace to land in, resolved above.
    const workspaceId = await this.resolveWorkspaceId(email);

    if (!workspaceId) {
      throw new AuthException(
        'No workspace could be resolved for this identity',
        AuthExceptionCode.INTERNAL_SERVER_ERROR,
      );
    }

    return res.redirect(
      await this.authService.signInUpWithSocialSSO(
        {
          email,
          picture: null,
          action: 'join-workspace',
          workspaceId,
        },
        AuthProviderEnum.SSO,
      ),
    );
  }
}
