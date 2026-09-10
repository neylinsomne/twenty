import { Controller, Get, Query, Res, UseFilters, UseGuards } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';

import * as jwt from 'jsonwebtoken';
import { Response } from 'express';
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
import { InjectCacheStorage } from 'src/engine/core-modules/cache-storage/decorators/cache-storage.decorator';
import { CacheStorageService } from 'src/engine/core-modules/cache-storage/services/cache-storage.service';
import { CacheStorageNamespace } from 'src/engine/core-modules/cache-storage/types/cache-storage-namespace.enum';

/**
 * Quiubot-specific: sign a user into Twenty using a short-lived, single-use
 * code the PORTAL mints for itself (Diache backend's
 * POST /connectors/crm/handoff-code), so a tenant admin who's already
 * authenticated at the portal never sees Twenty's own login form. NOT part
 * of upstream Twenty — genuine SSO (SAML/OIDC) is an Enterprise-licensed
 * feature there (see oidc.auth.strategy.ts), so this reuses the same
 * sign-in-or-create + SSO-exchange-token flow Google/Microsoft login already
 * goes through, just triggered by a signed handoff code instead of an OAuth
 * callback.
 *
 * SECURITY: identity comes from verifying `?code=` (HMAC-SHA256, shared
 * secret CRM_HANDOFF_JWT_SECRET with the Diache backend, 60s expiry,
 * single-use enforced via Redis) — NOT from oauth2-proxy's X-Forwarded-Email
 * header. That header used to be trusted here on the reasoning that
 * twenty-server has no public ingress of its own (oauth2-proxy, internal
 * network only, is the sole caller, so the header can't be spoofed
 * externally) — true, but insufficient: oauth2-proxy's OWN session cookie is
 * scoped to the whole .vara-alta.lat apex and stays cached per browser
 * independently of which tenant is currently logged into the portal, so the
 * header's value could be legitimately-set-by-oauth2-proxy and still be the
 * WRONG (stale, cross-tenant) identity (confirmed live 2026-09-10). oauth2-
 * proxy still fronts this whole service as the perimeter gate; it just no
 * longer decides WHO for this specific decision.
 */
@Controller(`${ApiPath.Auth}/trusted-proxy`)
@UseFilters(AuthRestApiExceptionFilter)
export class TrustedProxyAuthController {
  constructor(
    private readonly authService: AuthService,
    @InjectRepository(WorkspaceEntity)
    private readonly workspaceRepository: Repository<WorkspaceEntity>,
    @InjectCacheStorage(CacheStorageNamespace.EngineAuthSession)
    private readonly authSessionCache: CacheStorageService,
  ) {}

  /**
   * Verifies the short-lived, single-use "CRM handoff code" the portal mints
   * for itself (Diache backend's POST /connectors/crm/handoff-code) and
   * passes as ?code=. Returns the verified email, or throws.
   *
   * Replaces trusting oauth2-proxy's X-Forwarded-Email header for this
   * decision (oauth2-proxy stays in front as the perimeter gate — it just no
   * longer decides WHO). Confirmed live 2026-09-10: that header's identity is
   * whatever oauth2-proxy's own session cookie (scoped to the whole
   * .vara-alta.lat apex, cached PER BROWSER) last authenticated — completely
   * decoupled from which tenant is CURRENTLY logged into the portal in that
   * browser, so a browser that ever resolved tenant A kept getting tenant A's
   * workspace forever after, for every other tenant, forever. The code is
   * signed fresh by the portal's own backend from ITS OWN live Supabase
   * session on every CRM-tab visit, so it can't go stale the same way.
   */
  private async verifyHandoffCode(code: string | undefined): Promise<string> {
    if (!code) {
      throw new AuthException(
        'Missing CRM handoff code',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    let payload: jwt.JwtPayload;

    try {
      payload = jwt.verify(code, process.env.CRM_HANDOFF_JWT_SECRET ?? '', {
        algorithms: ['HS256'],
      }) as jwt.JwtPayload;
    } catch {
      throw new AuthException(
        'Invalid or expired CRM handoff code',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    const email = payload.email as string | undefined;
    const jti = payload.jti as string | undefined;

    if (!email || !jti) {
      throw new AuthException(
        'CRM handoff code missing required claims',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    // Single-use: the FIRST redemption wins, any replay (e.g. someone
    // capturing this URL and reloading it) is rejected. Fail CLOSED if Redis
    // itself is unreachable — never silently skip the replay check.
    let firstUse: boolean;

    try {
      firstUse = await this.authSessionCache.setIfAbsent(
        `crm-handoff:${jti}`,
        true,
        60_000,
      );
    } catch {
      throw new AuthException(
        'Could not verify CRM handoff code (cache unavailable)',
        AuthExceptionCode.INTERNAL_SERVER_ERROR,
      );
    }

    if (!firstUse) {
      throw new AuthException(
        'CRM handoff code already used',
        AuthExceptionCode.INVALID_INPUT,
      );
    }

    return email;
  }

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
  async trustedProxyAuthRedirect(
    @Query('code') code: string | undefined,
    @Res() res: Response,
  ) {
    const email = await this.verifyHandoffCode(code);

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
