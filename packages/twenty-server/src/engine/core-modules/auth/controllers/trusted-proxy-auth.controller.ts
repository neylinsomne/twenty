import { Controller, Get, Req, Res, UseFilters, UseGuards } from '@nestjs/common';

import { Request, Response } from 'express';
import { ApiPath } from 'twenty-shared/types';

import {
  AuthException,
  AuthExceptionCode,
} from 'src/engine/core-modules/auth/auth.exception';
import { AuthOAuthExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-oauth-exception.filter';
import { AuthRestApiExceptionFilter } from 'src/engine/core-modules/auth/filters/auth-rest-api-exception.filter';
import { AuthService } from 'src/engine/core-modules/auth/services/auth.service';
import { AuthProviderEnum } from 'src/engine/core-modules/workspace/types/workspace.type';
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
  constructor(private readonly authService: AuthService) {}

  /**
   * Multi-workspace resolution (control-plane owns the email->tenant->
   * workspace mapping via portal_users + tenant_registry.
   * twenty_workspace_id — see control-plane/app/twenty_crm.py): ask it which
   * workspace this email belongs to. Falls back to
   * QUIUBOT_DEFAULT_WORKSPACE_ID (the original single-workspace "Salto
   * Angel" behavior) on any failure/miss — a tenant with no auto-
   * provisioned workspace of its own, or control-plane being unreachable,
   * must never break login for the workspace that already works today.
   *
   * HARD 3s TIMEOUT on the control-plane call: control-plane's own
   * production deployment can be down/crash-looping (a real incident this
   * session — AUTH_MODE=demo forbidden in production, never fixed there
   * since the REAL control-plane runs locally, not on Railway) without
   * necessarily refusing the TCP connection fast — an un-timed-out fetch()
   * could hang the WHOLE login flow far longer than a user will wait,
   * rendering as a blank/broken iframe instead of degrading to the
   * fallback below.
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
        // fall through to the default workspace below
      }
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
