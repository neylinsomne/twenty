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

    return res.redirect(
      await this.authService.signInUpWithSocialSSO(
        {
          email,
          picture: null,
          action: 'list-available-workspaces',
        },
        AuthProviderEnum.SSO,
      ),
    );
  }
}
