// @ts-ignore
import originalURL from "original-url";
import { Request } from "express";
import { Strategy } from "passport";
import url from "url";
import { InternalOAuthError, AuthorizationError, TokenError } from "passport-oauth2";
import {
  ShortLivedAuthTokenResponse,
  LongLivedAuthTokenResponse,
  StrategyOptions,
  UserProfileResponse
} from "../index";
import { AUTHORIZE_URL } from "./links";
import { getShortLivedAccessToken, getLongLivedAccessToken, getUserProfile } from "./requests";

class InstagramStrategy extends Strategy {
  clientId: string;
  clientSecret: string;
  callbackUrl?: string;
  name = "instagram";

  constructor(options: StrategyOptions) {
    super();
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.callbackUrl = options.callbackUrl;
  }

  async authenticate(req: Request, options?: any) {
    options = options || {};

    if (req.query && req.query.error) {
      return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
    }

    const callbackUrl = this.callbackUrl || originalURL(req);
    let tokenData: any = {};
    if (req.query && req.query.code) {
      // token request
      try {
        const shortLivedAccessTokenData: ShortLivedAuthTokenResponse = await getShortLivedAccessToken({
          clientId: this.clientId,
          clientSecret: this.clientSecret,
          callbackUrl: callbackUrl,
          code: req.query.code
        });

        tokenData = {
          ...tokenData,
          ...shortLivedAccessTokenData
        };

        const longLivedAccessTokenData: LongLivedAuthTokenResponse = await getLongLivedAccessToken({
          accessToken: shortLivedAccessTokenData.access_token,
          clientSecret: this.clientSecret
        });

        tokenData = {
          ...tokenData,
          ...longLivedAccessTokenData
        };
      } catch (err) {
        return this.error(new TokenError("Failed to obtain access token", err.message || err));
      }

      try {
        const userData: UserProfileResponse = await getUserProfile(tokenData.access_token);
        if (!userData) {
          return this.error(new Error("Failed to fetch user data"));
        } else {
          this.success({
            provider: "instagram",
            ...userData,
            ...tokenData
          });
        }
      } catch (err) {
        return this.error(new InternalOAuthError("Can't get user profile", err));
      }
    } else {
      // code request
      const getScope = (scope?: string | [], scopeSeparator?: string) => {
        if (scope && Array.isArray(scope)) {
          return scope.join(scopeSeparator);
        } else {
          return scope || "user_profile";
        }
      };
      const scopes = getScope(options.scope, options.scopeSeparator || ",");
      const redirectUrl = `${AUTHORIZE_URL}?app_id=${this.clientId}&redirect_uri=${callbackUrl}&scope=${scopes}&state=${options.state}&response_type=code`;
      const location = url.format(redirectUrl);
      this.redirect(location);
    }
  }
}

export default InstagramStrategy;
