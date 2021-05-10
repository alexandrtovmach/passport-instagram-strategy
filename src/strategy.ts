import { Request } from "express";
import { Strategy } from "passport";
import url from "url";
import {
  ShortLivedAuthTokenResponse,
  LongLivedAuthTokenResponse,
  StrategyOptions,
  VerifyFunction,
  UserProfileResponse
} from "../";
import { AUTHORIZE_URL } from "./links";
import { getShortLivedAccessToken, getLongLivedAccessToken, getUserProfile } from "./requests";

class InstagramStrategy extends Strategy {
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  verify: VerifyFunction;
  name = "instagram";

  constructor(options: StrategyOptions, verify: VerifyFunction) {
    super();
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret;
    this.callbackUrl = options.callbackUrl;
    this.verify = verify;
  }

  async authenticate(req: Request, options?: any) {
    options = options || {};

    let tokenData: any = {};
    if (req.query && req.query.code) {
      // token request
      try {
        const shortLivedAccessTokenData: ShortLivedAuthTokenResponse = await getShortLivedAccessToken({
          clientId: this.clientId,
          clientSecret: this.clientSecret,
          callbackUrl: this.callbackUrl,
          code: String(req.query.code)
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
        return this.error(new Error("Failed to obtain access token"));
      }

      try {
        const userData: UserProfileResponse = await getUserProfile(tokenData.access_token);
        if (!userData) {
          return this.error(new Error("Failed to fetch user data"));
        } else {
          this.verify(tokenData.access_token, userData, (err, user) => {
            if (err) {
              this.fail(err);
            } else {
              this.success({
                provider: "instagram",
                ...user
              });
            }
          });
        }
      } catch (err) {
        return this.error(new Error("Can't get user profile"));
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
      const redirectUrl = `${AUTHORIZE_URL}?app_id=${this.clientId}&redirect_uri=${this.callbackUrl}&scope=${scopes}&state=${options.state}&response_type=code`;
      const location = url.format(redirectUrl);
      this.redirect(location);
    }
  }
}

export default InstagramStrategy;
