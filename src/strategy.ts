// @ts-ignore
import originalURL from "original-url";
import { Request } from "express";
import url from "url";
import request from "request-promise-native";
import OAuth2Strategy, {
  InternalOAuthError,
  StrategyOptions,
  VerifyFunction,
  AuthorizationError,
  TokenError
} from "passport-oauth2";

const AUTHORIZE_URL = "https://api.instagram.com/oauth/authorize/";
const SHORT_LIVED_ACCESS_TOKEN_URL =
  "https://api.instagram.com/oauth/access_token/";
const LONG_LIVED_ACCESS_TOKEN_URL = "https://graph.instagram.com/access_token/";
const GET_USER_URL = "https://api.instagram.com/v1/users/this/";

interface AuthTokenResponse {
  access_token: string;
  user_id: number;
}

class InstagramStrategy extends OAuth2Strategy {
  clientId: string;
  clientSecret: string;
  verify: OAuth2Strategy.VerifyFunction;
  stateStore?: OAuth2Strategy.StateStore;
  callbackURL?: string;
  name = "instagram";

  constructor(
    options: OAuth2Strategy.StrategyOptions,
    verify: OAuth2Strategy.VerifyFunction
  ) {
    super(options, verify);
    this.clientId = options.clientID;
    this.clientSecret = options.clientSecret;
    this.callbackURL = options.callbackURL;
    this.stateStore = options.store;
    this.verify = verify;
  }

  authenticate = (req: Request, options?: any) => {
    options = options || {};

    if (req.query && req.query.error) {
      if (req.query.error == "access_denied") {
        return this.fail(req.query.error_description);
      } else {
        return this.error(
          new AuthorizationError(
            req.query.error_description,
            req.query.error,
            req.query.error_uri
          )
        );
      }
    }

    const callbackURL = this.callbackURL || originalURL(req);

    if (req.query && req.query.code) {
      // token request
      const loaded = async (err: any) => {
        if (err) {
          return this.error(err);
        }

        const form = {
          app_id: this.clientId,
          app_secret: this.clientSecret,
          redirect_uri: callbackURL,
          code: req.query.code,
          grant_type: "authorization_code"
        };
        const headers = {
          "Content-Type": "application/x-www-form-urlencoded"
        };

        request
          .post({ url: SHORT_LIVED_ACCESS_TOKEN_URL, form, headers })
          .then(async ({ access_token, user_id }: AuthTokenResponse) => {
            const longLivedAccessTokenRes = await request.get(
              `${LONG_LIVED_ACCESS_TOKEN_URL}?grant_type=ig_exchange_token&client_secret=${this.clientSecret}&access_token=${access_token}`
            );
            this.userProfile(
              longLivedAccessTokenRes.access_token,
              (err, profile) => {
                if (err) {
                  return this.error(err);
                }
                this.success(profile);
              }
            );
          })
          .catch((err: any) => {
            return this.error(
              new TokenError("Failed to obtain access token", err)
            );
          });
      };

      const state = req.query.state;
      try {
        this.stateStore?.verify(req, state, loaded);
      } catch (err) {
        return this.error(err);
      }
    } else {
      // code request
      const getScope = (scope?: string | [], scopeSeparator?: string) => {
        if (scope && Array.isArray(scope)) {
          return scope.join(scopeSeparator);
        } else {
          return scope || "";
        }
      };
      const scopes = getScope(options.scope, options.scopeSeparator || ",");
      const redirectUrl = `https://api.instagram.com/oauth/authorize?app_id=${this.clientId}&redirect_uri=${callbackURL}&scope=${scopes}&state=${options.state}&response_type=code`;
      const location = url.format(redirectUrl);
      this.redirect(location);
    }
  };

  userProfile = (
    accessToken: string,
    done: (err?: Error | null, profile?: any) => void
  ): void => {
    this._oauth2.get(GET_USER_URL, accessToken, (err, body) => {
      if (err) {
        return done(new InternalOAuthError("Can't get user profile", err));
      }
      if (!body) {
        return done(new Error("User response is empty"));
      }
      if (typeof body !== "string") {
        return done(new Error("User response is not valid format"));
      }
      try {
        const json = JSON.parse(body);
        const {
          data: { id, full_name, last_name, first_name, username }
        } = json;
        done(null, {
          provider: "instagram",
          id,
          username,
          displayName: full_name,
          name: {
            familyName: last_name,
            givenName: first_name
          },
          _raw: body,
          _json: json
        });
      } catch (error) {
        done(
          new InternalOAuthError(
            "Something went wrong with getting user",
            error
          )
        );
      }
    });
  };
}

const getStrategy = (
  options: StrategyOptions,
  verify: VerifyFunction
): InstagramStrategy =>
  new InstagramStrategy(
    {
      ...options,
      authorizationURL: options.authorizationURL || AUTHORIZE_URL,
      tokenURL: options.tokenURL || SHORT_LIVED_ACCESS_TOKEN_URL
    },
    verify
  );

export default getStrategy;