import OAuth2Strategy, {
  InternalOAuthError,
  StrategyOptions,
  VerifyFunction
} from "passport-oauth2";

const AUTHORIZE_URL = "https://api.instagram.com/oauth/authorize/";
const ACCESS_TOKEN_URL = "https://api.instagram.com/oauth/access_token";
const GET_USER_URL = "https://api.instagram.com/v1/users/self";

class InstagramStrategy extends OAuth2Strategy {
  name = "instagram";

  authenticate = () => {};

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
      tokenURL: options.tokenURL || ACCESS_TOKEN_URL
    },
    verify
  );

export default getStrategy;
