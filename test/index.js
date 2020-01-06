const passport = require("passport");
const { Strategy } = require("../dist");

passport.use(
  new Strategy({
    clientId: "instagramClientId",
    clientSecret: "instagramClientSecret",
    callbackURL: "auth/instagram/callback"
  })
);
