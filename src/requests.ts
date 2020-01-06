import request from "request-promise-native";
import { SHORT_ACCESS_TOKEN_URL, LONG_ACCESS_TOKEN_URL, GET_USER_URL } from "./links";

export const getShortLivedAccessToken = async ({
  code,
  clientId,
  clientSecret,
  callbackUrl
}: {
  code: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
}) => {
  const form = {
    code,
    app_id: clientId,
    app_secret: clientSecret,
    redirect_uri: callbackUrl,
    grant_type: "authorization_code"
  };
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded"
  };

  const jsonRes = await request.post({
    url: SHORT_ACCESS_TOKEN_URL,
    form,
    headers
  });
  return JSON.parse(jsonRes);
};

export const getLongLivedAccessToken = async ({
  accessToken,
  clientSecret
}: {
  accessToken: string;
  clientSecret: string;
}) => {
  const url = `${LONG_ACCESS_TOKEN_URL}?grant_type=ig_exchange_token&client_secret=${clientSecret}&access_token=${accessToken}`;
  const jsonRes = await request.get(url);
  return JSON.parse(jsonRes);
};

export const getUserProfile = async (accessToken: string) => {
  const url = `${GET_USER_URL}?fields=id,username&access_token=${accessToken}`;
  const jsonRes = await request.get(url);
  return JSON.parse(jsonRes);
};
