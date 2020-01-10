import { Strategy } from 'passport';

interface StrategyOptions {
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
  scope?: string | string[];
  scopeSeparator?: string;
  sessionKey?: string;
  state?: any;
}
interface ShortLivedAuthTokenResponse {
  access_token: string;
  user_id: number;
}

interface LongLivedAuthTokenResponse {
  access_token: string;
  expires_in: number;
  token_type: string;
}

interface UserProfileResponse {
  id: number;
  account_type: 'BUSINESS' | 'CONSUMER' | 'CREATOR' | 'PRIVATE';
  username: string;
}

type VerifyFunction = (
  accessToken: string,
  profile: any,
  cb: (err: any, user: any) => void
) => void;

declare class InstagramStrategy extends Strategy {
  constructor(options: StrategyOptions);
}

export {
  ShortLivedAuthTokenResponse,
  LongLivedAuthTokenResponse,
  UserProfileResponse,
  VerifyFunction,
  StrategyOptions
};

export default InstagramStrategy;
