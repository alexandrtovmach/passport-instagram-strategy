import { Strategy } from 'passport';

interface StrategyOptions {
	clientId: string;
	clientSecret: string;
	callbackUrl?: string;
	scope?: string | string[];
	scopeSeparator?: string;
	sessionKey?: string;
	state?: any;
}
interface AuthTokenResponse {
  access_token: string;
  user_id: number;
}

interface UserProfileResponse {
  id: number;
  account_type: "BUSINESS" | "CONSUMER" | "CREATOR";
  username: string;
}

declare class InstagramStrategy extends Strategy {
	constructor(options: StrategyOptions)
}

export { AuthTokenResponse, UserProfileResponse, StrategyOptions };

export default InstagramStrategy;