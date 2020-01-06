import { Strategy } from 'passport';

interface AuthTokenResponse {
  access_token: string;
  user_id: number;
}

interface UserProfileResponse {
  id: number;
  account_type: "BUSINESS" | "CONSUMER" | "CREATOR";
  username: string;
}

declare class InstagramStrategy extends Strategy {}

export { AuthTokenResponse, UserProfileResponse };

export default InstagramStrategy;