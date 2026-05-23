import { api } from './client';
import type { UserInfo } from '../types';

export interface LoginResponse {
  token: string;
  user: UserInfo;
}

/** Returned by /api/auth/login when the user has a verified TOTP factor.
 *  The client must complete sign-in with POST /api/auth/login/totp. */
export interface TotpChallenge {
  stage: 'totp_required';
  challenge_id: string;
}

/** Discriminated by the presence of `stage`. */
export type LoginOutcome = LoginResponse | TotpChallenge;

export function isTotpChallenge(o: LoginOutcome): o is TotpChallenge {
  return (o as TotpChallenge).stage === 'totp_required';
}

export interface TotpStatus {
  enrolled: boolean;
  verified: boolean;
}

export interface EnrollResponse {
  secret_b32: string;
  provisioning_uri: string;
  qr_png_b64: string;
}

export const authApi = {
  login: (username: string, password: string) =>
    api.post<LoginOutcome>('/api/auth/login', { username, password }),
  loginTotp: (challenge_id: string, code: string) =>
    api.post<LoginResponse>('/api/auth/login/totp', { challenge_id, code }),
  logout: () => api.post<{ ok: true; logout_url?: string }>('/api/auth/logout'),
  me: () => api.get<UserInfo>('/api/auth/me'),

  totpStatus: () => api.get<TotpStatus>('/api/auth/totp'),
  totpEnroll: () => api.post<EnrollResponse>('/api/auth/totp/enroll'),
  totpConfirm: (code: string) => api.post<{ ok: true }>('/api/auth/totp/confirm', { code }),
  totpDisable: () => api.delete<{ ok: true }>('/api/auth/totp'),
};
