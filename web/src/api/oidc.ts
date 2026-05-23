import { api } from './client';

export interface OidcStatus {
  enabled: boolean;
  provider_name: string;
  /** When true and OIDC is enabled, /login auto-redirects to the IdP unless
   *  the URL has `?local=1` to force the local form. */
  force_login: boolean;
}

export interface OidcStartResponse {
  authorize_url: string;
  state: string;
}

export interface OidcConfig {
  enabled: boolean;
  issuer: string;
  client_id: string;
  /** "***" if a secret is stored, "" if not. PUT "***" to preserve. */
  client_secret: string;
  redirect_uri: string;
  scopes: string;
  group_claim: string;
  username_claim: string;
  email_claim: string;
  create_users: boolean;
  force_login: boolean;
  /** Setting keys (e.g. "oidc_issuer") locked by an env var. */
  locked: string[];
}

export type OidcConfigUpdate = Partial<Omit<OidcConfig, 'locked'>>;

export interface GroupMapping {
  id: string;
  group_name: string;
  role_id: string;
  role_name: string;
  scope: string;
  created_at: string;
}

export interface CreateGroupMapping {
  group_name: string;
  role_id: string;
  scope: string;
}

export const oidcApi = {
  status: () => api.get<OidcStatus>('/api/auth/oidc'),
  start: (returnTo?: string) =>
    api.get<OidcStartResponse>(
      `/api/auth/oidc/start${returnTo ? `?return_to=${encodeURIComponent(returnTo)}` : ''}`,
    ),

  getConfig: () => api.get<OidcConfig>('/api/oidc/config'),
  putConfig: (req: OidcConfigUpdate) => api.put<{ ok: true }>('/api/oidc/config', req),

  listMappings: () => api.get<GroupMapping[]>('/api/oidc/group-mappings'),
  createMapping: (req: CreateGroupMapping) =>
    api.post<GroupMapping>('/api/oidc/group-mappings', req),
  deleteMapping: (id: string) =>
    api.delete<{ ok: true }>(`/api/oidc/group-mappings/${id}`),
};
