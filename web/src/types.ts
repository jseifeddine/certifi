export interface UserInfo {
  id: string;
  username: string;
  is_admin: boolean;
  /** Effective permission keys (e.g. "certificate.create"). Flat union across
   *  all of the user's role assignments. Use the typed `perms` constants
   *  from `src/lib/perms.ts` rather than hardcoding strings. */
  permissions: string[];
}

// ── RBAC ────────────────────────────────────────────────────────────────────

export interface PermissionView {
  key: string;
  description: string | null;
}

export interface RoleView {
  id: string;
  name: string;
  description: string | null;
  is_system: boolean;
  permissions: string[];
}

export interface RoleAssignmentView {
  id: string;
  role_id: string;
  role_name: string;
  scope: string;
  granted_by: string | null;
  granted_at: string;
}

export interface User {
  id: string;
  username: string;
  is_admin: boolean;
  email: string | null;
  created_at: string;
  updated_at: string;
}

export interface Certificate {
  id: string;
  common_name: string;
  sans: string[];
  status: 'pending' | 'issuing' | 'active' | 'failed' | 'expired';
  auto_renew: boolean;
  key_algo: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
  error: string | null;
  has_files: boolean;
}

export interface CreateCertRequest {
  common_name: string;
  sans?: string[];
  auto_renew?: boolean;
  key_algo?: string | null;
  description?: string | null;
}

export interface Token {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  /** `null` = inherits issuer's perms; `[]`/array = explicit ceiling. */
  permissions: string[] | null;
}

export interface CreatedToken {
  id: string;
  name: string;
  token: string;
  created_at: string;
  expires_at: string | null;
  permissions: string[] | null;
}

export interface PfxResponse {
  pfx_b64: string;
  password: string;
  filename: string;
}

export interface PemBundle {
  fullchain_pem: string | null;
  cert_pem: string | null;
  chain_pem: string | null;
  privkey_pem: string | null;
  pfx_password: string | null;
}

export interface IntegrationField {
  key: string;
  label: string;
  field_type: 'text' | 'password' | 'number';
  required: boolean;
  default: string;
  placeholder: string;
  hint: string;
}

export interface IntegrationMeta {
  id: string;
  name: string;
  fields: IntegrationField[];
}

export interface Settings {
  acme_ca: string;
  acme_registered: boolean;
  acme_account_url: string;
  key_algo: string;
  locked: string[];
}

export type SettingsUpdate = Partial<{
  acme_ca: string;
  key_algo: string;
}>;

// ── DNS integrations (multi) ────────────────────────────────────────────────

export interface Integration {
  id: string;
  kind: string;
  name: string;
  /** Per-integration config map. Secret fields are masked as "***" in list/get. */
  config: Record<string, string>;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateIntegrationRequest {
  kind: string;
  name: string;
  config: Record<string, string>;
  enabled?: boolean;
}

export interface UpdateIntegrationRequest {
  name?: string;
  config?: Record<string, string>;
  enabled?: boolean;
}

export interface IntegrationListResponse {
  integrations: Integration[];
  available_kinds: IntegrationMeta[];
}

export interface IntegrationTestResult {
  ok: boolean;
  provider: string;
  zone_count: number;
  zones: string[];
}
