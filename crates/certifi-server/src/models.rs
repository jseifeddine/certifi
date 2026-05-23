use serde::{Deserialize, Serialize};

// Re-export wire types from the shared crate so handlers can keep importing
// from `crate::models::*` without caring where each type physically lives.
pub use certifi_types::{CertificateView, IssueCertRequest, IssueCertResponse};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_admin: bool,
    pub email: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ApiToken {
    pub id: String,
    pub user_id: String,
    pub name: String,
    // Verified by the auth layer's own query, not read off this struct — kept
    // here so `ApiToken` faithfully mirrors the row shape.
    #[serde(skip_serializing)]
    #[allow(dead_code)]
    pub token_hash: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    /// JSON-encoded `Vec<String>` of permission keys when the token is
    /// scoped, otherwise `NULL` (token inherits the issuer's perms).
    pub permissions: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Certificate {
    pub id: String,
    pub common_name: String,
    pub sans: String,
    pub status: String,
    pub auto_renew: bool,
    /// Per-certificate key algorithm override. NULL means "use global setting".
    /// Resolved and written to the DB when issuance starts.
    pub key_algo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fullchain_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privkey_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    /// AES-256-GCM ciphertext of the PFX password. Decrypted on demand by the
    /// `pem`/`pfx` handlers using the app's `COOKIE_KEY`.
    #[serde(skip_serializing)]
    pub pfx_password_enc: Option<String>,
    /// Free-text description set by the operator. Not used by issuance logic.
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub error: Option<String>,
}

impl From<Certificate> for CertificateView {
    fn from(c: Certificate) -> Self {
        let has_files = c.fullchain_pem.is_some();
        Self {
            has_files,
            auto_renew: c.auto_renew,
            key_algo: c.key_algo,
            description: c.description,
            id: c.id,
            common_name: c.common_name,
            sans: serde_json::from_str(&c.sans).unwrap_or_default(),
            status: c.status,
            created_at: c.created_at,
            updated_at: c.updated_at,
            expires_at: c.expires_at,
            error: c.error,
        }
    }
}

/// Valid key algorithm identifiers accepted by the API and `generate_csr`.
pub const VALID_KEY_ALGOS: &[&str] = &["ec-p256", "ec-p384", "rsa-2048", "rsa-4096"];

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Setting {
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

// ── Setting keys ──────────────────────────────────────────────────────────────

// ACME
pub const S_ACME_CA: &str = "acme_ca";
pub const S_ACME_ACCOUNT_KEY: &str = "acme_account_key"; // base64 PKCS8 DER
pub const S_ACME_ACCOUNT_URL: &str = "acme_account_url";
pub const S_KEY_ALGO: &str = "key_algo"; // ec-p384, ec-p256

// DNS integration config now lives in the `integrations` table — see the
// integrations module for the per-kind config keys (cf_api_token, pdns_url,
// etc.). Nothing in `settings` references them anymore.

// Well-known CA URLs
pub const ACME_LE_PROD: &str = "https://acme-v02.api.letsencrypt.org/directory";
#[allow(dead_code)] // reference constant for operators pointing at LE staging
pub const ACME_LE_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";

// OIDC SSO setting keys. Defaults match what most IdPs (Authentik, Keycloak,
// Google, Azure AD with the right scope) emit.
pub const S_OIDC_ENABLED: &str = "oidc_enabled";
pub const S_OIDC_ISSUER: &str = "oidc_issuer";
pub const S_OIDC_CLIENT_ID: &str = "oidc_client_id";
pub const S_OIDC_CLIENT_SECRET: &str = "oidc_client_secret";
pub const S_OIDC_REDIRECT_URI: &str = "oidc_redirect_uri";
pub const S_OIDC_SCOPES: &str = "oidc_scopes";
pub const S_OIDC_GROUP_CLAIM: &str = "oidc_group_claim";
pub const S_OIDC_USERNAME_CLAIM: &str = "oidc_username_claim";
pub const S_OIDC_EMAIL_CLAIM: &str = "oidc_email_claim";
pub const S_OIDC_CREATE_USERS: &str = "oidc_create_users";
/// When 'true', /login skips the local form and bounces straight to the IdP.
/// `/login?local=1` overrides for one visit so admins aren't locked out when
/// SSO breaks.
pub const S_OIDC_FORCE_LOGIN: &str = "oidc_force_login";

pub const OIDC_DEFAULT_SCOPES: &str = "openid,email,profile,groups";
pub const OIDC_DEFAULT_GROUP_CLAIM: &str = "groups";
pub const OIDC_DEFAULT_USERNAME_CLAIM: &str = "preferred_username";
pub const OIDC_DEFAULT_EMAIL_CLAIM: &str = "email";
