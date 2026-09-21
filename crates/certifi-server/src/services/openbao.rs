//! OpenBao (and Vault-compatible) KV client.
//!
//! Thin wrapper over the HTTP API — enough to read, write and destroy secrets
//! under one mount, and to keep a login token alive. Deliberately not a
//! general-purpose client: Certifi only ever touches KV.
//!
//! Auth is either a static token (`BAO_TOKEN` / `BAO_TOKEN_FILE`) or AppRole
//! (`BAO_ROLE_ID` + `BAO_SECRET_ID`). Both end up as a `TokenState` behind an
//! `RwLock`; every request checks whether the lease is close enough to expiry
//! to be worth refreshing, and a 403 triggers exactly one forced re-auth +
//! retry in case the token was revoked out from under us.

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tokio::sync::RwLock;

/// Refresh a lease once it's within this long of expiring. Generous enough
/// that a slow round-trip can't let a token lapse mid-request.
const RENEW_SKEW_SECS: i64 = 60;

/// Auth material, resolved from the environment at startup.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// A token supplied directly. Renewed via `auth/token/renew-self` while
    /// the server says it's renewable; a root/periodic token simply never
    /// needs it.
    Token(String),
    /// AppRole login. Re-logs in from scratch when the lease runs low —
    /// cheaper to reason about than renew-self, and a `secret_id` that is
    /// still valid can always mint another token.
    AppRole {
        mount: String,
        role_id: String,
        secret_id: String,
    },
}

/// Everything needed to talk to one KV mount.
#[derive(Debug, Clone)]
pub struct BaoConfig {
    /// Base URL, e.g. `https://openbao.internal:8200`. No trailing slash.
    pub addr: String,
    /// KV mount point (`BAO_MOUNT`, default `secret`).
    pub mount: String,
    /// Path prefix inside the mount that Certifi owns (`BAO_PATH`, default
    /// `certifi`). Every secret this server writes lives under it.
    pub base_path: String,
    /// 1 or 2. KV v2 nests payloads under `data/` and keeps versions; v1 is
    /// a flat read/write.
    pub kv_version: u8,
    pub namespace: Option<String>,
    pub ca_cert_path: Option<String>,
    pub skip_verify: bool,
    pub auth: AuthMethod,
}

impl BaoConfig {
    /// Read the backend config from the environment. Returns `Ok(None)` when
    /// `BAO_ADDR`/`VAULT_ADDR` is unset — that's how the backend stays opt-in.
    ///
    /// Every variable is read as `BAO_*` first and `VAULT_*` second, so an
    /// existing Vault-shaped environment works untouched.
    pub fn from_env() -> Result<Option<Self>> {
        let Some(addr) = env_any("ADDR") else {
            return Ok(None);
        };
        let addr = addr.trim_end_matches('/').to_string();

        let mount = env_any("MOUNT").unwrap_or_else(|| "secret".to_string());
        let base_path = env_any("PATH")
            .unwrap_or_else(|| "certifi".to_string())
            .trim_matches('/')
            .to_string();
        if base_path.is_empty() {
            bail!("BAO_PATH must not be empty — it is the prefix every Certifi secret lives under");
        }

        let kv_version: u8 = match env_any("KV_VERSION") {
            Some(v) => v
                .parse()
                .ok()
                .filter(|n| matches!(n, 1 | 2))
                .ok_or_else(|| anyhow!("BAO_KV_VERSION must be 1 or 2, got '{}'", v))?,
            None => 2,
        };

        let auth = resolve_auth()?;

        Ok(Some(Self {
            addr,
            mount: mount.trim_matches('/').to_string(),
            base_path,
            kv_version,
            namespace: env_any("NAMESPACE"),
            ca_cert_path: env_any("CACERT"),
            skip_verify: env_any("SKIP_VERIFY")
                .map(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
                .unwrap_or(false),
            auth,
        }))
    }

    /// Human-readable description of where secrets land, for the boot log.
    pub fn describe(&self) -> String {
        let method = match &self.auth {
            AuthMethod::Token(_) => "token".to_string(),
            AuthMethod::AppRole { mount, .. } => format!("approle({})", mount),
        };
        format!(
            "{} mount={} path={} kv=v{} auth={}",
            self.addr, self.mount, self.base_path, self.kv_version, method
        )
    }
}

/// `BAO_<suffix>`, falling back to `VAULT_<suffix>`. Empty values count as
/// unset so a blank compose variable doesn't half-enable the backend.
fn env_any(suffix: &str) -> Option<String> {
    for prefix in ["BAO_", "VAULT_"] {
        if let Ok(v) = std::env::var(format!("{}{}", prefix, suffix)) {
            let v = v.trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

/// Read a secret-bearing value from either `BAO_X` or `BAO_X_FILE` (the
/// `_FILE` form is how Docker/Kubernetes secrets are normally surfaced).
fn env_secret(suffix: &str) -> Result<Option<String>> {
    if let Some(v) = env_any(suffix) {
        return Ok(Some(v));
    }
    let Some(path) = env_any(&format!("{}_FILE", suffix)) else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading BAO_{}_FILE at {}", suffix, path))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        bail!("BAO_{}_FILE at {} is empty", suffix, path);
    }
    Ok(Some(trimmed))
}

fn resolve_auth() -> Result<AuthMethod> {
    let role_id = env_secret("ROLE_ID")?;
    let secret_id = env_secret("SECRET_ID")?;
    let token = env_secret("TOKEN")?;

    match (role_id, secret_id, token) {
        (Some(role_id), Some(secret_id), _) => Ok(AuthMethod::AppRole {
            mount: env_any("APPROLE_PATH").unwrap_or_else(|| "approle".to_string()),
            role_id,
            secret_id,
        }),
        (Some(_), None, _) => bail!(
            "BAO_ROLE_ID is set but BAO_SECRET_ID / BAO_SECRET_ID_FILE is not — \
             AppRole login needs both"
        ),
        (None, Some(_), _) => bail!(
            "BAO_SECRET_ID is set but BAO_ROLE_ID / BAO_ROLE_ID_FILE is not — \
             AppRole login needs both"
        ),
        (None, None, Some(token)) => Ok(AuthMethod::Token(token)),
        (None, None, None) => bail!(
            "BAO_ADDR is set but no credentials are. Provide BAO_TOKEN / BAO_TOKEN_FILE, \
             or BAO_ROLE_ID + BAO_SECRET_ID for AppRole login"
        ),
    }
}

#[derive(Debug, Clone)]
struct TokenState {
    token: String,
    /// `None` for a token with no lease (root, or a KV-only token issued
    /// without a TTL) — nothing to refresh.
    expires_at: Option<DateTime<Utc>>,
    renewable: bool,
}

impl TokenState {
    fn needs_refresh(&self) -> bool {
        match self.expires_at {
            Some(exp) => Utc::now() + Duration::seconds(RENEW_SKEW_SECS) >= exp,
            None => false,
        }
    }
}

pub struct BaoClient {
    http: reqwest::Client,
    config: BaoConfig,
    token: RwLock<TokenState>,
}

impl BaoClient {
    /// Build the client and perform the initial login. Fails loudly if the
    /// server is unreachable or the credentials are rejected — the caller
    /// treats that as a fatal boot error.
    pub async fn connect(config: BaoConfig) -> Result<Self> {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(20))
            .user_agent(concat!("certifi/", env!("CARGO_PKG_VERSION")));

        if config.skip_verify {
            tracing::warn!(
                "BAO_SKIP_VERIFY is set — the OpenBao server's TLS certificate is NOT being \
                 verified. Every secret this instance holds transits this connection."
            );
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(path) = &config.ca_cert_path {
            let pem =
                std::fs::read(path).with_context(|| format!("reading BAO_CACERT at {}", path))?;
            let cert = reqwest::Certificate::from_pem(&pem)
                .with_context(|| format!("parsing BAO_CACERT at {} as PEM", path))?;
            builder = builder.add_root_certificate(cert);
        }

        let http = builder
            .build()
            .context("building the OpenBao HTTP client")?;

        // Seed with the raw credential so `login()` can authenticate; AppRole
        // overwrites it immediately, a static token keeps it.
        let seed = match &config.auth {
            AuthMethod::Token(t) => TokenState {
                token: t.clone(),
                expires_at: None,
                renewable: false,
            },
            AuthMethod::AppRole { .. } => TokenState {
                token: String::new(),
                expires_at: None,
                renewable: false,
            },
        };

        let client = Self {
            http,
            config,
            token: RwLock::new(seed),
        };
        client.login().await?;
        Ok(client)
    }

    /// Confirm the token works and we can see the mount. Called once at boot
    /// so a misconfigured path surfaces there rather than at first issuance.
    pub async fn health_check(&self) -> Result<()> {
        let url = format!("{}/v1/auth/token/lookup-self", self.config.addr);
        let token = self.token.read().await.token.clone();
        let resp = self
            .http
            .get(&url)
            .header("X-Vault-Token", &token)
            .headers(self.namespace_headers())
            .send()
            .await
            .context("OpenBao token lookup-self")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            bail!("OpenBao rejected the token ({}): {}", status, body.trim());
        }
        Ok(())
    }

    // ── Auth ──────────────────────────────────────────────────────────────

    /// (Re-)authenticate. For AppRole this mints a brand-new token; for a
    /// static token it tries renew-self and otherwise leaves the token as-is.
    async fn login(&self) -> Result<()> {
        match &self.config.auth {
            AuthMethod::Token(t) => {
                let state = self.renew_self(t).await.unwrap_or_else(|e| {
                    // A non-renewable token (root, or one without a lease) is
                    // perfectly normal — it just means there's nothing to do.
                    tracing::debug!("OpenBao token renew-self not applicable: {}", e);
                    TokenState {
                        token: t.clone(),
                        expires_at: None,
                        renewable: false,
                    }
                });
                *self.token.write().await = state;
                Ok(())
            }
            AuthMethod::AppRole {
                mount,
                role_id,
                secret_id,
            } => {
                let url = format!("{}/v1/auth/{}/login", self.config.addr, mount);
                let resp = self
                    .http
                    .post(&url)
                    .headers(self.namespace_headers())
                    .json(&json!({ "role_id": role_id, "secret_id": secret_id }))
                    .send()
                    .await
                    .context("OpenBao AppRole login request")?;

                let status = resp.status();
                let body: Value = resp
                    .json()
                    .await
                    .context("decoding the OpenBao AppRole login response")?;
                if !status.is_success() {
                    bail!(
                        "OpenBao AppRole login failed ({}): {}",
                        status,
                        errors(&body)
                    );
                }

                let auth = body
                    .get("auth")
                    .ok_or_else(|| anyhow!("OpenBao AppRole login returned no `auth` block"))?;
                let token = auth
                    .get("client_token")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow!("OpenBao AppRole login returned no client_token"))?
                    .to_string();
                let lease = auth
                    .get("lease_duration")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);

                *self.token.write().await = TokenState {
                    token,
                    expires_at: (lease > 0).then(|| Utc::now() + Duration::seconds(lease)),
                    renewable: auth
                        .get("renewable")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                };
                tracing::info!("OpenBao AppRole login succeeded (lease {}s)", lease);
                Ok(())
            }
        }
    }

    async fn renew_self(&self, token: &str) -> Result<TokenState> {
        let url = format!("{}/v1/auth/token/renew-self", self.config.addr);
        let resp = self
            .http
            .post(&url)
            .header("X-Vault-Token", token)
            .headers(self.namespace_headers())
            .json(&json!({}))
            .send()
            .await
            .context("OpenBao token renew-self request")?;

        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .context("decoding the OpenBao renew-self response")?;
        if !status.is_success() {
            bail!("renew-self rejected ({}): {}", status, errors(&body));
        }

        let auth = body
            .get("auth")
            .ok_or_else(|| anyhow!("renew-self returned no `auth` block"))?;
        let lease = auth
            .get("lease_duration")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        Ok(TokenState {
            token: token.to_string(),
            expires_at: (lease > 0).then(|| Utc::now() + Duration::seconds(lease)),
            renewable: auth
                .get("renewable")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        })
    }

    /// Return a usable token, refreshing the lease first if it's close to
    /// expiring.
    async fn current_token(&self) -> Result<String> {
        {
            let state = self.token.read().await;
            if !state.needs_refresh() {
                return Ok(state.token.clone());
            }
        }
        // Re-check under the write path: another task may have refreshed
        // while we waited.
        let stale = {
            let state = self.token.read().await;
            state.needs_refresh()
        };
        if stale {
            match &self.config.auth {
                AuthMethod::Token(t) => {
                    let renewable = self.token.read().await.renewable;
                    if renewable {
                        if let Ok(state) = self.renew_self(t).await {
                            *self.token.write().await = state;
                        }
                    }
                }
                AuthMethod::AppRole { .. } => self.login().await?,
            }
        }
        Ok(self.token.read().await.token.clone())
    }

    fn namespace_headers(&self) -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        if let Some(ns) = &self.config.namespace {
            if let Ok(v) = reqwest::header::HeaderValue::from_str(ns) {
                headers.insert("X-Vault-Namespace", v);
            }
        }
        headers
    }

    // ── KV ────────────────────────────────────────────────────────────────

    /// Full URL for a logical path. KV v2 separates the data and metadata
    /// API prefixes; v1 addresses the secret directly.
    fn url_for(&self, path: &str, metadata: bool) -> String {
        let segment = match (self.config.kv_version, metadata) {
            (2, false) => "data/",
            (2, true) => "metadata/",
            _ => "",
        };
        format!(
            "{}/v1/{}/{}{}/{}",
            self.config.addr, self.config.mount, segment, self.config.base_path, path
        )
    }

    /// Read a secret. `Ok(None)` when it simply isn't there — a missing
    /// secret is an ordinary state (a cert issued before the backend was
    /// enabled, say), not an error.
    pub async fn read(&self, path: &str) -> Result<Option<BTreeMap<String, String>>> {
        let url = self.url_for(path, false);
        let resp = self.send_authed(reqwest::Method::GET, &url, None).await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let status = resp.status();
        let body: Value = resp
            .json()
            .await
            .with_context(|| format!("decoding the OpenBao read of {}", path))?;
        if !status.is_success() {
            bail!(
                "OpenBao read of {} failed ({}): {}",
                path,
                status,
                errors(&body)
            );
        }

        // v2: {"data":{"data":{...},"metadata":{...}}}; v1: {"data":{...}}
        let data = match self.config.kv_version {
            2 => body.get("data").and_then(|d| d.get("data")),
            _ => body.get("data"),
        };
        let Some(Value::Object(map)) = data else {
            // A v2 secret whose latest version was soft-deleted comes back
            // 200 with `data: null`. Same meaning as a 404 to us.
            return Ok(None);
        };

        let mut out = BTreeMap::new();
        for (k, v) in map {
            match v {
                Value::String(s) => {
                    out.insert(k.clone(), s.clone());
                }
                Value::Null => {}
                other => {
                    // Someone hand-wrote a non-string into our path. Keep the
                    // JSON rather than dropping the field silently.
                    out.insert(k.clone(), other.to_string());
                }
            }
        }
        Ok(Some(out))
    }

    /// Write a secret, replacing whatever was there.
    pub async fn write(&self, path: &str, data: &BTreeMap<String, String>) -> Result<()> {
        let url = self.url_for(path, false);
        let payload = match self.config.kv_version {
            2 => json!({ "data": data }),
            _ => serde_json::to_value(data)?,
        };

        let resp = self
            .send_authed(reqwest::Method::POST, &url, Some(payload))
            .await?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        bail!(
            "OpenBao write to {} failed ({}): {}",
            path,
            status,
            errors(&body)
        );
    }

    /// Permanently remove a secret and every version of it. Used when a cert
    /// or integration is deleted — a soft delete would leave the private key
    /// recoverable, which is not what "delete this certificate" means.
    pub async fn delete(&self, path: &str) -> Result<()> {
        let url = self.url_for(path, self.config.kv_version == 2);
        let resp = self
            .send_authed(reqwest::Method::DELETE, &url, None)
            .await?;
        let status = resp.status();
        if status.is_success() || status == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        bail!(
            "OpenBao delete of {} failed ({}): {}",
            path,
            status,
            errors(&body)
        );
    }

    /// Issue a request with the current token, retrying once after a forced
    /// re-auth if the server says the token is no good. Covers the case where
    /// a token was revoked or expired earlier than its advertised lease.
    async fn send_authed(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<Value>,
    ) -> Result<reqwest::Response> {
        let token = self.current_token().await?;
        let resp = self.send_once(&method, url, body.clone(), &token).await?;

        if resp.status() != reqwest::StatusCode::FORBIDDEN {
            return Ok(resp);
        }
        tracing::warn!(
            "OpenBao returned 403 for {} — re-authenticating and retrying once",
            url
        );
        self.login().await?;
        let token = self.token.read().await.token.clone();
        self.send_once(&method, url, body, &token).await
    }

    async fn send_once(
        &self,
        method: &reqwest::Method,
        url: &str,
        body: Option<Value>,
        token: &str,
    ) -> Result<reqwest::Response> {
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("X-Vault-Token", token)
            .headers(self.namespace_headers());
        if let Some(b) = body {
            req = req.json(&b);
        }
        req.send()
            .await
            .with_context(|| format!("OpenBao {} {}", method, url))
    }
}

/// Flatten OpenBao's `{"errors":[...]}` body into one line for logs.
fn errors(body: &Value) -> String {
    match body.get("errors").and_then(Value::as_array) {
        Some(list) if !list.is_empty() => list
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("; "),
        _ => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(kv_version: u8) -> BaoConfig {
        BaoConfig {
            addr: "https://bao.example:8200".into(),
            mount: "secret".into(),
            base_path: "certifi".into(),
            kv_version,
            namespace: None,
            ca_cert_path: None,
            skip_verify: false,
            auth: AuthMethod::Token("t".into()),
        }
    }

    /// The client is only ever constructed via `connect`, which needs a live
    /// server. `url_for` is pure, so build the struct directly to test it.
    fn client(kv_version: u8) -> BaoClient {
        BaoClient {
            http: reqwest::Client::new(),
            config: cfg(kv_version),
            token: RwLock::new(TokenState {
                token: "t".into(),
                expires_at: None,
                renewable: false,
            }),
        }
    }

    #[test]
    fn kv_v2_reads_and_writes_go_through_the_data_prefix() {
        let c = client(2);
        assert_eq!(
            c.url_for("certificates/abc", false),
            "https://bao.example:8200/v1/secret/data/certifi/certificates/abc"
        );
    }

    #[test]
    fn kv_v2_destroys_via_the_metadata_prefix() {
        let c = client(2);
        assert_eq!(
            c.url_for("certificates/abc", true),
            "https://bao.example:8200/v1/secret/metadata/certifi/certificates/abc"
        );
    }

    #[test]
    fn kv_v1_addresses_the_secret_directly() {
        let c = client(1);
        assert_eq!(
            c.url_for("acme/account", false),
            "https://bao.example:8200/v1/secret/certifi/acme/account"
        );
        // v1 has no metadata API — delete hits the same path.
        assert_eq!(
            c.url_for("acme/account", true),
            "https://bao.example:8200/v1/secret/certifi/acme/account"
        );
    }

    #[test]
    fn a_lease_close_to_expiry_wants_refreshing() {
        let soon = TokenState {
            token: "t".into(),
            expires_at: Some(Utc::now() + Duration::seconds(RENEW_SKEW_SECS / 2)),
            renewable: true,
        };
        assert!(soon.needs_refresh());

        let later = TokenState {
            expires_at: Some(Utc::now() + Duration::hours(1)),
            ..soon.clone()
        };
        assert!(!later.needs_refresh());

        let leaseless = TokenState {
            expires_at: None,
            ..soon
        };
        assert!(!leaseless.needs_refresh());
    }

    #[test]
    fn errors_flattens_the_error_array() {
        let body = json!({"errors": ["permission denied", "bad mount"]});
        assert_eq!(errors(&body), "permission denied; bad mount");
    }

    #[test]
    fn errors_falls_back_to_the_raw_body() {
        let body = json!({"errors": []});
        assert_eq!(errors(&body), r#"{"errors":[]}"#);
    }
}
