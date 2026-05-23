use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub listen_addr: String,
    pub cookie_key: Vec<u8>,

    // SMTP (all optional — if smtp_host is None, email is disabled)
    pub smtp_host: Option<String>,
    pub smtp_port: u16,
    pub smtp_from: String,
    pub smtp_username: Option<String>,
    pub smtp_password: Option<String>,

    // Optional env-var overrides for app settings.
    // When set, these values take precedence over the DB and the UI fields are
    // rendered as read-only.  The env var name is shown in the UI hint.
    //
    //   ACME_CA_URL  → acme_ca      (ACME directory URL)
    //   PDNS_URL     → pdns_url     (full URL incl. scheme + optional port)
    //   PDNS_KEY     → pdns_key
    //   PDNS_WAIT    → pdns_wait    (propagation delay seconds)
    //   PDNS_SERVER  → pdns_server  (server ID, optional)
    //
    // Legacy PDNS_HOST / PDNS_PORT are still read on startup and migrated
    // into PDNS_URL — they no longer drive runtime behavior.
    pub env_acme_ca: Option<String>,
    pub env_pdns_url: Option<String>,
    pub env_pdns_key: Option<String>,
    pub env_pdns_wait: Option<String>,
    pub env_pdns_server: Option<String>,

    // OIDC SSO env overrides. When set, the corresponding setting key is
    // locked in the admin UI and the env value wins at runtime.
    //   OIDC_ENABLED        → oidc_enabled        ('true'/'false')
    //   OIDC_ISSUER         → oidc_issuer         (discovery base URL)
    //   OIDC_CLIENT_ID      → oidc_client_id
    //   OIDC_CLIENT_SECRET  → oidc_client_secret
    //   OIDC_REDIRECT_URI   → oidc_redirect_uri   (must match what the IdP has registered)
    //   OIDC_SCOPES         → oidc_scopes         (comma-separated)
    //   OIDC_GROUP_CLAIM    → oidc_group_claim
    //   OIDC_USERNAME_CLAIM → oidc_username_claim
    //   OIDC_EMAIL_CLAIM    → oidc_email_claim
    //   OIDC_CREATE_USERS   → oidc_create_users   ('true'/'false', JIT provisioning)
    pub env_oidc_enabled: Option<String>,
    pub env_oidc_issuer: Option<String>,
    pub env_oidc_client_id: Option<String>,
    pub env_oidc_client_secret: Option<String>,
    pub env_oidc_redirect_uri: Option<String>,
    pub env_oidc_scopes: Option<String>,
    pub env_oidc_group_claim: Option<String>,
    pub env_oidc_username_claim: Option<String>,
    pub env_oidc_email_claim: Option<String>,
    pub env_oidc_create_users: Option<String>,
    pub env_oidc_force_login: Option<String>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let data_dir =
            PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "./data".to_string()));

        let listen_addr =
            std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

        let cookie_key = std::env::var("COOKIE_KEY")
            .map(|k| k.into_bytes())
            .unwrap_or_else(|_| {
                use rand::Rng;
                rand::thread_rng()
                    .sample_iter(rand::distributions::Standard)
                    .take(64)
                    .collect()
            });

        let smtp_host = std::env::var("SMTP_HOST").ok().filter(|s| !s.is_empty());
        let smtp_port: u16 = std::env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(587);
        let smtp_from =
            std::env::var("SMTP_FROM").unwrap_or_else(|_| "certifi@localhost".to_string());
        let smtp_username = std::env::var("SMTP_USERNAME")
            .ok()
            .filter(|s| !s.is_empty());
        let smtp_password = std::env::var("SMTP_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty());

        let env_acme_ca = std::env::var("ACME_CA_URL").ok().filter(|s| !s.is_empty());

        // Prefer PDNS_URL, but synthesize from legacy PDNS_HOST/PDNS_PORT for
        // backward compatibility with existing deployments.
        let env_pdns_url = std::env::var("PDNS_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                let host = std::env::var("PDNS_HOST").ok().filter(|s| !s.is_empty())?;
                let port = std::env::var("PDNS_PORT")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "8081".to_string());
                tracing::warn!(
                    "PDNS_HOST / PDNS_PORT are deprecated — set PDNS_URL=http://{}:{} instead",
                    host,
                    port
                );
                Some(format!("http://{}:{}", host, port))
            });

        let env_pdns_key = std::env::var("PDNS_KEY").ok().filter(|s| !s.is_empty());
        let env_pdns_wait = std::env::var("PDNS_WAIT").ok().filter(|s| !s.is_empty());
        let env_pdns_server = std::env::var("PDNS_SERVER").ok().filter(|s| !s.is_empty());

        let env_oidc_enabled = std::env::var("OIDC_ENABLED").ok().filter(|s| !s.is_empty());
        let env_oidc_issuer = std::env::var("OIDC_ISSUER").ok().filter(|s| !s.is_empty());
        let env_oidc_client_id = std::env::var("OIDC_CLIENT_ID")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_client_secret = std::env::var("OIDC_CLIENT_SECRET")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_redirect_uri = std::env::var("OIDC_REDIRECT_URI")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_scopes = std::env::var("OIDC_SCOPES").ok().filter(|s| !s.is_empty());
        let env_oidc_group_claim = std::env::var("OIDC_GROUP_CLAIM")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_username_claim = std::env::var("OIDC_USERNAME_CLAIM")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_email_claim = std::env::var("OIDC_EMAIL_CLAIM")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_create_users = std::env::var("OIDC_CREATE_USERS")
            .ok()
            .filter(|s| !s.is_empty());
        let env_oidc_force_login = std::env::var("OIDC_FORCE_LOGIN")
            .ok()
            .filter(|s| !s.is_empty());

        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            data_dir,
            listen_addr,
            cookie_key,
            smtp_host,
            smtp_port,
            smtp_from,
            smtp_username,
            smtp_password,
            env_acme_ca,
            env_pdns_url,
            env_pdns_key,
            env_pdns_wait,
            env_pdns_server,
            env_oidc_enabled,
            env_oidc_issuer,
            env_oidc_client_id,
            env_oidc_client_secret,
            env_oidc_redirect_uri,
            env_oidc_scopes,
            env_oidc_group_claim,
            env_oidc_username_claim,
            env_oidc_email_claim,
            env_oidc_create_users,
            env_oidc_force_login,
        })
    }

    pub fn db_path(&self) -> String {
        self.data_dir
            .join("certifi.db")
            .to_string_lossy()
            .to_string()
    }

    pub fn smtp_enabled(&self) -> bool {
        self.smtp_host.is_some()
    }

    /// Returns (setting_key, value) pairs for each env var that was set.
    /// Keys match the DB setting key strings (e.g. "acme_ca", "pdns_url").
    pub fn env_overrides(&self) -> Vec<(&'static str, String)> {
        let mut v: Vec<(&'static str, String)> = Vec::new();
        if let Some(x) = &self.env_acme_ca {
            v.push(("acme_ca", x.clone()));
        }
        if let Some(x) = &self.env_pdns_url {
            v.push(("pdns_url", x.clone()));
        }
        if let Some(x) = &self.env_pdns_key {
            v.push(("pdns_key", x.clone()));
        }
        if let Some(x) = &self.env_pdns_wait {
            v.push(("pdns_wait", x.clone()));
        }
        if let Some(x) = &self.env_pdns_server {
            v.push(("pdns_server", x.clone()));
        }
        if let Some(x) = &self.env_oidc_enabled {
            v.push(("oidc_enabled", x.clone()));
        }
        if let Some(x) = &self.env_oidc_issuer {
            v.push(("oidc_issuer", x.clone()));
        }
        if let Some(x) = &self.env_oidc_client_id {
            v.push(("oidc_client_id", x.clone()));
        }
        if let Some(x) = &self.env_oidc_client_secret {
            v.push(("oidc_client_secret", x.clone()));
        }
        if let Some(x) = &self.env_oidc_redirect_uri {
            v.push(("oidc_redirect_uri", x.clone()));
        }
        if let Some(x) = &self.env_oidc_scopes {
            v.push(("oidc_scopes", x.clone()));
        }
        if let Some(x) = &self.env_oidc_group_claim {
            v.push(("oidc_group_claim", x.clone()));
        }
        if let Some(x) = &self.env_oidc_username_claim {
            v.push(("oidc_username_claim", x.clone()));
        }
        if let Some(x) = &self.env_oidc_email_claim {
            v.push(("oidc_email_claim", x.clone()));
        }
        if let Some(x) = &self.env_oidc_create_users {
            v.push(("oidc_create_users", x.clone()));
        }
        if let Some(x) = &self.env_oidc_force_login {
            v.push(("oidc_force_login", x.clone()));
        }
        v
    }

    /// Returns the setting keys whose values are locked by an environment variable.
    pub fn locked_keys(&self) -> Vec<&'static str> {
        self.env_overrides().into_iter().map(|(k, _)| k).collect()
    }

    /// Merges env-var overrides on top of a DB-loaded settings map.
    /// Env vars always win; DB values are used as fallback.
    pub fn apply_env_overrides(&self, mut map: HashMap<String, String>) -> HashMap<String, String> {
        for (k, v) in self.env_overrides() {
            map.insert(k.to_string(), v);
        }
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Config with everything unset/defaulted. `from_env` is not used here so
    /// the tests don't depend on (or mutate) the process environment.
    fn base() -> Config {
        Config {
            data_dir: PathBuf::from("/var/lib/certifi"),
            listen_addr: "0.0.0.0:8080".to_string(),
            cookie_key: vec![0u8; 64],
            smtp_host: None,
            smtp_port: 587,
            smtp_from: "certifi@localhost".to_string(),
            smtp_username: None,
            smtp_password: None,
            env_acme_ca: None,
            env_pdns_url: None,
            env_pdns_key: None,
            env_pdns_wait: None,
            env_pdns_server: None,
            env_oidc_enabled: None,
            env_oidc_issuer: None,
            env_oidc_client_id: None,
            env_oidc_client_secret: None,
            env_oidc_redirect_uri: None,
            env_oidc_scopes: None,
            env_oidc_group_claim: None,
            env_oidc_username_claim: None,
            env_oidc_email_claim: None,
            env_oidc_create_users: None,
            env_oidc_force_login: None,
        }
    }

    #[test]
    fn db_path_is_under_the_data_dir() {
        let c = base();
        assert_eq!(c.db_path(), "/var/lib/certifi/certifi.db");
    }

    #[test]
    fn smtp_enabled_tracks_the_host() {
        assert!(!base().smtp_enabled());
        let mut c = base();
        c.smtp_host = Some("smtp.example.com".to_string());
        assert!(c.smtp_enabled());
    }

    #[test]
    fn env_overrides_lists_only_set_keys() {
        let mut c = base();
        c.env_acme_ca = Some("https://acme.example/dir".to_string());
        c.env_oidc_enabled = Some("true".to_string());
        let keys: Vec<&str> = c.env_overrides().into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["acme_ca", "oidc_enabled"]);
    }

    #[test]
    fn locked_keys_matches_env_overrides() {
        let mut c = base();
        c.env_pdns_url = Some("http://pdns:8081".to_string());
        c.env_pdns_key = Some("secret".to_string());
        assert_eq!(c.locked_keys(), vec!["pdns_url", "pdns_key"]);
    }

    #[test]
    fn apply_env_overrides_lets_env_win_but_keeps_db_only_keys() {
        let mut c = base();
        c.env_pdns_url = Some("http://env-pdns:8081".to_string());

        let mut db = HashMap::new();
        db.insert("pdns_url".to_string(), "http://db-pdns:8081".to_string());
        db.insert("acme_ca".to_string(), "https://db-acme/dir".to_string());

        let merged = c.apply_env_overrides(db);
        // Env value overrides the DB value for the same key …
        assert_eq!(merged.get("pdns_url").unwrap(), "http://env-pdns:8081");
        // … but DB-only keys with no env override survive untouched.
        assert_eq!(merged.get("acme_ca").unwrap(), "https://db-acme/dir");
    }
}
