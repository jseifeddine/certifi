//! First-boot provisioning from a YAML file.
//!
//! When `CERTIFI_PROVISIONING_FILE` points at a readable YAML document
//! AND the database has never been provisioned (no `provisioned_at`
//! setting), this module reads the file and seeds:
//!
//!   * ACME settings (CA URL, key algo)
//!   * OIDC provider settings (issuer, client_id, client_secret, claims,
//!     create_users, force_login)
//!   * OIDC group → role mappings
//!   * DNS integrations (CRUD-equivalent inserts)
//!
//! Secrets (OIDC client secret, integration API tokens) live verbatim in
//! the file — operator manages file permissions (chmod 600, root:certifi
//! or similar). No env-var substitution by design: one source of truth.
//!
//! A `provisioned_at` setting is written on success so subsequent restarts
//! skip the file. To re-apply: `DELETE FROM settings WHERE key =
//! 'provisioned_at'`. We deliberately do NOT do continuous reconciliation —
//! after first boot, operators manage state via the API/UI.
//!
//! Failure mode: hard error on a malformed file. A silent skip would mask
//! deployment misconfiguration.

use crate::integrations::{available_integrations, build_single_provider};
use crate::models::*;
use crate::rbac::system_roles;
use crate::services::secret;
use crate::AppState;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::Deserialize;
use sqlx::SqlitePool;
use std::collections::BTreeMap;
use uuid::Uuid;

const SENTINEL_KEY: &str = "provisioned_at";

#[derive(Debug, Deserialize)]
struct ProvisioningFile {
    #[serde(default)]
    acme: Option<AcmeBlock>,
    #[serde(default)]
    oidc: Option<OidcBlock>,
    #[serde(default)]
    integrations: Vec<IntegrationBlock>,
}

#[derive(Debug, Deserialize)]
struct AcmeBlock {
    #[serde(default)]
    ca_url: Option<String>,
    #[serde(default)]
    key_algo: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OidcBlock {
    #[serde(default)]
    enabled: Option<bool>,
    issuer: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    group_claim: Option<String>,
    #[serde(default)]
    username_claim: Option<String>,
    #[serde(default)]
    email_claim: Option<String>,
    #[serde(default)]
    create_users: Option<bool>,
    #[serde(default)]
    force_login: Option<bool>,
    #[serde(default)]
    group_mappings: Vec<GroupMappingBlock>,
}

#[derive(Debug, Deserialize)]
struct GroupMappingBlock {
    group: String,
    /// One of: "SuperAdmin", "Operator", "Viewer", or a raw role id
    /// ("system:super_admin"). Friendly names are case-insensitive.
    role: String,
    #[serde(default = "default_scope")]
    scope: String,
}

fn default_scope() -> String {
    "global".to_string()
}

#[derive(Debug, Deserialize)]
struct IntegrationBlock {
    name: String,
    kind: String,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default)]
    config: BTreeMap<String, String>,
}

fn default_enabled() -> bool {
    true
}

/// Read `CERTIFI_PROVISIONING_FILE`, validate, and apply if appropriate.
/// Returns true if a file was applied; false if no file is configured or
/// the sentinel already exists. Errors abort startup — better than a
/// silently half-configured instance.
pub async fn apply_if_present(state: &AppState) -> Result<bool> {
    let Some(path) = std::env::var("CERTIFI_PROVISIONING_FILE")
        .ok()
        .filter(|s| !s.is_empty())
    else {
        tracing::debug!("provisioning: CERTIFI_PROVISIONING_FILE not set, skipping");
        return Ok(false);
    };

    // Already-provisioned sentinel — read once, refuse to re-apply.
    if sentinel_present(&state.db).await? {
        tracing::info!(
            "provisioning: {} present but {} sentinel already set — skipping",
            path,
            SENTINEL_KEY
        );
        return Ok(false);
    }

    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading provisioning file {}", path))?;
    let doc: ProvisioningFile = serde_yaml::from_str(&raw)
        .with_context(|| format!("parsing provisioning file {}", path))?;

    let mut applied = ApplySummary::default();
    let now = Utc::now().to_rfc3339();

    if let Some(acme) = doc.acme {
        applied.acme = apply_acme(&state.db, &acme, &now).await?;
    }
    if let Some(oidc) = doc.oidc {
        let (settings_n, mappings_n) = apply_oidc(state, &oidc, &now).await?;
        applied.oidc_settings = settings_n;
        applied.oidc_mappings = mappings_n;
    }
    for integ in &doc.integrations {
        apply_integration(&state.db, integ, &now)
            .await
            .with_context(|| format!("provisioning integration '{}'", integ.name))?;
        applied.integrations += 1;
    }

    write_sentinel(&state.db, &now).await?;
    tracing::info!(
        "provisioning: applied {} from {} (acme={}, oidc_settings={}, oidc_mappings={}, integrations={})",
        if applied.is_empty() { "nothing" } else { "config" },
        path,
        applied.acme,
        applied.oidc_settings,
        applied.oidc_mappings,
        applied.integrations,
    );
    Ok(true)
}

#[derive(Default, Debug)]
struct ApplySummary {
    acme: usize,
    oidc_settings: usize,
    oidc_mappings: usize,
    integrations: usize,
}

impl ApplySummary {
    fn is_empty(&self) -> bool {
        self.acme == 0
            && self.oidc_settings == 0
            && self.oidc_mappings == 0
            && self.integrations == 0
    }
}

async fn sentinel_present(db: &SqlitePool) -> Result<bool> {
    let row: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
        .bind(SENTINEL_KEY)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

async fn write_sentinel(db: &SqlitePool, now: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
    )
    .bind(SENTINEL_KEY)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

async fn apply_acme(db: &SqlitePool, acme: &AcmeBlock, now: &str) -> Result<usize> {
    let mut n = 0;
    if let Some(ca) = &acme.ca_url {
        upsert_setting(db, S_ACME_CA, ca, now).await?;
        n += 1;
    }
    if let Some(algo) = &acme.key_algo {
        upsert_setting(db, S_KEY_ALGO, algo, now).await?;
        n += 1;
    }
    Ok(n)
}

async fn apply_oidc(state: &AppState, oidc: &OidcBlock, now: &str) -> Result<(usize, usize)> {
    let db = &state.db;
    let mut n = 0usize;

    let pairs: &[(&str, String)] = &[
        (S_OIDC_ENABLED, bool_str(oidc.enabled.unwrap_or(true))),
        (S_OIDC_ISSUER, oidc.issuer.clone()),
        (S_OIDC_CLIENT_ID, oidc.client_id.clone()),
        // Encrypt with COOKIE_KEY so the at-rest format matches what the
        // UI write path produces — a later admin edit will round-trip.
        (
            S_OIDC_CLIENT_SECRET,
            secret::encrypt(&oidc.client_secret, &state.config.cookie_key)
                .context("encrypting OIDC client_secret")?,
        ),
        (S_OIDC_REDIRECT_URI, oidc.redirect_uri.clone()),
        (S_OIDC_SCOPES, oidc.scopes.join(",")),
    ];
    for (k, v) in pairs {
        upsert_setting(db, k, v, now).await?;
        n += 1;
    }

    if let Some(c) = &oidc.group_claim {
        upsert_setting(db, S_OIDC_GROUP_CLAIM, c, now).await?;
        n += 1;
    }
    if let Some(c) = &oidc.username_claim {
        upsert_setting(db, S_OIDC_USERNAME_CLAIM, c, now).await?;
        n += 1;
    }
    if let Some(c) = &oidc.email_claim {
        upsert_setting(db, S_OIDC_EMAIL_CLAIM, c, now).await?;
        n += 1;
    }
    if let Some(b) = oidc.create_users {
        upsert_setting(db, S_OIDC_CREATE_USERS, &bool_str(b), now).await?;
        n += 1;
    }
    if let Some(b) = oidc.force_login {
        upsert_setting(db, S_OIDC_FORCE_LOGIN, &bool_str(b), now).await?;
        n += 1;
    }

    let mut mappings = 0usize;
    for m in &oidc.group_mappings {
        let role_id = resolve_role_id(&m.role)?;
        // Validate the role exists in the seeded RBAC table.
        let exists: Option<(String,)> = sqlx::query_as("SELECT id FROM roles WHERE id = ?")
            .bind(&role_id)
            .fetch_optional(db)
            .await?;
        if exists.is_none() {
            return Err(anyhow!(
                "provisioning oidc.group_mappings: unknown role '{}' (resolved to id '{}')",
                m.role,
                role_id
            ));
        }
        sqlx::query(
            "INSERT OR IGNORE INTO oidc_group_mappings (id, group_name, role_id, scope, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&m.group)
        .bind(&role_id)
        .bind(&m.scope)
        .bind(now)
        .execute(db)
        .await?;
        mappings += 1;
    }

    Ok((n, mappings))
}

fn resolve_role_id(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("group mapping role cannot be empty"));
    }
    // Friendly aliases — case-insensitive.
    let id = match trimmed.to_ascii_lowercase().as_str() {
        "superadmin" | "super_admin" | "admin" => system_roles::SUPER_ADMIN.to_string(),
        "operator" => system_roles::OPERATOR.to_string(),
        "viewer" => system_roles::VIEWER.to_string(),
        // Fall through — treat as a raw role id (allows custom roles seeded
        // elsewhere, though the validation below will reject unknowns).
        _ => trimmed.to_string(),
    };
    Ok(id)
}

async fn apply_integration(db: &SqlitePool, integ: &IntegrationBlock, now: &str) -> Result<()> {
    let kind = integ.kind.trim();
    if kind.is_empty() || integ.name.trim().is_empty() {
        return Err(anyhow!("integration name and kind are required"));
    }
    if !available_integrations().iter().any(|k| k.id == kind) {
        let known: Vec<&str> = available_integrations().iter().map(|k| k.id).collect();
        return Err(anyhow!(
            "unknown integration kind '{}'. Known kinds: {}",
            kind,
            known.join(", ")
        ));
    }

    // Validate the config before persisting — same path the HTTP create
    // handler takes. Catches missing required fields / malformed URLs early.
    build_single_provider(kind, &integ.config).map_err(|e| anyhow!("config rejected: {:#}", e))?;

    let config_json = serde_json::to_string(&integ.config).unwrap_or_else(|_| "{}".into());
    sqlx::query(
        "INSERT INTO integrations (id, kind, name, config, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(kind)
    .bind(&integ.name)
    .bind(&config_json)
    .bind(integ.enabled)
    .bind(now)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

async fn upsert_setting(db: &SqlitePool, key: &str, value: &str, now: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
    )
    .bind(key)
    .bind(value)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

fn bool_str(b: bool) -> String {
    if b {
        "true".into()
    } else {
        "false".into()
    }
}
