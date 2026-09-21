//! Where Certifi's secret material lives.
//!
//! Two backends:
//!
//! * **Database** (default) — PEMs in the `certificates` columns, the ACME
//!   account key in `settings`, DNS credentials in `integrations.config`.
//!   Exactly what Certifi has always done.
//! * **OpenBao** — the same material in a KV mount; the DB columns hold a
//!   reference instead.
//!
//! A row says for itself where its secret lives: a column whose value starts
//! with [`REF_PREFIX`] is a pointer, anything else is the value. That keeps a
//! partially-migrated database coherent, and means a single read path works
//! for both backends without a global mode flag being consulted everywhere.
//!
//! Callers never touch the columns directly — they go through this facade, so
//! adding a third backend later is a matter of another match arm.

use crate::integrations::IntegrationRow;
use crate::models::{Certificate, S_ACME_ACCOUNT_KEY};
use crate::services::acme::IssuedCert;
use crate::services::openbao::{BaoClient, BaoConfig};
use crate::services::secret;
use anyhow::{Context, Result};
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Marks a DB value as a pointer into the external backend rather than the
/// secret itself. The suffix is the logical path inside the configured mount
/// and base path — e.g. `openbao:certificates/9f2c…`.
pub const REF_PREFIX: &str = "openbao:";

/// Field names inside a `certificates/<id>` secret.
const F_FULLCHAIN: &str = "fullchain_pem";
const F_CERT: &str = "cert_pem";
const F_CHAIN: &str = "chain_pem";
const F_PRIVKEY: &str = "privkey_pem";
const F_PFX_PASSWORD: &str = "pfx_password";
/// Field name inside the `acme/account` secret.
const F_ACME_KEY: &str = "key_pkcs8_b64";

/// If `value` is a reference, the path it points at.
fn as_ref_path(value: &str) -> Option<&str> {
    value.strip_prefix(REF_PREFIX)
}

fn cert_path(id: &str) -> String {
    format!("certificates/{}", id)
}

fn integration_path(id: &str) -> String {
    format!("integrations/{}", id)
}

const ACME_PATH: &str = "acme/account";

/// Everything secret about one certificate.
///
/// The PFX password is plaintext here. In DB mode it is AES-GCM-encrypted
/// under `COOKIE_KEY` on the way to the column; in OpenBao mode the backend
/// provides encryption at rest and a second layer would only add a way to
/// lose the value when `COOKIE_KEY` rotates.
#[derive(Debug, Clone, Default)]
pub struct CertMaterial {
    pub fullchain_pem: Option<String>,
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub privkey_pem: Option<String>,
    pub pfx_password: Option<String>,
}

#[derive(Clone)]
enum Backend {
    Database,
    OpenBao(Arc<BaoClient>),
}

#[derive(Clone)]
pub struct SecretStore {
    backend: Backend,
    /// Kept for the DB backend's PFX password encryption. Unused when the
    /// OpenBao backend is active.
    cookie_key: Vec<u8>,
}

impl SecretStore {
    /// The default backend: secrets stay in SQLite.
    pub fn database(cookie_key: Vec<u8>) -> Self {
        Self {
            backend: Backend::Database,
            cookie_key,
        }
    }

    /// Connect to OpenBao and verify the credentials before returning.
    pub async fn openbao(config: BaoConfig, cookie_key: Vec<u8>) -> Result<Self> {
        let summary = config.describe();
        let client = BaoClient::connect(config)
            .await
            .with_context(|| format!("connecting to OpenBao at {}", summary))?;
        client
            .health_check()
            .await
            .context("OpenBao credentials were rejected")?;
        tracing::info!("Secret backend: OpenBao — {}", summary);
        Ok(Self {
            backend: Backend::OpenBao(Arc::new(client)),
            cookie_key,
        })
    }

    pub fn is_external(&self) -> bool {
        matches!(self.backend, Backend::OpenBao(_))
    }

    fn bao(&self) -> Option<&BaoClient> {
        match &self.backend {
            Backend::OpenBao(c) => Some(c),
            Backend::Database => None,
        }
    }

    // ── Certificate material ──────────────────────────────────────────────

    /// Load the PEMs and PFX password for a certificate row.
    ///
    /// Reads from wherever *this row* says its material lives, not from
    /// whichever backend is currently configured — a row written before the
    /// backend was enabled still resolves correctly.
    pub async fn load_cert_material(&self, cert: &Certificate) -> Result<CertMaterial> {
        if let Some(path) = cert.secret_ref.as_deref().and_then(as_ref_path) {
            let client = self.bao().context(
                "this certificate's key material lives in OpenBao, but no OpenBao backend is \
                 configured — set BAO_ADDR (and credentials) to read it",
            )?;
            let Some(data) = client.read(path).await.with_context(|| {
                format!("reading certificate material from OpenBao at {}", path)
            })?
            else {
                // The row points at a secret that is gone. Treat it as "not
                // issued yet" so the caller 404s rather than 500s; the cert
                // can be re-issued to repopulate it.
                tracing::warn!(
                    "Certificate {} references OpenBao path {} but no secret is there",
                    cert.id,
                    path
                );
                return Ok(CertMaterial::default());
            };
            return Ok(CertMaterial {
                fullchain_pem: data.get(F_FULLCHAIN).cloned(),
                cert_pem: data.get(F_CERT).cloned(),
                chain_pem: data.get(F_CHAIN).cloned(),
                privkey_pem: data.get(F_PRIVKEY).cloned(),
                pfx_password: data.get(F_PFX_PASSWORD).cloned(),
            });
        }

        Ok(CertMaterial {
            fullchain_pem: cert.fullchain_pem.clone(),
            cert_pem: cert.cert_pem.clone(),
            chain_pem: cert.chain_pem.clone(),
            privkey_pem: cert.privkey_pem.clone(),
            // A decrypt failure here means COOKIE_KEY rotated. The PFX
            // handler treats `None` as "mint a fresh password", which is the
            // right recovery, so swallow the error rather than failing the
            // whole read.
            pfx_password: cert
                .pfx_password_enc
                .as_deref()
                .and_then(|enc| secret::decrypt(enc, &self.cookie_key).ok()),
        })
    }

    /// Persist freshly-issued material, leaving the row's status/expiry to
    /// the caller. Returns the value to write into `secret_ref`.
    ///
    /// The PFX password is *not* touched: it is generated lazily on first
    /// download and must survive a renewal, so a re-issue carries the
    /// existing one forward.
    pub async fn store_issued_cert(
        &self,
        db: &SqlitePool,
        cert_id: &str,
        issued: &IssuedCert,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        let Some(client) = self.bao() else {
            sqlx::query(
                "UPDATE certificates
                 SET fullchain_pem=?, cert_pem=?, chain_pem=?, privkey_pem=?, updated_at=?
                 WHERE id=?",
            )
            .bind(&issued.fullchain_pem)
            .bind(&issued.cert_pem)
            .bind(&issued.chain_pem)
            .bind(&issued.privkey_pem)
            .bind(&now)
            .bind(cert_id)
            .execute(db)
            .await?;
            return Ok(());
        };

        let path = cert_path(cert_id);
        // Carry the existing PFX password over so a renewal doesn't silently
        // invalidate the archive the operator already downloaded.
        //
        // A failed read here must not fail the renewal — a cert that didn't
        // get issued is far worse than a PFX password the operator has to
        // regenerate. But it mustn't pass silently either, because the next
        // download would hand them a different password with no explanation.
        let mut data = match client.read(&path).await {
            Ok(existing) => existing.unwrap_or_default(),
            Err(e) => {
                tracing::warn!(
                    "Could not read the existing secret for certificate {} before re-issuing \
                     ({:#}); any stored PFX password is being replaced and the next download \
                     will show a new one",
                    cert_id,
                    e
                );
                BTreeMap::new()
            }
        };
        data.insert(F_FULLCHAIN.into(), issued.fullchain_pem.clone());
        data.insert(F_CERT.into(), issued.cert_pem.clone());
        data.insert(F_CHAIN.into(), issued.chain_pem.clone());
        data.insert(F_PRIVKEY.into(), issued.privkey_pem.clone());

        client
            .write(&path, &data)
            .await
            .with_context(|| format!("writing certificate material to OpenBao at {}", path))?;

        // Only now point the row at it, and make sure no copy lingers in the
        // columns — this is also the path a DB-backed cert takes on its first
        // renewal after the backend is switched on.
        sqlx::query(
            "UPDATE certificates
             SET secret_ref=?, fullchain_pem=NULL, cert_pem=NULL, chain_pem=NULL,
                 privkey_pem=NULL, updated_at=?
             WHERE id=?",
        )
        .bind(format!("{}{}", REF_PREFIX, path))
        .bind(&now)
        .bind(cert_id)
        .execute(db)
        .await?;
        Ok(())
    }

    /// Save the PFX password for a certificate.
    pub async fn store_pfx_password(
        &self,
        db: &SqlitePool,
        cert: &Certificate,
        password: &str,
    ) -> Result<()> {
        let now = Utc::now().to_rfc3339();

        if let Some(path) = cert.secret_ref.as_deref().and_then(as_ref_path) {
            let client = self
                .bao()
                .context("no OpenBao backend configured to store the PFX password")?;
            let mut data = client.read(path).await?.unwrap_or_default();
            data.insert(F_PFX_PASSWORD.into(), password.to_string());
            client
                .write(path, &data)
                .await
                .with_context(|| format!("writing the PFX password to OpenBao at {}", path))?;
            return Ok(());
        }

        let enc = secret::encrypt(password, &self.cookie_key)?;
        sqlx::query("UPDATE certificates SET pfx_password_enc = ?, updated_at = ? WHERE id = ?")
            .bind(&enc)
            .bind(&now)
            .bind(&cert.id)
            .execute(db)
            .await?;
        Ok(())
    }

    /// Drop a certificate's material. Called after the row is deleted, so a
    /// failure here leaves an orphaned secret rather than a dangling row —
    /// logged, not fatal.
    pub async fn delete_cert_material(&self, cert: &Certificate) -> Result<()> {
        let Some(path) = cert.secret_ref.as_deref().and_then(as_ref_path) else {
            // DB backend: the material went with the row.
            return Ok(());
        };
        let client = self
            .bao()
            .context("no OpenBao backend configured to delete the certificate material")?;
        client
            .delete(path)
            .await
            .with_context(|| format!("destroying OpenBao secret at {}", path))
    }

    // ── ACME account key ──────────────────────────────────────────────────

    /// Resolve the account key from a settings map, following a reference if
    /// that's what the `acme_account_key` value is.
    pub async fn load_acme_account_key(&self, stored: Option<&str>) -> Result<Option<String>> {
        let Some(value) = stored.filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let Some(path) = as_ref_path(value) else {
            return Ok(Some(value.to_string()));
        };
        let client = self.bao().context(
            "the ACME account key lives in OpenBao, but no OpenBao backend is configured",
        )?;
        let data = client
            .read(path)
            .await
            .with_context(|| format!("reading the ACME account key from OpenBao at {}", path))?;
        Ok(data.and_then(|d| d.get(F_ACME_KEY).cloned()))
    }

    /// Persist the ACME account key, writing a reference into `settings` when
    /// the OpenBao backend is active.
    pub async fn store_acme_account_key(&self, db: &SqlitePool, key_b64: &str) -> Result<()> {
        let value = match self.bao() {
            None => key_b64.to_string(),
            Some(client) => {
                let mut data = BTreeMap::new();
                data.insert(F_ACME_KEY.to_string(), key_b64.to_string());
                client
                    .write(ACME_PATH, &data)
                    .await
                    .context("writing the ACME account key to OpenBao")?;
                format!("{}{}", REF_PREFIX, ACME_PATH)
            }
        };

        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        )
        .bind(S_ACME_ACCOUNT_KEY)
        .bind(&value)
        .bind(Utc::now().to_rfc3339())
        .execute(db)
        .await?;
        Ok(())
    }

    // ── DNS integration credentials ───────────────────────────────────────

    /// Decode an integration's config, following a reference if present.
    pub async fn load_integration_config(
        &self,
        row: &IntegrationRow,
    ) -> Result<BTreeMap<String, String>> {
        let Some(path) = as_ref_path(&row.config) else {
            return Ok(row.config_map());
        };
        let client = self.bao().with_context(|| {
            format!(
                "integration '{}' has its credentials in OpenBao, but no OpenBao backend is \
                 configured",
                row.name
            )
        })?;
        let data = client
            .read(path)
            .await
            .with_context(|| format!("reading integration credentials from OpenBao at {}", path))?;
        Ok(data.unwrap_or_default())
    }

    /// The value to store in `integrations.config` — either the JSON blob
    /// itself, or a reference after writing the blob to OpenBao.
    pub async fn store_integration_config(
        &self,
        id: &str,
        config: &BTreeMap<String, String>,
    ) -> Result<String> {
        let Some(client) = self.bao() else {
            return Ok(serde_json::to_string(config).unwrap_or_else(|_| "{}".into()));
        };
        let path = integration_path(id);
        client
            .write(&path, config)
            .await
            .with_context(|| format!("writing integration credentials to OpenBao at {}", path))?;
        Ok(format!("{}{}", REF_PREFIX, path))
    }

    /// Drop an integration's credentials.
    pub async fn delete_integration_config(&self, row: &IntegrationRow) -> Result<()> {
        let Some(path) = as_ref_path(&row.config) else {
            return Ok(());
        };
        let client = self
            .bao()
            .context("no OpenBao backend configured to delete the integration credentials")?;
        client
            .delete(path)
            .await
            .with_context(|| format!("destroying OpenBao secret at {}", path))
    }

    // ── Migration ─────────────────────────────────────────────────────────

    /// Move every secret still sitting in SQLite into OpenBao.
    ///
    /// Write, read back, verify, *then* clear the column — so an interrupted
    /// run never loses material, it just leaves work for the next boot. A row
    /// that already carries a reference is skipped, which makes the whole
    /// thing idempotent and cheap on subsequent starts.
    ///
    /// No-op when the DB backend is active.
    pub async fn migrate_from_database(&self, db: &SqlitePool) -> Result<()> {
        let Some(client) = self.bao() else {
            return Ok(());
        };

        let mut moved = Migrated::default();

        // ── Certificates ──
        let certs: Vec<Certificate> = sqlx::query_as(
            "SELECT * FROM certificates
             WHERE secret_ref IS NULL
               AND (fullchain_pem IS NOT NULL OR cert_pem IS NOT NULL
                    OR chain_pem IS NOT NULL OR privkey_pem IS NOT NULL
                    OR pfx_password_enc IS NOT NULL)",
        )
        .fetch_all(db)
        .await?;

        for cert in &certs {
            let material = self.load_cert_material(cert).await?;
            let mut data = BTreeMap::new();
            for (field, value) in [
                (F_FULLCHAIN, &material.fullchain_pem),
                (F_CERT, &material.cert_pem),
                (F_CHAIN, &material.chain_pem),
                (F_PRIVKEY, &material.privkey_pem),
                (F_PFX_PASSWORD, &material.pfx_password),
            ] {
                if let Some(v) = value {
                    data.insert(field.to_string(), v.clone());
                }
            }

            let path = cert_path(&cert.id);
            client.write(&path, &data).await.with_context(|| {
                format!("migrating certificate {} ({})", cert.common_name, cert.id)
            })?;
            verify_readback(client, &path, &data)
                .await
                .with_context(|| {
                    format!(
                        "verifying migrated certificate {} ({})",
                        cert.common_name, cert.id
                    )
                })?;

            sqlx::query(
                "UPDATE certificates
                 SET secret_ref=?, fullchain_pem=NULL, cert_pem=NULL, chain_pem=NULL,
                     privkey_pem=NULL, pfx_password_enc=NULL
                 WHERE id=?",
            )
            .bind(format!("{}{}", REF_PREFIX, path))
            .bind(&cert.id)
            .execute(db)
            .await?;
            moved.certificates += 1;
        }

        // ── ACME account key ──
        let acme: Option<(String,)> = sqlx::query_as("SELECT value FROM settings WHERE key = ?")
            .bind(S_ACME_ACCOUNT_KEY)
            .fetch_optional(db)
            .await?;
        if let Some((value,)) = acme {
            if !value.is_empty() && as_ref_path(&value).is_none() {
                let mut data = BTreeMap::new();
                data.insert(F_ACME_KEY.to_string(), value);
                client
                    .write(ACME_PATH, &data)
                    .await
                    .context("migrating the ACME account key")?;
                verify_readback(client, ACME_PATH, &data)
                    .await
                    .context("verifying the migrated ACME account key")?;

                sqlx::query("UPDATE settings SET value=?, updated_at=? WHERE key=?")
                    .bind(format!("{}{}", REF_PREFIX, ACME_PATH))
                    .bind(Utc::now().to_rfc3339())
                    .bind(S_ACME_ACCOUNT_KEY)
                    .execute(db)
                    .await?;
                moved.acme_key = true;
            }
        }

        // ── DNS integrations ──
        let rows: Vec<IntegrationRow> = sqlx::query_as("SELECT * FROM integrations")
            .fetch_all(db)
            .await?;
        for row in &rows {
            if as_ref_path(&row.config).is_some() {
                continue;
            }
            let config = row.config_map();
            let path = integration_path(&row.id);
            client
                .write(&path, &config)
                .await
                .with_context(|| format!("migrating integration '{}'", row.name))?;
            verify_readback(client, &path, &config)
                .await
                .with_context(|| format!("verifying migrated integration '{}'", row.name))?;

            sqlx::query("UPDATE integrations SET config=? WHERE id=?")
                .bind(format!("{}{}", REF_PREFIX, path))
                .bind(&row.id)
                .execute(db)
                .await?;
            moved.integrations += 1;
        }

        if moved.any() {
            tracing::info!(
                "Migrated secrets into OpenBao: {} certificate(s), {} integration(s), \
                 acme_account_key={}. The corresponding database columns are now empty.",
                moved.certificates,
                moved.integrations,
                moved.acme_key
            );
            scrub_database(db).await?;
        } else {
            tracing::debug!("No database-resident secrets left to migrate into OpenBao");
        }
        Ok(())
    }
}

/// Rewrite the database file so the migrated plaintext is actually gone.
///
/// `UPDATE … SET col = NULL` only unlinks the old payload: the bytes stay in
/// free pages and in WAL frames, where `grep` finds them just fine. For a
/// feature whose whole point is "the private keys are not on this disk", that
/// is not good enough — so after a migration that moved something, fold the
/// WAL into the main file, VACUUM (which rebuilds it from the live rows only),
/// then truncate the WAL that VACUUM itself produced.
///
/// Only ever runs at boot, immediately after a migration, so there is no
/// concurrent writer to contend with.
async fn scrub_database(db: &SqlitePool) -> Result<()> {
    for stmt in [
        "PRAGMA wal_checkpoint(TRUNCATE)",
        "VACUUM",
        "PRAGMA wal_checkpoint(TRUNCATE)",
    ] {
        sqlx::query(stmt).execute(db).await.with_context(|| {
            format!(
                "scrubbing migrated secrets out of the database file ({}). The secrets are \
                 safely in OpenBao, but stale copies may remain in the SQLite file — run \
                 `VACUUM` against it manually.",
                stmt
            )
        })?;
    }
    tracing::info!("Database file rewritten — no stale copies of the migrated secrets remain");
    Ok(())
}

#[derive(Default)]
struct Migrated {
    certificates: usize,
    integrations: usize,
    acme_key: bool,
}

impl Migrated {
    fn any(&self) -> bool {
        self.certificates > 0 || self.integrations > 0 || self.acme_key
    }
}

/// Read a just-written secret back and confirm every field survived the round
/// trip. The guard that makes clearing the DB column safe.
async fn verify_readback(
    client: &BaoClient,
    path: &str,
    expected: &BTreeMap<String, String>,
) -> Result<()> {
    let got = client
        .read(path)
        .await?
        .context("secret is not readable immediately after writing it")?;
    for (k, v) in expected {
        match got.get(k) {
            Some(actual) if actual == v => {}
            Some(_) => anyhow::bail!("field '{}' does not match what was written", k),
            None => anyhow::bail!("field '{}' is missing from the read-back", k),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_value_is_not_a_reference() {
        assert!(as_ref_path("LS0tLS1CRUdJTi…").is_none());
        assert!(as_ref_path(r#"{"cf_api_token":"abc"}"#).is_none());
    }

    #[test]
    fn a_reference_yields_its_path() {
        assert_eq!(
            as_ref_path("openbao:certificates/abc-123"),
            Some("certificates/abc-123")
        );
        assert_eq!(as_ref_path("openbao:acme/account"), Some("acme/account"));
    }

    #[test]
    fn paths_are_namespaced_by_kind() {
        assert_eq!(cert_path("abc"), "certificates/abc");
        assert_eq!(integration_path("def"), "integrations/def");
    }

    /// The DB backend must keep round-tripping the PFX password through
    /// COOKIE_KEY — the OpenBao path is what skips the extra layer.
    #[test]
    fn database_backend_still_encrypts_the_pfx_password() {
        let store = SecretStore::database(b"cookie-key".to_vec());
        assert!(!store.is_external());
        let ct = secret::encrypt("hunter2", &store.cookie_key).unwrap();
        assert_ne!(ct, "hunter2");
        assert_eq!(secret::decrypt(&ct, &store.cookie_key).unwrap(), "hunter2");
    }
}
