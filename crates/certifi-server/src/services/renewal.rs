use crate::config::Config;
use crate::events::{emit, CertEvent, CertEventSender};
use crate::integrations;
use crate::models::*;
use crate::services::acme::{AccountCredentials, AcmeClient};
use crate::services::email::EmailNotifier;
use crate::services::pfx::parse_cert_expiry;
use crate::services::secret_store::SecretStore;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

pub async fn run_renewal_scheduler(
    db: SqlitePool,
    config: Config,
    events: CertEventSender,
    secrets: SecretStore,
) {
    // Brief startup delay so the server is fully initialised
    sleep(Duration::from_secs(30)).await;

    loop {
        tracing::info!("Renewal scheduler: checking certificates...");
        if let Err(e) = check_renewals(&db, &config, &events, &secrets).await {
            tracing::error!("Renewal scheduler error: {:?}", e);
        }
        sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

async fn check_renewals(
    db: &SqlitePool,
    config: &Config,
    events: &CertEventSender,
    secrets: &SecretStore,
) -> anyhow::Result<()> {
    let notifier = EmailNotifier::new(config.clone());
    let recipients = fetch_email_recipients(db).await?;

    let settings = load_effective_settings(db, config).await?;
    let now = Utc::now();
    let threshold = now + chrono::Duration::days(30);
    let threshold_str = threshold.to_rfc3339();

    // Certs due for auto-renewal (auto_renew=1, active, expiring <30d)
    let due: Vec<Certificate> = sqlx::query_as(
        "SELECT * FROM certificates
         WHERE auto_renew = 1
           AND status = 'active'
           AND expires_at IS NOT NULL
           AND expires_at < ?",
    )
    .bind(&threshold_str)
    .fetch_all(db)
    .await?;

    for cert in &due {
        tracing::info!(
            "Auto-renewing {} (expires {:?})",
            cert.common_name,
            cert.expires_at
        );
        renew_cert(db, cert, &settings, events, secrets, &notifier, &recipients).await;
    }

    // Certs whose last attempt failed. Without this pass a single bad run
    // (DNS provider hiccup, expired API token, ACME rate limit) parks the row
    // in `failed` forever: the query above only looks at `active` rows, so
    // auto-renew never fires again and the cert silently expires. Retried on
    // the same daily cadence — either it's already inside the renewal window
    // or it never got issued at all (expires_at IS NULL).
    let retry: Vec<Certificate> = sqlx::query_as(
        "SELECT * FROM certificates
         WHERE auto_renew = 1
           AND status = 'failed'
           AND (expires_at IS NULL OR expires_at < ?)",
    )
    .bind(&threshold_str)
    .fetch_all(db)
    .await?;

    for cert in &retry {
        tracing::info!(
            "Retrying failed certificate {} (last error: {})",
            cert.common_name,
            cert.error.as_deref().unwrap_or("unknown")
        );
        renew_cert(db, cert, &settings, events, secrets, &notifier, &recipients).await;
    }

    // Certs with auto_renew=0 that are expiring — just warn
    let expiring: Vec<Certificate> = sqlx::query_as(
        "SELECT * FROM certificates
         WHERE auto_renew = 0
           AND status = 'active'
           AND expires_at IS NOT NULL
           AND expires_at < ?",
    )
    .bind(&threshold_str)
    .fetch_all(db)
    .await?;

    for cert in &expiring {
        if let Some(exp) = &cert.expires_at {
            if let Ok(exp_dt) = chrono::DateTime::parse_from_rfc3339(exp) {
                let days = (exp_dt.with_timezone(&Utc) - now).num_days();
                tracing::warn!(
                    "Certificate {} expires in {} days and auto-renew is OFF",
                    cert.common_name,
                    days
                );
                if !recipients.is_empty() {
                    notifier
                        .send_expiry_warning(&recipients, &cert.common_name, exp, days)
                        .await;
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn renew_cert(
    db: &SqlitePool,
    cert: &Certificate,
    settings: &HashMap<String, String>,
    events: &CertEventSender,
    secrets: &SecretStore,
    notifier: &EmailNotifier,
    recipients: &[String],
) {
    // Only alert on the transition into `failed`. A cert that was already
    // failing is retried every day, and a daily "renewal failed" email for the
    // same known-broken cert is noise that trains operators to ignore it.
    let notify_on_failure = cert.status != "failed";
    let now = Utc::now().to_rfc3339();
    let _ = sqlx::query(
        "UPDATE certificates SET status='pending', error=NULL, updated_at=? WHERE id=?",
    )
    .bind(&now)
    .bind(&cert.id)
    .execute(db)
    .await;
    emit(events, CertEvent::changed(&cert.id));

    let cn = cert.common_name.clone();
    let sans: Vec<String> = serde_json::from_str(&cert.sans).unwrap_or_default();
    let cert_id = cert.id.clone();
    let key_algo_override = cert.key_algo.clone();

    match run_issuance(
        db,
        settings,
        events,
        secrets,
        &cert_id,
        &cn,
        &sans,
        key_algo_override.as_deref(),
    )
    .await
    {
        Ok(expires_at) => {
            tracing::info!("Auto-renewed {} (expires {})", cn, expires_at);
            if !recipients.is_empty() {
                notifier
                    .send_renewal_success(recipients, &cn, &expires_at)
                    .await;
            }
        }
        Err(e) => {
            let msg = e.to_string();
            tracing::error!("Auto-renewal failed for {}: {}", cn, msg);
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query(
                "UPDATE certificates SET status='failed', error=?, updated_at=? WHERE id=?",
            )
            .bind(&msg)
            .bind(&now)
            .bind(&cert_id)
            .execute(db)
            .await;
            emit(events, CertEvent::changed(&cert_id));

            if notify_on_failure && !recipients.is_empty() {
                notifier.send_renewal_failure(recipients, &cn, &msg).await;
            }
        }
    }
}

/// Issue (or re-issue) a certificate.
///
/// `key_algo_override` — per-certificate algorithm preference. When `None`,
/// falls back to the global `key_algo` setting.  The resolved algorithm is
/// written to the `key_algo` column so the UI always shows what was actually used.
#[allow(clippy::too_many_arguments)]
pub async fn run_issuance(
    db: &SqlitePool,
    settings: &HashMap<String, String>,
    events: &CertEventSender,
    secrets: &SecretStore,
    cert_id: &str,
    cn: &str,
    sans: &[String],
    key_algo_override: Option<&str>,
) -> anyhow::Result<String> {
    let now = Utc::now().to_rfc3339();

    // Resolve effective algorithm: per-cert override → global setting → hardcoded default
    let key_algo = key_algo_override
        .or_else(|| settings.get(S_KEY_ALGO).map(String::as_str))
        .unwrap_or("ec-p384");

    if !VALID_KEY_ALGOS.contains(&key_algo) {
        anyhow::bail!(
            "Unsupported key algorithm '{}'. Valid options: {}",
            key_algo,
            VALID_KEY_ALGOS.join(", ")
        );
    }

    // Persist the resolved algorithm and mark as issuing
    sqlx::query("UPDATE certificates SET status='issuing', key_algo=?, updated_at=? WHERE id=?")
        .bind(key_algo)
        .bind(&now)
        .bind(cert_id)
        .execute(db)
        .await?;
    emit(events, CertEvent::changed(cert_id));

    let ca_url = settings
        .get(S_ACME_CA)
        .map(|s| s.as_str())
        .unwrap_or(ACME_LE_PROD);

    let acme = build_acme_client(settings, ca_url, db, secrets).await?;
    let provider = integrations::build_provider(db, secrets).await?;
    if provider.is_empty() {
        anyhow::bail!("No DNS integrations configured");
    }
    let issued = acme
        .issue_certificate(cn, sans, key_algo, &provider)
        .await?;

    let expires_at = parse_cert_expiry(&issued.cert_pem).unwrap_or_default();

    // Key material first — it's the part that can fail against an external
    // backend, and a cert marked `active` whose private key never landed
    // anywhere would be worse than one left `issuing` for the retry sweep.
    secrets.store_issued_cert(db, cert_id, &issued).await?;

    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "UPDATE certificates
         SET status='active', expires_at=?, error=NULL, updated_at=?
         WHERE id=?",
    )
    .bind(&expires_at)
    .bind(&now)
    .bind(cert_id)
    .execute(db)
    .await?;
    emit(events, CertEvent::changed(cert_id));

    tracing::info!(
        "Certificate issued: {} algo={} expires={}",
        cn,
        key_algo,
        expires_at
    );
    Ok(expires_at)
}

async fn build_acme_client(
    settings: &HashMap<String, String>,
    ca_url: &str,
    db: &SqlitePool,
    secrets: &SecretStore,
) -> anyhow::Result<AcmeClient> {
    // The settings value may be the key itself or a reference into the
    // secret backend; the store knows which and resolves it either way.
    let key_b64 = secrets
        .load_acme_account_key(settings.get(S_ACME_ACCOUNT_KEY).map(String::as_str))
        .await?;
    let account_url = settings
        .get(S_ACME_ACCOUNT_URL)
        .cloned()
        .unwrap_or_default();

    if let (Some(k), url) = (key_b64, &account_url) {
        if !url.is_empty() {
            let creds = AccountCredentials {
                key_pkcs8_b64: k,
                account_url: url.clone(),
            };
            return AcmeClient::from_credentials(ca_url, &creds).await;
        }
    }

    tracing::info!("No ACME account found, registering with {}", ca_url);
    let (client, creds) = AcmeClient::register(ca_url).await?;

    secrets
        .store_acme_account_key(db, &creds.key_pkcs8_b64)
        .await?;
    sqlx::query(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
    )
    .bind(S_ACME_ACCOUNT_URL)
    .bind(&creds.account_url)
    .bind(Utc::now().to_rfc3339())
    .execute(db)
    .await?;

    Ok(client)
}

async fn load_effective_settings(
    db: &SqlitePool,
    config: &Config,
) -> anyhow::Result<HashMap<String, String>> {
    let rows = sqlx::query_as::<_, Setting>("SELECT * FROM settings")
        .fetch_all(db)
        .await?;
    let map: HashMap<String, String> = rows.into_iter().map(|s| (s.key, s.value)).collect();
    Ok(config.apply_env_overrides(map))
}

async fn fetch_email_recipients(db: &SqlitePool) -> anyhow::Result<Vec<String>> {
    let rows: Vec<(Option<String>,)> =
        sqlx::query_as("SELECT email FROM users WHERE email IS NOT NULL AND email != ''")
            .fetch_all(db)
            .await?;
    Ok(rows.into_iter().filter_map(|(e,)| e).collect())
}
