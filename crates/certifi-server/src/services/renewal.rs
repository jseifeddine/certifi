use crate::config::Config;
use crate::events::{emit, CertEvent, CertEventSender};
use crate::integrations;
use crate::models::*;
use crate::services::acme::{AccountCredentials, AcmeClient};
use crate::services::email::EmailNotifier;
use crate::services::pfx::parse_cert_expiry;
use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

pub async fn run_renewal_scheduler(db: SqlitePool, config: Config, events: CertEventSender) {
    // Brief startup delay so the server is fully initialised
    sleep(Duration::from_secs(30)).await;

    loop {
        tracing::info!("Renewal scheduler: checking certificates...");
        if let Err(e) = check_renewals(&db, &config, &events).await {
            tracing::error!("Renewal scheduler error: {:?}", e);
        }
        sleep(Duration::from_secs(24 * 60 * 60)).await;
    }
}

async fn check_renewals(
    db: &SqlitePool,
    config: &Config,
    events: &CertEventSender,
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
        renew_cert(db, cert, &settings, events, &notifier, &recipients).await;
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

async fn renew_cert(
    db: &SqlitePool,
    cert: &Certificate,
    settings: &HashMap<String, String>,
    events: &CertEventSender,
    notifier: &EmailNotifier,
    recipients: &[String],
) {
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

            if !recipients.is_empty() {
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
pub async fn run_issuance(
    db: &SqlitePool,
    settings: &HashMap<String, String>,
    events: &CertEventSender,
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

    let acme = build_acme_client(settings, ca_url, db).await?;
    let provider = integrations::build_provider(db).await?;
    if provider.is_empty() {
        anyhow::bail!("No DNS integrations configured");
    }
    let issued = acme
        .issue_certificate(cn, sans, key_algo, &provider)
        .await?;

    let expires_at = parse_cert_expiry(&issued.cert_pem).unwrap_or_default();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "UPDATE certificates
         SET status='active', fullchain_pem=?, cert_pem=?, chain_pem=?,
             privkey_pem=?, expires_at=?, error=NULL, updated_at=?
         WHERE id=?",
    )
    .bind(&issued.fullchain_pem)
    .bind(&issued.cert_pem)
    .bind(&issued.chain_pem)
    .bind(&issued.privkey_pem)
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
) -> anyhow::Result<AcmeClient> {
    let key_b64 = settings.get(S_ACME_ACCOUNT_KEY).cloned();
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

    let now = Utc::now().to_rfc3339();
    for (key, value) in [
        (S_ACME_ACCOUNT_KEY, creds.key_pkcs8_b64.as_str()),
        (S_ACME_ACCOUNT_URL, creds.account_url.as_str()),
    ] {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .bind(&now)
        .execute(db)
        .await?;
    }

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
