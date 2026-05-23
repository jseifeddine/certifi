//! TOTP (RFC 6238) enrollment + verification.
//!
//! Phase 6 / MFA. Each enrolled user has one row in `user_totp` keyed on
//! `user_id`; `secret_enc` holds the base32 secret encrypted with the
//! instance's `COOKIE_KEY`. The factor is only treated as required for
//! sign-in once `verified_at` is non-NULL — i.e. the user has proven they
//! can produce a current code.

use crate::services::secret;
use crate::AppState;
use anyhow::{anyhow, Result};
use chrono::Utc;
use totp_rs::{Algorithm, Secret, TOTP};

const ISSUER: &str = "Certifi";
const STEP_SECONDS: u64 = 30;
const SKEW: u8 = 1; // allow +/- one step for client clock drift

fn totp_for(secret_b32: &str, account: &str) -> Result<TOTP> {
    let bytes = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| anyhow!("decode TOTP secret: {:?}", e))?;
    TOTP::new(
        Algorithm::SHA1,
        6,
        SKEW,
        STEP_SECONDS,
        bytes,
        Some(ISSUER.into()),
        account.into(),
    )
    .map_err(|e| anyhow!("construct TOTP: {:?}", e))
}

/// Information returned to the SPA at enrollment so the user can scan a
/// QR code or paste the secret into their authenticator. Until the user
/// confirms a code via `verify_user_code` the factor is **not** enforced
/// at sign-in.
pub struct EnrollmentResult {
    pub secret_b32: String,
    /// `otpauth://` URI suitable for QR rendering.
    pub provisioning_uri: String,
    /// base64-encoded PNG of the QR code, so the SPA doesn't need its own
    /// QR library.
    pub qr_png_b64: String,
}

/// Create or replace the user's enrollment. Existing `verified_at` is
/// cleared so the new factor must be re-verified before it gates sign-in.
pub async fn begin_enrollment(
    state: &AppState,
    user_id: &str,
    account: &str,
) -> Result<EnrollmentResult> {
    let secret_b32 = Secret::generate_secret().to_encoded().to_string();
    let totp = totp_for(&secret_b32, account)?;

    let secret_enc = secret::encrypt(&secret_b32, &state.config.cookie_key)?;
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO user_totp (user_id, secret_enc, enrolled_at, verified_at)
         VALUES (?, ?, ?, NULL)
         ON CONFLICT(user_id) DO UPDATE SET
             secret_enc = excluded.secret_enc,
             enrolled_at = excluded.enrolled_at,
             verified_at = NULL",
    )
    .bind(user_id)
    .bind(&secret_enc)
    .bind(&now)
    .execute(&state.db)
    .await?;

    let provisioning_uri = totp.get_url();
    let qr_png_b64 = totp
        .get_qr_base64()
        .map_err(|e| anyhow!("qr render: {:?}", e))?;

    Ok(EnrollmentResult {
        secret_b32,
        provisioning_uri,
        qr_png_b64,
    })
}

/// First-time confirmation: validates the supplied code against the
/// stored secret and, on success, stamps `verified_at` so subsequent
/// sign-ins gate on TOTP.
pub async fn confirm_enrollment(state: &AppState, user_id: &str, code: &str) -> Result<()> {
    let secret_enc: String =
        sqlx::query_scalar("SELECT secret_enc FROM user_totp WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| anyhow!("No TOTP enrollment for this user"))?;
    let secret_b32 = secret::decrypt(&secret_enc, &state.config.cookie_key)?;
    let totp = totp_for(&secret_b32, user_id)?;
    if !totp.check_current(code).unwrap_or(false) {
        return Err(anyhow!("Code does not match"));
    }
    sqlx::query("UPDATE user_totp SET verified_at = ? WHERE user_id = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Verify a code during a sign-in flow. Called from `POST /api/auth/login/totp`.
pub async fn verify_user_code(state: &AppState, user_id: &str, code: &str) -> Result<()> {
    let secret_enc: String = sqlx::query_scalar(
        "SELECT secret_enc FROM user_totp WHERE user_id = ? AND verified_at IS NOT NULL",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| anyhow!("TOTP not enrolled"))?;
    let secret_b32 = secret::decrypt(&secret_enc, &state.config.cookie_key)?;
    let totp = totp_for(&secret_b32, user_id)?;
    if totp.check_current(code).unwrap_or(false) {
        Ok(())
    } else {
        Err(anyhow!("Invalid TOTP code"))
    }
}

/// Disable TOTP entirely for a user. Idempotent.
pub async fn disable(state: &AppState, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM user_totp WHERE user_id = ?")
        .bind(user_id)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// `(enrolled, verified)` — is the user mid-enrollment or fully on?
pub async fn status(state: &AppState, user_id: &str) -> Result<(bool, bool)> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT verified_at FROM user_totp WHERE user_id = ?")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?;
    Ok(match row {
        None => (false, false),
        Some((None,)) => (true, false),
        Some((Some(_),)) => (true, true),
    })
}
