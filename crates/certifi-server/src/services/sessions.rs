//! DB-backed opaque session tokens for browser flows.
//!
//! Replaces the JWT-as-session-cookie pattern phase 1 inherited. Each session
//! is one row in the `sessions` table; the cookie carries only the row id.
//!
//! Trade-off vs. JWT: every authenticated request pays a single DB lookup,
//! but in return we get **instant revocation** (DELETE the row → next request
//! 401s) and no JWT-secret rotation problem. With the in-process SQLite pool
//! the lookup is sub-millisecond.
//!
//! `Authorization: Bearer dapi_…` API tokens are unchanged and bypass this
//! module entirely — see `auth.rs`.

use crate::error::AppError;
use anyhow::Result;
use chrono::{Duration, Utc};
use rand::Rng;
use sqlx::SqlitePool;

/// Lifetime of a freshly-minted session. Each request bumps `last_used_at`
/// but the expiry stays absolute — equivalent to a refresh-on-use within
/// the 8-hour window, no infinite extension.
pub const SESSION_TTL: Duration = Duration::hours(8);

/// Cookie name carrying the opaque session id. Same name the JWT cookie
/// used so existing reverse-proxy rules keep working.
pub const COOKIE_NAME: &str = "session";

/// Random 32-byte URL-safe session id. Distinguishable from `dapi_` API
/// tokens by the absence of that prefix.
fn new_id() -> String {
    let bytes: [u8; 24] = rand::thread_rng().gen();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}

/// Insert a fresh row and return the id the caller should put in the cookie.
///
/// `oidc` carries `(id_token, end_session_endpoint)` when the session was
/// minted via the OIDC callback — both are stored so logout can build an
/// RP-initiated-logout URL back to the IdP. Local sign-ins pass `None`.
pub async fn create(
    db: &SqlitePool,
    user_id: &str,
    ip: Option<&str>,
    user_agent: Option<&str>,
    oidc: Option<(&str, Option<&str>)>,
) -> Result<String> {
    let id = new_id();
    let now = Utc::now();
    let (id_token, end_session_url) = match oidc {
        Some((tok, end)) => (Some(tok), end),
        None => (None, None),
    };
    sqlx::query(
        "INSERT INTO sessions (id, user_id, created_at, last_used_at, expires_at, ip, user_agent,
                               oidc_id_token, oidc_end_session_url)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(user_id)
    .bind(now.to_rfc3339())
    .bind(now.to_rfc3339())
    .bind((now + SESSION_TTL).to_rfc3339())
    .bind(ip)
    .bind(user_agent)
    .bind(id_token)
    .bind(end_session_url)
    .execute(db)
    .await?;
    Ok(id)
}

/// Pull the OIDC tail for a session, if any. Returns
/// `(id_token, end_session_endpoint)` — both populated only for sessions
/// minted via the OIDC callback. Called by the logout handler to decide
/// whether to do an RP-initiated-logout redirect or just clear the cookie.
pub async fn oidc_logout_info(
    db: &SqlitePool,
    session_id: &str,
) -> Result<Option<(String, String)>> {
    let row: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT oidc_id_token, oidc_end_session_url FROM sessions WHERE id = ?")
            .bind(session_id)
            .fetch_optional(db)
            .await?;
    Ok(row.and_then(|(t, e)| match (t, e) {
        (Some(t), Some(e)) if !t.is_empty() && !e.is_empty() => Some((t, e)),
        _ => None,
    }))
}

/// Resolve a session id from the cookie. Returns the bound user (id +
/// username) and refreshes `last_used_at`. Expired rows are deleted and
/// surface as `None`.
pub async fn lookup(
    db: &SqlitePool,
    session_id: &str,
) -> std::result::Result<Option<(String, String)>, AppError> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT s.user_id, u.username, s.expires_at FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.id = ?",
    )
    .bind(session_id)
    .fetch_optional(db)
    .await?;

    let Some((user_id, username, expires_at)) = row else {
        return Ok(None);
    };

    let now = Utc::now();
    let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| dt.with_timezone(&Utc) < now)
        .unwrap_or(true);
    if expired {
        // Best-effort cleanup; ignore failures.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(session_id)
            .execute(db)
            .await;
        return Ok(None);
    }

    // Bump activity timestamp. Best-effort — a failure here shouldn't deny
    // the request.
    let _ = sqlx::query("UPDATE sessions SET last_used_at = ? WHERE id = ?")
        .bind(now.to_rfc3339())
        .bind(session_id)
        .execute(db)
        .await;

    Ok(Some((user_id, username)))
}

/// Tear down a single session row (called by /api/auth/logout).
pub async fn destroy(db: &SqlitePool, session_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE id = ?")
        .bind(session_id)
        .execute(db)
        .await?;
    Ok(())
}

/// Cookie string the login endpoint writes. HttpOnly + SameSite=Strict so
/// the browser refuses to send it on cross-site state-changing requests —
/// adequate CSRF protection without the double-submit dance for now.
pub fn cookie_for(session_id: &str) -> String {
    format!(
        "{}={}; HttpOnly; SameSite=Strict; Path=/; Max-Age={}",
        COOKIE_NAME,
        session_id,
        SESSION_TTL.num_seconds(),
    )
}

/// Cookie string used by `/api/auth/logout` to clear the session.
pub fn clear_cookie() -> String {
    format!(
        "{}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        COOKIE_NAME
    )
}
