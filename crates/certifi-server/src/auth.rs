use crate::error::AppError;
use crate::rbac;
use crate::AppState;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;
use chrono::Utc;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use std::collections::HashSet;

pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_api_token() -> String {
    use rand::Rng;
    let random: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(40)
        .map(char::from)
        .collect();
    format!("dapi_{}", random)
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub username: String,
    /// Derived from holding the SuperAdmin role at global scope. Kept as a
    /// struct field so handlers and the auth/me response don't each have
    /// to query.
    pub is_admin: bool,
    /// Permission set granted at **global scope** — i.e. apply everywhere.
    /// `has` / `require` check this set.
    pub permissions: HashSet<String>,
    /// Non-global grants, each pinned to a specific scope string (e.g.
    /// `"zone:example.com"`). Consumed by [`has_for_domains`] /
    /// [`require_for_domains`] when an operation has a domain context.
    pub scoped: Vec<rbac::ScopedGrant>,
    /// Request metadata captured by the extractor — used by the audit log.
    pub remote_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    /// `Some(id)` when the request authenticated via an API token; that id
    /// also lands in the audit row so a stolen token can be traced.
    pub via_token: Option<String>,
}

impl AuthUser {
    /// True if the user holds the given permission at **global scope**.
    /// Use this only for operations that don't have a domain context
    /// (settings, user mgmt, role mgmt, …).
    pub fn has(&self, perm: &str) -> bool {
        self.permissions.contains(perm)
    }

    /// Global-scope permission check. Returns `Forbidden` if missing.
    pub fn require(&self, perm: &str) -> Result<(), AppError> {
        if self.has(perm) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    /// Permission check for a domain-scoped operation. Returns true iff
    /// **every** requested domain is covered by a grant — either the global
    /// permission, or a `zone:Z` grant where Z is `domain` or an ancestor.
    ///
    /// A cert spanning multiple zones (e.g. `example.com` + `other.com`)
    /// therefore requires permission on *each* zone, or a global grant.
    /// Conservative on purpose: better to deny a partial grant than to
    /// silently issue a cert the user isn't authorized for.
    pub fn has_for_domains<S: AsRef<str>>(&self, perm: &str, domains: &[S]) -> bool {
        if self.has(perm) {
            return true;
        }
        if domains.is_empty() {
            return false;
        }
        domains.iter().all(|d| self.covers_domain(perm, d.as_ref()))
    }

    /// `has_for_domains` → `Forbidden`.
    pub fn require_for_domains<S: AsRef<str>>(
        &self,
        perm: &str,
        domains: &[S],
    ) -> Result<(), AppError> {
        if self.has_for_domains(perm, domains) {
            Ok(())
        } else {
            Err(AppError::Forbidden)
        }
    }

    fn covers_domain(&self, perm: &str, domain: &str) -> bool {
        if self.has(perm) {
            return true;
        }
        for grant in &self.scoped {
            let Some(zone) = grant.scope.strip_prefix("zone:") else {
                continue;
            };
            if grant.permissions.contains(perm) && rbac::zone_covers(zone, domain) {
                return true;
            }
        }
        false
    }
}

/// Build an [`AuthUser`] once we've resolved a user id from a JWT, cookie, or
/// API token. Centralised so every code path loads the same RBAC view.
async fn build_auth_user(
    db: &SqlitePool,
    user_id: String,
    username: String,
) -> Result<AuthUser, AppError> {
    let grants = rbac::load_user_grants(db, &user_id)
        .await
        .map_err(AppError::Database)?;
    let is_admin = rbac::is_super_admin(db, &user_id)
        .await
        .map_err(AppError::Database)?;
    Ok(AuthUser {
        user_id,
        username,
        is_admin,
        permissions: grants.global,
        scoped: grants.scoped,
        remote_ip: None,
        user_agent: None,
        request_id: None,
        via_token: None,
    })
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Best-effort client IP. Prefers `X-Forwarded-For` (first hop in the
/// comma-separated list) so deployments behind nginx/HAProxy see the real
/// client; falls back to `X-Real-IP`.
fn client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(xff) = header_str(headers, "x-forwarded-for") {
        if let Some(first) = xff.split(',').next() {
            let t = first.trim();
            if !t.is_empty() {
                return Some(t.to_string());
            }
        }
    }
    header_str(headers, "x-real-ip")
}

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn extract_cookie_token(headers: &HeaderMap) -> Option<String> {
    let cookie_hdr = headers.get("Cookie")?.to_str().ok()?;
    for part in cookie_hdr.split(';') {
        let part = part.trim();
        if let Some(val) = part.strip_prefix("session=") {
            return Some(val.to_string());
        }
    }
    None
}

#[axum::async_trait]
impl FromRequestParts<AppState> for AuthUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let headers = &parts.headers;
        let remote_ip = client_ip(headers);
        let user_agent = header_str(headers, "user-agent");
        let request_id = header_str(headers, "x-request-id");

        // 1. Try Authorization: Bearer <token>
        //    - `dapi_…` → API token (CLI clients)
        //    - anything else → opaque session id (browser fallback for
        //      clients that can't set cookies cleanly, e.g. testing tools)
        if let Some(bearer) = extract_bearer(headers) {
            if !bearer.starts_with("dapi_") {
                if let Some((user_id, username)) =
                    crate::services::sessions::lookup(&state.db, bearer).await?
                {
                    let mut auth = build_auth_user(&state.db, user_id, username).await?;
                    auth.remote_ip = remote_ip;
                    auth.user_agent = user_agent;
                    auth.request_id = request_id;
                    return Ok(auth);
                }
            }

            if bearer.starts_with("dapi_") {
                let hash = hash_token(bearer);
                let now = Utc::now().to_rfc3339();
                let result = sqlx::query_as::<_, (String, String, String, Option<String>)>(
                    "SELECT t.id, u.id, u.username, t.permissions FROM api_tokens t
                     JOIN users u ON u.id = t.user_id
                     WHERE t.token_hash = ? AND (t.expires_at IS NULL OR t.expires_at > ?)",
                )
                .bind(&hash)
                .bind(&now)
                .fetch_optional(&state.db)
                .await
                .map_err(|_| AppError::Unauthorized)?;

                if let Some((token_id, user_id, username, perm_json)) = result {
                    // Update last_used_at
                    let _ =
                        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE token_hash = ?")
                            .bind(&now)
                            .bind(&hash)
                            .execute(&state.db)
                            .await;

                    let mut auth = build_auth_user(&state.db, user_id, username).await?;
                    auth.remote_ip = remote_ip;
                    auth.user_agent = user_agent;
                    auth.request_id = request_id;
                    auth.via_token = Some(token_id);
                    // If the token carries an explicit permission list, intersect
                    // it with the user's effective set. A user whose role is
                    // revoked therefore loses token-driven access on the very
                    // next request — see phase 4 in docs/api.md.
                    if let Some(json) = perm_json {
                        let allow: HashSet<String> = serde_json::from_str::<Vec<String>>(&json)
                            .unwrap_or_default()
                            .into_iter()
                            .collect();
                        auth.permissions.retain(|p| allow.contains(p));
                        for grant in auth.scoped.iter_mut() {
                            grant.permissions.retain(|p| allow.contains(p));
                        }
                        // SuperAdmin status is "is global SuperAdmin role assigned"
                        // -> independent of token scoping. But once we restrict
                        // permissions, the is_admin flag would be misleading for
                        // UI affordances, so recompute it as "has every system
                        // SuperAdmin permission via the token". Cheap enough.
                        auth.is_admin = auth.is_admin
                            && auth.permissions.contains(crate::rbac::perms::ROLE_ASSIGN);
                    }
                    return Ok(auth);
                }
            }
        }

        // 2. Try DB-backed session cookie (phase 6).
        if let Some(session_id) = extract_cookie_token(headers) {
            if let Some((user_id, username)) =
                crate::services::sessions::lookup(&state.db, &session_id).await?
            {
                let mut auth = build_auth_user(&state.db, user_id, username).await?;
                auth.remote_ip = remote_ip;
                auth.user_agent = user_agent;
                auth.request_id = request_id;
                return Ok(auth);
            }
        }

        Err(AppError::Unauthorized)
    }
}
