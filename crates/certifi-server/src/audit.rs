//! Append-only audit log.
//!
//! Each state-changing handler emits one record describing the actor (user
//! or token), the action (`certificate.create`, `user.delete`, …), the
//! resource being acted on, and a `before` / `after` JSON snapshot. The log
//! is queryable via `GET /api/audit` (gated on `audit.read`).
//!
//! Secret redaction happens at write time — any JSON object key that matches
//! a known-sensitive pattern (`password`, `token`, `secret`, `key`, etc.)
//! has its value replaced with the literal `"[REDACTED]"` before it's
//! committed. Once we've written the masked snapshot, the plaintext never
//! reaches the audit_log table.
//!
//! Append-only by convention: no UPDATE/DELETE codepath exists. Retention
//! pruning, if it's ever needed, will be a separate periodic job.

use crate::auth::AuthUser;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sqlx::SqlitePool;
use uuid::Uuid;

/// Substrings that mark a key as carrying a secret. Comparison is
/// case-insensitive and walks every object key at any depth.
const SECRET_KEY_NEEDLES: &[&str] = &[
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth",
    "credential",
    "cookie",
    "private",
    "pkey",
    "pem_enc",
    "_enc",
];

const REDACTED: &str = "[REDACTED]";

/// Strips secret-looking values out of an arbitrary JSON tree before the
/// audit row is written. Recursive; arrays and nested objects are walked.
pub fn redact(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out: Map<String, Value> = Map::new();
            for (k, v) in map {
                let lk = k.to_ascii_lowercase();
                let is_secret = SECRET_KEY_NEEDLES.iter().any(|needle| lk.contains(needle));
                if is_secret && !matches!(v, Value::Null) {
                    out.insert(k, Value::String(REDACTED.to_string()));
                } else {
                    out.insert(k, redact(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(redact).collect()),
        other => other,
    }
}

/// Record a single audit event. Logs (rather than propagates) DB failures so
/// the wrapping handler isn't poisoned by an audit-write hiccup.
pub async fn log(
    db: &SqlitePool,
    auth: &AuthUser,
    action: &str,
    resource_type: &str,
    resource_id: Option<&str>,
    before: Option<Value>,
    after: Option<Value>,
) {
    let before_json = before.map(|v| serde_json::to_string(&redact(v)).unwrap_or_default());
    let after_json = after.map(|v| serde_json::to_string(&redact(v)).unwrap_or_default());
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    let res = sqlx::query(
        "INSERT INTO audit_log
            (id, created_at, actor_user_id, actor_username, actor_token_id,
             action, resource_type, resource_id, before_json, after_json,
             ip, user_agent, request_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&now)
    .bind(&auth.user_id)
    .bind(&auth.username)
    .bind(&auth.via_token)
    .bind(action)
    .bind(resource_type)
    .bind(resource_id)
    .bind(&before_json)
    .bind(&after_json)
    .bind(&auth.remote_ip)
    .bind(&auth.user_agent)
    .bind(&auth.request_id)
    .execute(db)
    .await;

    if let Err(e) = res {
        tracing::error!("audit log write failed: {:?}", e);
    }
}

/// Row shape we serve out of `GET /api/audit`.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct AuditRecord {
    pub id: String,
    pub created_at: String,
    pub actor_user_id: Option<String>,
    pub actor_username: Option<String>,
    pub actor_token_id: Option<String>,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub before_json: Option<String>,
    pub after_json: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_known_secret_keys() {
        let out = redact(json!({
            "username": "alice",
            "password": "hunter2",
            "api_key": "abc",
            "cf_api_token": "xyz",
        }));
        assert_eq!(out["username"], "alice");
        assert_eq!(out["password"], REDACTED);
        assert_eq!(out["api_key"], REDACTED);
        // "cf_api_token" contains both "api_key"? no — it contains "token".
        assert_eq!(out["cf_api_token"], REDACTED);
    }

    #[test]
    fn secret_key_matching_is_case_insensitive() {
        let out = redact(json!({ "Cookie_Secret": "v", "PASSWORD": "v" }));
        assert_eq!(out["Cookie_Secret"], REDACTED);
        assert_eq!(out["PASSWORD"], REDACTED);
    }

    #[test]
    fn recurses_into_nested_objects_and_arrays() {
        // NB: the array key is "rows", not "tokens" — a key containing the
        // needle "token" would itself be redacted wholesale before recursion.
        let out = redact(json!({
            "integration": { "name": "cf", "cf_api_token": "leak" },
            "rows": [{ "token": "a" }, { "token": "b" }],
        }));
        assert_eq!(out["integration"]["name"], "cf");
        assert_eq!(out["integration"]["cf_api_token"], REDACTED);
        assert_eq!(out["rows"][0]["token"], REDACTED);
        assert_eq!(out["rows"][1]["token"], REDACTED);
    }

    #[test]
    fn preserves_null_secret_values() {
        // A null secret carries no plaintext, so it's left as-is rather than
        // masked — distinguishes "unset" from "redacted" in the audit trail.
        let out = redact(json!({ "password": null, "secret": "v" }));
        assert!(out["password"].is_null());
        assert_eq!(out["secret"], REDACTED);
    }

    #[test]
    fn leaves_non_secret_scalars_untouched() {
        let out = redact(json!({ "count": 3, "enabled": true, "name": "x" }));
        assert_eq!(out["count"], 3);
        assert_eq!(out["enabled"], true);
        assert_eq!(out["name"], "x");
    }
}
