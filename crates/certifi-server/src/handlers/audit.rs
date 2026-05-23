//! `GET /api/audit` — query the audit log.

use crate::audit::AuditRecord;
use crate::auth::AuthUser;
use crate::error::Result;
use crate::rbac::perms;
use crate::AppState;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct AuditQuery {
    /// Filter by actor user_id.
    #[serde(default)]
    pub actor_user_id: Option<String>,
    /// Filter by exact action key (`certificate.create`, `role.assign`, …).
    #[serde(default)]
    pub action: Option<String>,
    /// Filter by `resource_type` (e.g. `certificate`).
    #[serde(default)]
    pub resource_type: Option<String>,
    /// Filter by `resource_id`.
    #[serde(default)]
    pub resource_id: Option<String>,
    /// Page size; defaults to 100, capped at 500.
    #[serde(default)]
    pub limit: Option<i64>,
    /// Pagination cursor — pass the `created_at` of the last row from the
    /// previous page to fetch the next page (ordered desc).
    #[serde(default)]
    pub before: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/audit",
    tag = "audit",
    security(("bearer" = [])),
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit records, newest first. Secrets in `before_json` / \
                                       `after_json` are masked as `[REDACTED]`.",
            body = [AuditRecord]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `audit.read`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(q): Query<AuditQuery>,
) -> Result<Json<Vec<AuditRecord>>> {
    auth.require(perms::AUDIT_READ)?;

    let limit = q.limit.unwrap_or(100).clamp(1, 500);

    // We compose the SQL piecewise rather than using a single big query —
    // sqlx doesn't bind variadic predicates without procedural macros, and
    // this stays readable.
    let mut sql = String::from(
        "SELECT id, created_at, actor_user_id, actor_username, actor_token_id, \
                action, resource_type, resource_id, before_json, after_json, \
                ip, user_agent, request_id \
         FROM audit_log WHERE 1=1",
    );
    if q.actor_user_id.is_some() {
        sql.push_str(" AND actor_user_id = ?");
    }
    if q.action.is_some() {
        sql.push_str(" AND action = ?");
    }
    if q.resource_type.is_some() {
        sql.push_str(" AND resource_type = ?");
    }
    if q.resource_id.is_some() {
        sql.push_str(" AND resource_id = ?");
    }
    if q.before.is_some() {
        sql.push_str(" AND created_at < ?");
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");

    let mut query = sqlx::query_as::<_, AuditRecord>(&sql);
    if let Some(v) = &q.actor_user_id {
        query = query.bind(v);
    }
    if let Some(v) = &q.action {
        query = query.bind(v);
    }
    if let Some(v) = &q.resource_type {
        query = query.bind(v);
    }
    if let Some(v) = &q.resource_id {
        query = query.bind(v);
    }
    if let Some(v) = &q.before {
        query = query.bind(v);
    }
    let rows = query.bind(limit).fetch_all(&state.db).await?;

    Ok(Json(rows))
}
