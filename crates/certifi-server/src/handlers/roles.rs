//! Roles, permissions, and role-assignment endpoints.
//!
//! Phase 1 surface: enough to list the registry, inspect what a user holds,
//! grant a role, and revoke an assignment. Custom-role creation
//! (`POST /api/roles`) is wired but limited to the permission-keys the calling
//! user holds — a SuperAdmin can mint anything; an Operator with `role.create`
//! couldn't grant `user.delete` to a custom role because they don't hold it
//! themselves.

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::rbac::{self, perms};
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct PermissionView {
    pub key: String,
    pub description: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RoleView {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub permissions: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct RoleAssignmentView {
    pub id: String,
    pub role_id: String,
    pub role_name: String,
    pub scope: String,
    pub granted_by: Option<String>,
    pub granted_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub role_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}
fn default_scope() -> String {
    "global".to_string()
}

// ── Permissions registry ─────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/permissions",
    tag = "roles",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "All permission keys known to this binary.",
            body = [PermissionView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.list`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list_permissions(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<PermissionView>>> {
    auth.require(perms::ROLE_LIST)?;
    let rows: Vec<(String, Option<String>)> =
        sqlx::query_as("SELECT key, description FROM permissions ORDER BY key")
            .fetch_all(&state.db)
            .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(key, description)| PermissionView { key, description })
            .collect(),
    ))
}

// ── Roles ────────────────────────────────────────────────────────────────────

async fn role_permissions(state: &AppState, role_id: &str) -> Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT permission_key FROM role_permissions WHERE role_id = ? ORDER BY permission_key",
    )
    .bind(role_id)
    .fetch_all(&state.db)
    .await?;
    Ok(rows.into_iter().map(|(k,)| k).collect())
}

#[utoipa::path(
    get,
    path = "/api/roles",
    tag = "roles",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "All roles (system + custom) with their permission lists.",
            body = [RoleView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.list`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list_roles(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<RoleView>>> {
    auth.require(perms::ROLE_LIST)?;
    let rows: Vec<(String, String, Option<String>, i64)> = sqlx::query_as(
        "SELECT id, name, description, is_system FROM roles ORDER BY is_system DESC, name",
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, name, description, is_system) in rows {
        let permissions = role_permissions(&state, &id).await?;
        out.push(RoleView {
            id,
            name,
            description,
            is_system: is_system != 0,
            permissions,
        });
    }
    Ok(Json(out))
}

#[utoipa::path(
    post,
    path = "/api/roles",
    tag = "roles",
    security(("bearer" = [])),
    request_body = CreateRoleRequest,
    responses(
        (status = 200, description = "Custom role created.", body = RoleView),
        (status = 400, description = "Empty name, unknown permission key, or attempt to grant \
                                       a permission the caller does not hold.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.create`.", body = crate::openapi::ErrorBody),
        (status = 409, description = "Role name already in use.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<RoleView>> {
    auth.require(perms::ROLE_CREATE)?;
    let name = req.name.trim().to_string();
    if name.is_empty() {
        return Err(AppError::BadRequest("Role name required".into()));
    }

    // Validate every requested permission exists and is held by the caller.
    // SuperAdmin trivially passes both checks (it holds everything).
    for key in &req.permissions {
        let known: Option<(String,)> = sqlx::query_as("SELECT key FROM permissions WHERE key = ?")
            .bind(key)
            .fetch_optional(&state.db)
            .await?;
        if known.is_none() {
            return Err(AppError::BadRequest(format!(
                "Unknown permission '{}'",
                key
            )));
        }
        if !auth.has(key) {
            return Err(AppError::BadRequest(format!(
                "You cannot grant permission '{}' because you don't hold it",
                key
            )));
        }
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO roles (id, name, description, is_system, created_at, updated_at)
         VALUES (?, ?, ?, 0, ?, ?)",
    )
    .bind(&id)
    .bind(&name)
    .bind(&req.description)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::Conflict("Role name already exists".into())
        } else {
            AppError::Database(e)
        }
    })?;

    for key in &req.permissions {
        sqlx::query("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)")
            .bind(&id)
            .bind(key)
            .execute(&state.db)
            .await?;
    }

    audit::log(
        &state.db,
        &auth,
        "role.create",
        "role",
        Some(&id),
        None,
        Some(serde_json::json!({
            "name": name,
            "description": req.description,
            "permissions": req.permissions,
        })),
    )
    .await;

    Ok(Json(RoleView {
        id,
        name,
        description: req.description,
        is_system: false,
        permissions: req.permissions,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/roles/{id}",
    tag = "roles",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Role id.")),
    responses(
        (status = 200, description = "Role deleted.", body = crate::openapi::OkResponse),
        (status = 400, description = "Cannot delete a system role.", body = crate::openapi::ErrorBody),
        (status = 404, description = "No role with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.delete`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::ROLE_DELETE)?;
    let row: Option<(i64,)> = sqlx::query_as("SELECT is_system FROM roles WHERE id = ?")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    let Some((is_system,)) = row else {
        return Err(AppError::NotFound("Role not found".into()));
    };
    if is_system != 0 {
        return Err(AppError::BadRequest(
            "System roles cannot be deleted".into(),
        ));
    }
    sqlx::query("DELETE FROM roles WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    audit::log(
        &state.db,
        &auth,
        "role.delete",
        "role",
        Some(&id),
        None,
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Role assignments ─────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/users/{id}/roles",
    tag = "roles",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "User id.")),
    responses(
        (status = 200, description = "All role assignments held by the user.",
            body = [RoleAssignmentView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.list`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list_user_assignments(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<RoleAssignmentView>>> {
    auth.require(perms::ROLE_LIST)?;
    let rows: Vec<(String, String, String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT ra.id, ra.role_id, r.name, ra.scope, ra.granted_by, ra.granted_at
         FROM role_assignments ra
         JOIN roles r ON r.id = ra.role_id
         WHERE ra.user_id = ?
         ORDER BY ra.granted_at",
    )
    .bind(&user_id)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(
                |(id, role_id, role_name, scope, granted_by, granted_at)| RoleAssignmentView {
                    id,
                    role_id,
                    role_name,
                    scope,
                    granted_by,
                    granted_at,
                },
            )
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/users/{id}/roles",
    tag = "roles",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "User id.")),
    request_body = AssignRoleRequest,
    responses(
        (status = 200, description = "Assignment created (or already existed).",
            body = RoleAssignmentView),
        (status = 400, description = "Unknown role id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.assign`.", body = crate::openapi::ErrorBody),
        (status = 404, description = "User not found.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn assign_role(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(user_id): Path<String>,
    Json(req): Json<AssignRoleRequest>,
) -> Result<Json<RoleAssignmentView>> {
    auth.require(perms::ROLE_ASSIGN)?;

    // Validate the scope string. Accepted forms (phase 2):
    //   "global"          — applies everywhere
    //   "zone:<fqdn>"     — only for cert ops whose CN/SANs fall under <fqdn>
    let scope = req.scope.trim();
    if scope != "global" {
        let zone = scope
            .strip_prefix("zone:")
            .ok_or_else(|| AppError::BadRequest("scope must be 'global' or 'zone:<fqdn>'".into()))?
            .trim()
            .trim_end_matches('.');
        if zone.is_empty() || !zone.contains('.') {
            return Err(AppError::BadRequest(
                "zone scope must include a fully-qualified domain (e.g. zone:example.com)".into(),
            ));
        }
    }

    // Confirm both the user and the role exist before inserting.
    let user_row: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&state.db)
        .await?;
    if user_row.is_none() {
        return Err(AppError::NotFound("User not found".into()));
    }

    let role_row: Option<(String,)> = sqlx::query_as("SELECT name FROM roles WHERE id = ?")
        .bind(&req.role_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((role_name,)) = role_row else {
        return Err(AppError::BadRequest("Unknown role".into()));
    };

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    // ON CONFLICT clause makes this idempotent: re-assigning is a no-op,
    // we still return the existing row.
    sqlx::query(
        "INSERT INTO role_assignments
            (id, user_id, role_id, scope, granted_by, granted_at)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(user_id, role_id, scope) DO NOTHING",
    )
    .bind(&id)
    .bind(&user_id)
    .bind(&req.role_id)
    .bind(&req.scope)
    .bind(&auth.user_id)
    .bind(&now)
    .execute(&state.db)
    .await?;

    // Re-read whatever the canonical row is (existed before us, or just inserted).
    let row: (String, String, String, Option<String>, String) = sqlx::query_as(
        "SELECT id, role_id, scope, granted_by, granted_at
         FROM role_assignments
         WHERE user_id = ? AND role_id = ? AND scope = ?",
    )
    .bind(&user_id)
    .bind(&req.role_id)
    .bind(&req.scope)
    .fetch_one(&state.db)
    .await?;
    let (assignment_id, role_id, scope, granted_by, granted_at) = row;

    audit::log(
        &state.db,
        &auth,
        "role.assign",
        "user",
        Some(&user_id),
        None,
        Some(serde_json::json!({
            "role_id": role_id,
            "scope": scope,
        })),
    )
    .await;

    Ok(Json(RoleAssignmentView {
        id: assignment_id,
        role_id,
        role_name,
        scope,
        granted_by,
        granted_at,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/roles/{assignment_id}",
    tag = "roles",
    security(("bearer" = [])),
    params(
        ("user_id" = String, Path, description = "User id."),
        ("assignment_id" = String, Path, description = "Role assignment id."),
    ),
    responses(
        (status = 200, description = "Assignment removed.", body = crate::openapi::OkResponse),
        (status = 400, description = "Cannot revoke your own last SuperAdmin assignment.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "Assignment not found.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.assign`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn revoke_assignment(
    State(state): State<AppState>,
    auth: AuthUser,
    Path((user_id, assignment_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::ROLE_ASSIGN)?;

    // Read the assignment first so we can guard against locking out the
    // last SuperAdmin or the caller's own SuperAdmin role.
    let row: Option<(String,)> =
        sqlx::query_as("SELECT role_id FROM role_assignments WHERE id = ? AND user_id = ?")
            .bind(&assignment_id)
            .bind(&user_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((role_id,)) = row else {
        return Err(AppError::NotFound("Assignment not found".into()));
    };

    if role_id == rbac::system_roles::SUPER_ADMIN {
        let (count,): (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM role_assignments WHERE role_id = ?")
                .bind(rbac::system_roles::SUPER_ADMIN)
                .fetch_one(&state.db)
                .await?;
        if count <= 1 {
            return Err(AppError::BadRequest(
                "Refusing to revoke the only remaining SuperAdmin assignment".into(),
            ));
        }
        if user_id == auth.user_id {
            return Err(AppError::BadRequest(
                "Refusing to revoke your own SuperAdmin role — ask another admin".into(),
            ));
        }
    }

    sqlx::query("DELETE FROM role_assignments WHERE id = ? AND user_id = ?")
        .bind(&assignment_id)
        .bind(&user_id)
        .execute(&state.db)
        .await?;

    audit::log(
        &state.db,
        &auth,
        "role.revoke",
        "user",
        Some(&user_id),
        Some(serde_json::json!({"role_id": role_id})),
        None,
    )
    .await;

    Ok(Json(serde_json::json!({"ok": true})))
}
