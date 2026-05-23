use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::models::User;
use crate::rbac::{self, perms};
use crate::AppState;
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher};
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub is_admin: Option<bool>,
    pub email: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub is_admin: bool,
    pub email: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<User> for UserView {
    fn from(u: User) -> Self {
        UserView {
            id: u.id,
            username: u.username,
            is_admin: u.is_admin,
            email: u.email,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "users",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "All users. Password hashes are never returned.",
            body = [UserView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<UserView>>> {
    auth.require(perms::USER_LIST)?;
    let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(&state.db)
        .await?;

    // Derive is_admin from role_assignments rather than the legacy users.is_admin
    // column. OIDC sync grants/revokes SuperAdmin by writing to role_assignments
    // only — the column stays at 0 for OIDC-provisioned admins, which made the
    // list show them with the "user" badge despite full SuperAdmin perms.
    let admin_rows: Vec<(String,)> = sqlx::query_as(
        "SELECT user_id FROM role_assignments WHERE role_id = ? AND scope = 'global'",
    )
    .bind(crate::rbac::system_roles::SUPER_ADMIN)
    .fetch_all(&state.db)
    .await?;
    let admins: std::collections::HashSet<String> =
        admin_rows.into_iter().map(|(id,)| id).collect();

    let views: Vec<UserView> = users
        .into_iter()
        .map(|u| {
            let is_admin = admins.contains(&u.id);
            let mut v = UserView::from(u);
            v.is_admin = is_admin;
            v
        })
        .collect();
    Ok(Json(views))
}

#[utoipa::path(
    post,
    path = "/api/users",
    tag = "users",
    security(("bearer" = [])),
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created.", body = UserView),
        (status = 400, description = "Missing username, or password shorter than 8 chars.",
            body = crate::openapi::ErrorBody),
        (status = 409, description = "Username already taken.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserView>> {
    auth.require(perms::USER_CREATE)?;
    if req.username.is_empty() || req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Username required, password must be at least 8 characters".into(),
        ));
    }

    let email = req
        .email
        .as_deref()
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .map(|e| e.to_string());

    let hash = hash_password(&req.password)?;
    let now = Utc::now().to_rfc3339();
    let id = Uuid::new_v4().to_string();
    let is_admin = req.is_admin.unwrap_or(false);

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin, email, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.username)
    .bind(&hash)
    .bind(is_admin)
    .bind(&email)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE") {
            AppError::Conflict("Username already exists".into())
        } else {
            AppError::Database(e)
        }
    })?;

    // Materialise the user's RBAC view: SuperAdmin if is_admin was checked
    // at creation, else Operator. Without this the newly-created user has
    // zero permissions and gets `Forbidden` on every page.
    rbac::set_user_admin_status(&state.db, &id, is_admin, Some(&auth.user_id))
        .await
        .map_err(AppError::Database)?;

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;

    audit::log(
        &state.db, &auth, "user.create", "user", Some(&user.id),
        None,
        Some(serde_json::json!({"username": &user.username, "is_admin": is_admin, "email": &user.email})),
    ).await;

    Ok(Json(user_view_with_derived_admin(&state, user).await?))
}

#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "users",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "User UUID.")),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated.", body = UserView),
        (status = 400, description = "No fields to update.", body = crate::openapi::ErrorBody),
        (status = 404, description = "No user with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserView>> {
    auth.require(perms::USER_UPDATE)?;
    let now = Utc::now().to_rfc3339();
    let mut sets: Vec<String> = Vec::new();

    if req.email.is_some() {
        sets.push("email = ?".into());
    }
    if req.is_admin.is_some() {
        sets.push("is_admin = ?".into());
    }
    sets.push("updated_at = ?".into());

    if sets.len() == 1 {
        return Err(AppError::BadRequest("No fields to update".into()));
    }

    let sql = format!("UPDATE users SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql);

    if let Some(email) = &req.email {
        let trimmed = email.trim();
        q = q.bind(if trimmed.is_empty() {
            None::<String>
        } else {
            Some(trimmed.to_string())
        });
    }
    if let Some(is_admin) = req.is_admin {
        q = q.bind(is_admin);
    }

    let affected = q
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("User not found".into()));
    }

    // Keep role assignments in sync with the legacy `is_admin` flag.
    // Without this, ticking "Admin privileges" in the UI flipped the column
    // but the user kept their old role set (and could end up with neither
    // SuperAdmin nor Operator — silent lockout).
    if let Some(is_admin) = req.is_admin {
        rbac::set_user_admin_status(&state.db, &id, is_admin, Some(&auth.user_id))
            .await
            .map_err(AppError::Database)?;
    }

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;

    audit::log(
        &state.db,
        &auth,
        "user.update",
        "user",
        Some(&user.id),
        None,
        Some(serde_json::json!({"email": &user.email, "is_admin": user.is_admin})),
    )
    .await;

    Ok(Json(user_view_with_derived_admin(&state, user).await?))
}

/// Build a `UserView` whose `is_admin` reflects whether the user actually
/// holds the SuperAdmin role at global scope right now, regardless of what
/// the legacy `users.is_admin` column says. OIDC-provisioned admins never
/// flip the column — they only land in `role_assignments` — so reading
/// the column would mis-label them.
async fn user_view_with_derived_admin(state: &AppState, user: User) -> Result<UserView> {
    let is_admin = rbac::is_super_admin(&state.db, &user.id).await?;
    let mut v = UserView::from(user);
    v.is_admin = is_admin;
    Ok(v)
}

#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "users",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "User UUID.")),
    responses(
        (status = 200, description = "User removed.", body = crate::openapi::OkResponse),
        (status = 400, description = "Cannot delete your own account.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No user with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::USER_DELETE)?;
    if id == auth.user_id {
        return Err(AppError::BadRequest(
            "Cannot delete your own account".into(),
        ));
    }

    let affected = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("User not found".into()));
    }

    audit::log(
        &state.db,
        &auth,
        "user.delete",
        "user",
        Some(&id),
        None,
        None,
    )
    .await;

    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(
    put,
    path = "/api/users/{id}/password",
    tag = "users",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "User UUID.")),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed.", body = crate::openapi::OkResponse),
        (status = 400, description = "Password shorter than 8 chars.",
            body = crate::openapi::ErrorBody),
        (status = 403, description = "Non-admin trying to change someone else's password.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No user with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn change_password(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<serde_json::Value>> {
    // Self-service: always allowed.
    // Cross-user: requires `user.password.update`.
    if id != auth.user_id {
        auth.require(perms::USER_PASSWORD_UPDATE)?;
    }

    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters".into(),
        ));
    }

    let hash = hash_password(&req.new_password)?;
    let now = Utc::now().to_rfc3339();

    let affected = sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
        .bind(&hash)
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("User not found".into()));
    }

    audit::log(
        &state.db,
        &auth,
        "user.password.change",
        "user",
        Some(&id),
        None,
        None,
    )
    .await;

    Ok(Json(serde_json::json!({"ok": true})))
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Password hash error: {}", e)))?
        .to_string();
    Ok(hash)
}
