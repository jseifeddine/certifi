use crate::audit;
use crate::auth::{generate_api_token, hash_token, AuthUser};
use crate::error::{AppError, Result};
use crate::models::ApiToken;
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub name: String,
    pub expires_at: Option<String>,
    /// Optional permission ceiling for the new token. When omitted (or
    /// null), the token inherits the issuer's current permissions at every
    /// request. When supplied, every key must be one the issuing user
    /// currently holds — preventing privilege-escalation via tokens.
    #[serde(default)]
    pub permissions: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct TokenCreatedResponse {
    pub id: String,
    pub name: String,
    pub token: String,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub permissions: Option<Vec<String>>,
}

#[derive(Serialize, ToSchema)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub expires_at: Option<String>,
    /// `None` ⇒ token inherits the issuer's permissions. `Some([...])` ⇒ the
    /// listed keys are the token's ceiling.
    pub permissions: Option<Vec<String>>,
}

impl From<ApiToken> for TokenView {
    fn from(t: ApiToken) -> Self {
        let permissions = t
            .permissions
            .as_deref()
            .and_then(|s| serde_json::from_str::<Vec<String>>(s).ok());
        TokenView {
            id: t.id,
            name: t.name,
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            permissions,
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/tokens",
    tag = "tokens",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "API tokens belonging to the authenticated user. \
                                       The token hash is never returned.",
            body = [TokenView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<Vec<TokenView>>> {
    let tokens = sqlx::query_as::<_, ApiToken>(
        "SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at DESC",
    )
    .bind(&auth.user_id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(tokens.into_iter().map(TokenView::from).collect()))
}

#[utoipa::path(
    post,
    path = "/api/tokens",
    tag = "tokens",
    security(("bearer" = [])),
    request_body = CreateTokenRequest,
    responses(
        (status = 200, description = "Token created. The plaintext `token` is returned **only \
                                       once** — only its SHA-256 hash is persisted. Store it \
                                       immediately.",
            body = TokenCreatedResponse),
        (status = 400, description = "Empty `name`.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Json<TokenCreatedResponse>> {
    if req.name.is_empty() {
        return Err(AppError::BadRequest("Token name required".into()));
    }

    // Validate the optional permission list: every key must already be held
    // by the issuing user (global scope). Closes the path "I can't do X, but
    // I mint a token that says it can do X and use that".
    if let Some(perms) = &req.permissions {
        for p in perms {
            if !auth.has(p) {
                return Err(AppError::BadRequest(format!(
                    "You can't grant '{}' to a token because you don't hold it yourself",
                    p
                )));
            }
        }
    }
    let permissions_json = req
        .permissions
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "[]".into()));

    let token = generate_api_token();
    let hash = hash_token(&token);
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at, expires_at, permissions)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&auth.user_id)
    .bind(&req.name)
    .bind(&hash)
    .bind(&now)
    .bind(&req.expires_at)
    .bind(&permissions_json)
    .execute(&state.db)
    .await?;

    audit::log(
        &state.db,
        &auth,
        "token.create",
        "token",
        Some(&id),
        None,
        Some(serde_json::json!({
            "name": &req.name,
            "permissions": &req.permissions,
            "expires_at": &req.expires_at,
        })),
    )
    .await;

    Ok(Json(TokenCreatedResponse {
        id,
        name: req.name,
        token,
        created_at: now,
        expires_at: req.expires_at,
        permissions: req.permissions,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/tokens/{id}",
    tag = "tokens",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Token UUID.")),
    responses(
        (status = 200, description = "Token revoked.", body = crate::openapi::OkResponse),
        (status = 404, description = "No such token belonging to the authenticated user.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    let affected = sqlx::query("DELETE FROM api_tokens WHERE id = ? AND user_id = ?")
        .bind(&id)
        .bind(&auth.user_id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("Token not found".into()));
    }

    audit::log(
        &state.db,
        &auth,
        "token.delete",
        "token",
        Some(&id),
        None,
        None,
    )
    .await;

    Ok(Json(serde_json::json!({"ok": true})))
}
