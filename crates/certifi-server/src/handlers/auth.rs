use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::models::User;
use crate::rbac;
use crate::services::sessions;
use crate::AppState;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use axum::extract::State;
use axum::http::header;
use axum::http::HeaderValue;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

/// Body of the two-step TOTP completion (`POST /api/auth/login/totp`).
#[derive(Deserialize, ToSchema)]
pub struct LoginTotpRequest {
    pub challenge_id: String,
    pub code: String,
}

/// Successful sign-in. `token` carries the same value as the `session=`
/// cookie — clients that can't deal with cookies can send it in
/// `Authorization: Bearer <token>` instead.
#[derive(Serialize, ToSchema)]
pub struct LoginResponse {
    pub token: String,
    pub user: UserInfo,
}

/// When the user has a verified TOTP factor, the password step returns this
/// shape instead of a `LoginResponse`. The client posts the OTP back in a
/// second request, identified by `challenge_id`.
#[derive(Serialize, ToSchema)]
pub struct TotpChallenge {
    pub stage: String,
    pub challenge_id: String,
}

/// One-of: `LoginResponse` on direct sign-in OR `TotpChallenge` when MFA
/// is required. We serialize the variants inline (untagged) so the SPA can
/// branch on the presence of `stage`.
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum LoginOutcome {
    Ok(LoginResponse),
    Mfa(TotpChallenge),
}

#[derive(Serialize, ToSchema)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    /// True iff the user holds the SuperAdmin role. Kept for backwards
    /// compatibility with web UI that pre-dates the permission system; new
    /// UI affordances should branch on `permissions` instead.
    pub is_admin: bool,
    /// Flattened permission set across all of the user's role assignments.
    pub permissions: Vec<String>,
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login succeeded — either with a session right away \
                                       (LoginResponse) or with a TOTP challenge the client \
                                       must complete via POST /api/auth/login/totp.",
            body = LoginOutcome),
        (status = 400, description = "Missing credentials, or username/password mismatch.",
            body = crate::openapi::ErrorBody),
    ),
)]
pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Response> {
    if req.username.is_empty() || req.password.is_empty() {
        return Err(AppError::BadRequest(
            "Username and password required".into(),
        ));
    }

    let bad = || AppError::BadRequest("Invalid username or password".into());

    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?")
        .bind(&req.username)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(bad)?;

    let parsed_hash = PasswordHash::new(&user.password_hash).map_err(|_| bad())?;
    Argon2::default()
        .verify_password(req.password.as_bytes(), &parsed_hash)
        .map_err(|_| bad())?;

    // Branch on TOTP enrollment. A user with a verified TOTP gets a
    // challenge instead of a session.
    let totp_verified: bool = sqlx::query_scalar(
        "SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND verified_at IS NOT NULL",
    )
    .bind(&user.id)
    .fetch_one(&state.db)
    .await
    .map(|n: i64| n > 0)?;

    if totp_verified {
        let challenge_id = Uuid::new_v4().to_string();
        let now = Utc::now();
        let expires = (now + Duration::minutes(5)).to_rfc3339();
        sqlx::query(
            "INSERT INTO login_challenges (id, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(&challenge_id)
        .bind(&user.id)
        .bind(now.to_rfc3339())
        .bind(&expires)
        .execute(&state.db)
        .await?;
        return Ok(Json(LoginOutcome::Mfa(TotpChallenge {
            stage: "totp_required".into(),
            challenge_id,
        }))
        .into_response());
    }

    issue_session_response(&state, user).await
}

#[utoipa::path(
    post,
    path = "/api/auth/login/totp",
    tag = "auth",
    request_body = LoginTotpRequest,
    responses(
        (status = 200, description = "TOTP verified; session issued.", body = LoginResponse),
        (status = 400, description = "Invalid / expired challenge or wrong code.",
            body = crate::openapi::ErrorBody),
    ),
)]
pub async fn login_totp(
    State(state): State<AppState>,
    Json(req): Json<LoginTotpRequest>,
) -> Result<Response> {
    // Reads + deletes the challenge so a single OTP can't be re-used.
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT user_id, expires_at FROM login_challenges WHERE id = ?")
            .bind(&req.challenge_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((user_id, expires_at)) = row else {
        return Err(AppError::BadRequest("Unknown or expired challenge".into()));
    };
    let _ = sqlx::query("DELETE FROM login_challenges WHERE id = ?")
        .bind(&req.challenge_id)
        .execute(&state.db)
        .await;

    let expired = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map(|dt| dt.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true);
    if expired {
        return Err(AppError::BadRequest("Challenge expired".into()));
    }

    crate::services::totp::verify_user_code(&state, &user_id, &req.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;

    let user: User = sqlx::query_as("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_one(&state.db)
        .await?;

    issue_session_response(&state, user).await
}

/// Common tail of both login paths — mint a session, set the cookie, and
/// hydrate the SPA with permissions + is_admin.
async fn issue_session_response(state: &AppState, user: User) -> Result<Response> {
    let session_id = sessions::create(&state.db, &user.id, None, None, None)
        .await
        .map_err(AppError::Internal)?;
    let permissions = rbac::load_user_permissions(&state.db, &user.id).await?;
    let is_admin = rbac::is_super_admin(&state.db, &user.id).await?;

    let body = Json(LoginOutcome::Ok(LoginResponse {
        token: session_id.clone(),
        user: UserInfo {
            id: user.id,
            username: user.username,
            is_admin,
            permissions: permissions.into_iter().collect(),
        },
    }));

    let mut resp = body.into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::cookie_for(&session_id)).unwrap(),
    );
    Ok(resp)
}

#[utoipa::path(
    post,
    path = "/api/auth/logout",
    tag = "auth",
    responses(
        (status = 200, description = "Session destroyed and cookie cleared. \
            If the session was minted via OIDC and the IdP advertised an \
            end_session_endpoint, the response also carries a `logout_url` \
            the SPA should navigate to so the user lands on the IdP's \
            signed-out screen instead of being silently re-authenticated.",
            body = crate::openapi::OkResponse),
    ),
)]
pub async fn logout(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    // Pull the session id from either the cookie or the Authorization header.
    let cookie = headers
        .get("Cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let cookie_id = cookie
        .split(';')
        .map(str::trim)
        .find_map(|p| p.strip_prefix("session=").map(str::to_string));
    let bearer = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer ").map(str::to_string));

    // If this is an OIDC-minted session, pull the id_token + end-session
    // URL we stored at sign-in time BEFORE destroying the row, so we can
    // hand the SPA an RP-initiated-logout URL on the way out.
    let mut logout_url: Option<String> = None;
    if let Some(id) = cookie_id.or(bearer) {
        if !id.is_empty() && !id.starts_with("dapi_") {
            if let Ok(Some((id_token, end_session))) =
                sessions::oidc_logout_info(&state.db, &id).await
            {
                logout_url = Some(build_rp_logout_url(&end_session, &id_token, &state).await);
            }
            let _ = sessions::destroy(&state.db, &id).await;
        }
    }

    let body = if let Some(u) = logout_url {
        serde_json::json!({"ok": true, "logout_url": u})
    } else {
        serde_json::json!({"ok": true})
    };
    let mut resp = Json(body).into_response();
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::clear_cookie()).unwrap(),
    );
    resp
}

/// Build an OpenID Connect RP-initiated-logout URL — `end_session_endpoint`
/// plus `id_token_hint` and `client_id` query params. We deliberately omit
/// `post_logout_redirect_uri`: most IdPs require pre-registration of that
/// URI, and Authentik (the IdP in the screenshot) renders a perfectly good
/// signed-out screen when no redirect target is provided. Operators who
/// want a "Log back in" button on the IdP page can add one later by
/// registering a URI on the provider side.
async fn build_rp_logout_url(end_session: &str, id_token: &str, state: &AppState) -> String {
    let client_id = crate::services::oidc::OidcSettings::load(state)
        .await
        .ok()
        .flatten()
        .map(|s| s.client_id)
        .unwrap_or_default();

    match url::Url::parse(end_session) {
        Ok(mut u) => {
            {
                let mut q = u.query_pairs_mut();
                q.append_pair("id_token_hint", id_token);
                if !client_id.is_empty() {
                    q.append_pair("client_id", &client_id);
                }
            }
            u.to_string()
        }
        // Stored URL is malformed for some reason — return as-is so the
        // SPA at least lands on the IdP's logout page (no hint).
        Err(_) => end_session.to_string(),
    }
}

#[utoipa::path(
    get,
    path = "/api/auth/me",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Authenticated user info.", body = UserInfo),
        (status = 401, description = "No or invalid credentials.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn me(auth: AuthUser) -> Result<Json<UserInfo>> {
    let mut permissions: Vec<String> = auth.permissions.iter().cloned().collect();
    permissions.sort();
    Ok(Json(UserInfo {
        id: auth.user_id,
        username: auth.username,
        is_admin: auth.is_admin,
        permissions,
    }))
}
