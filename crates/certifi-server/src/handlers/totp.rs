//! Self-service TOTP management — gated on identity only, no permission
//! check. Each user manages their own factor; admins do not enrol TOTP on
//! someone else's behalf.

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::services::totp;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct TotpStatus {
    /// True if the user has a row in `user_totp` (whether or not it's
    /// verified). When `enrolled && !verified`, the user is mid-enrollment.
    pub enrolled: bool,
    /// True if the factor is active — verified at least once and now
    /// required at every sign-in.
    pub verified: bool,
}

#[derive(Serialize, ToSchema)]
pub struct EnrollResponse {
    pub secret_b32: String,
    pub provisioning_uri: String,
    pub qr_png_b64: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ConfirmRequest {
    pub code: String,
}

#[utoipa::path(
    get,
    path = "/api/auth/totp",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, body = TotpStatus),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn status(State(state): State<AppState>, auth: AuthUser) -> Result<Json<TotpStatus>> {
    let (enrolled, verified) = totp::status(&state, &auth.user_id)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(TotpStatus { enrolled, verified }))
}

#[utoipa::path(
    post,
    path = "/api/auth/totp/enroll",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "New secret + QR. Factor is not active until the user \
                                       confirms a code via /api/auth/totp/confirm.",
            body = EnrollResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn enroll(State(state): State<AppState>, auth: AuthUser) -> Result<Json<EnrollResponse>> {
    let result = totp::begin_enrollment(&state, &auth.user_id, &auth.username)
        .await
        .map_err(AppError::Internal)?;
    audit::log(
        &state.db,
        &auth,
        "totp.enroll",
        "user",
        Some(&auth.user_id),
        None,
        Some(serde_json::json!({"enrolled": true, "verified": false})),
    )
    .await;
    Ok(Json(EnrollResponse {
        secret_b32: result.secret_b32,
        provisioning_uri: result.provisioning_uri,
        qr_png_b64: result.qr_png_b64,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/totp/confirm",
    tag = "auth",
    security(("bearer" = [])),
    request_body = ConfirmRequest,
    responses(
        (status = 200, description = "Factor activated.", body = crate::openapi::OkResponse),
        (status = 400, description = "Wrong code or no enrollment in progress.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn confirm(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<ConfirmRequest>,
) -> Result<Json<serde_json::Value>> {
    totp::confirm_enrollment(&state, &auth.user_id, &req.code)
        .await
        .map_err(|e| AppError::BadRequest(e.to_string()))?;
    audit::log(
        &state.db,
        &auth,
        "totp.confirm",
        "user",
        Some(&auth.user_id),
        None,
        Some(serde_json::json!({"verified": true})),
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(
    delete,
    path = "/api/auth/totp",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Factor disabled.", body = crate::openapi::OkResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn disable(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>> {
    totp::disable(&state, &auth.user_id)
        .await
        .map_err(AppError::Internal)?;
    audit::log(
        &state.db,
        &auth,
        "totp.disable",
        "user",
        Some(&auth.user_id),
        Some(serde_json::json!({"verified": true})),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}
