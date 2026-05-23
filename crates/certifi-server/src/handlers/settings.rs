use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::models::*;
use crate::rbac::perms;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct SettingsResponse {
    // ACME
    pub acme_ca: String,
    pub acme_registered: bool,
    pub acme_account_url: String,
    pub key_algo: String,
    /// Setting keys whose values are locked by an environment variable.
    /// The UI renders these fields as read-only; the API rejects writes to them.
    pub locked: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateSettingsRequest {
    pub acme_ca: Option<String>,
    pub key_algo: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/settings",
    tag = "settings",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Current ACME + key-algorithm settings. `locked` lists \
                                       keys whose values come from an environment variable and \
                                       cannot be changed via the API.",
            body = SettingsResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn get_settings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<SettingsResponse>> {
    auth.require(perms::SETTINGS_READ)?;
    let map = load_all_settings(&state).await?;
    let locked: Vec<String> = state
        .config
        .locked_keys()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let account_url = map.get(S_ACME_ACCOUNT_URL).cloned().unwrap_or_default();

    Ok(Json(SettingsResponse {
        acme_ca: map
            .get(S_ACME_CA)
            .cloned()
            .unwrap_or_else(|| ACME_LE_PROD.to_string()),
        acme_registered: !account_url.is_empty(),
        acme_account_url: account_url,
        key_algo: map
            .get(S_KEY_ALGO)
            .cloned()
            .unwrap_or_else(|| "ec-p384".to_string()),
        locked,
    }))
}

#[utoipa::path(
    put,
    path = "/api/settings",
    tag = "settings",
    security(("bearer" = [])),
    request_body = UpdateSettingsRequest,
    responses(
        (status = 200, description = "Settings updated.", body = crate::openapi::OkResponse),
        (status = 400, description = "Attempted to update a setting locked by an environment \
                                       variable.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn update_settings(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::SETTINGS_UPDATE)?;
    let now = Utc::now().to_rfc3339();
    let locked = state.config.locked_keys();
    let mut updates: Vec<(String, String)> = Vec::new();

    macro_rules! push {
        ($opt:expr, $key:expr) => {
            if let Some(v) = $opt {
                if locked.contains(&$key) {
                    return Err(AppError::BadRequest(format!(
                        "Setting '{}' is locked by an environment variable and cannot be changed via the API",
                        $key
                    )));
                }
                updates.push(($key.to_string(), v));
            }
        };
    }

    push!(req.acme_ca, S_ACME_CA);
    push!(req.key_algo, S_KEY_ALGO);

    let summary: Vec<String> = updates.iter().map(|(k, _)| k.clone()).collect();
    audit::log(
        &state.db,
        &auth,
        "settings.update",
        "settings",
        None,
        None,
        Some(serde_json::json!({"keys": summary})),
    )
    .await;

    for (key, value) in updates {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(&key)
        .bind(&value)
        .bind(&now)
        .execute(&state.db)
        .await?;
    }

    Ok(Json(serde_json::json!({"ok": true})))
}

/// Re-register ACME account (or register for the first time).
#[utoipa::path(
    post,
    path = "/api/settings/acme/register",
    tag = "settings",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "ACME account registered. The new account URL is stored \
                                       in settings and returned in the body.",
            body = crate::openapi::AcmeRegisterResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
        (status = 500, description = "ACME directory unreachable or registration rejected.",
            body = crate::openapi::ErrorBody),
    ),
)]
pub async fn register_acme(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::SETTINGS_ACME_REGISTER)?;
    let map = load_all_settings(&state).await?;
    let ca_url = map
        .get(S_ACME_CA)
        .cloned()
        .unwrap_or_else(|| ACME_LE_PROD.to_string());

    let (_, creds) = crate::services::acme::AcmeClient::register(&ca_url)
        .await
        .map_err(crate::error::AppError::Internal)?;

    let now = Utc::now().to_rfc3339();
    for (key, value) in [
        (S_ACME_ACCOUNT_KEY, creds.key_pkcs8_b64.clone()),
        (S_ACME_ACCOUNT_URL, creds.account_url.clone()),
    ] {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(value)
        .bind(&now)
        .execute(&state.db)
        .await?;
    }

    tracing::info!("ACME account registered: {}", creds.account_url);
    audit::log(
        &state.db,
        &auth,
        "settings.acme.register",
        "settings",
        None,
        None,
        Some(serde_json::json!({"account_url": &creds.account_url})),
    )
    .await;
    Ok(Json(
        serde_json::json!({"ok": true, "account_url": creds.account_url}),
    ))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Load all settings from the DB and apply any env-var overrides on top.
pub async fn load_all_settings(state: &AppState) -> Result<HashMap<String, String>> {
    let rows = sqlx::query_as::<_, Setting>("SELECT * FROM settings")
        .fetch_all(&state.db)
        .await?;
    let map: HashMap<String, String> = rows.into_iter().map(|s| (s.key, s.value)).collect();
    Ok(state.config.apply_env_overrides(map))
}
