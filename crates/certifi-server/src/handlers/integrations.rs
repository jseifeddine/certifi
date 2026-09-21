//! CRUD endpoints for DNS integrations.
//!
//! Multiple integrations can coexist; the order they're created in is the
//! tie-break order when zones overlap (first-match wins). Secret config
//! values are masked on read — the API never returns them after creation.

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::integrations::{
    available_integrations, build_single_provider, is_secret_key, IntegrationField,
    IntegrationMeta, IntegrationRow, SECRET_MASK,
};
use crate::rbac::perms;
use crate::AppState;
use axum::extract::{Path, State};
use axum::Json;
use certifi_types::{
    CreateIntegrationRequest, Integration, IntegrationTestResult, UpdateIntegrationRequest,
};
use chrono::Utc;
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
pub struct ListResponse {
    pub integrations: Vec<Integration>,
    /// Metadata describing the kinds the operator can pick from when adding
    /// a new integration. Drives the rendered form on the "Add" modal.
    pub available_kinds: Vec<IntegrationMetaView>,
}

#[derive(Serialize, ToSchema)]
pub struct IntegrationMetaView {
    pub id: &'static str,
    pub name: &'static str,
    pub fields: Vec<IntegrationField>,
}

impl From<IntegrationMeta> for IntegrationMetaView {
    fn from(m: IntegrationMeta) -> Self {
        Self {
            id: m.id,
            name: m.name,
            fields: m.fields,
        }
    }
}

/// Render a row for the API. `cfg` is the resolved config (from the column
/// or from the secret backend) — the row's own `config` field may be a
/// reference and is never surfaced.
fn row_to_view(
    row: IntegrationRow,
    mut cfg: BTreeMap<String, String>,
    mask_secrets: bool,
) -> Integration {
    if mask_secrets {
        for (k, v) in cfg.iter_mut() {
            if !v.is_empty() && is_secret_key(&row.kind, k) {
                *v = SECRET_MASK.to_string();
            }
        }
    }
    Integration {
        id: row.id,
        kind: row.kind,
        name: row.name,
        config: cfg,
        enabled: row.enabled,
        created_at: row.created_at,
        updated_at: row.updated_at,
    }
}

/// Resolve a row's credentials and render it masked. Used by every endpoint
/// that returns an integration.
async fn masked_view(state: &AppState, row: IntegrationRow) -> Result<Integration> {
    let cfg = state
        .secrets
        .load_integration_config(&row)
        .await
        .map_err(AppError::Internal)?;
    Ok(row_to_view(row, cfg, true))
}

async fn fetch_row(state: &AppState, id: &str) -> Result<IntegrationRow> {
    sqlx::query_as::<_, IntegrationRow>("SELECT * FROM integrations WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Integration not found".into()))
}

#[utoipa::path(
    get,
    path = "/api/integrations",
    tag = "integrations",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Configured integrations (secrets masked) plus the \
                                       metadata catalogue used by the 'Add Integration' UI.",
            body = ListResponse),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(State(state): State<AppState>, auth: AuthUser) -> Result<Json<ListResponse>> {
    auth.require(perms::INTEGRATION_LIST)?;
    let rows: Vec<IntegrationRow> =
        sqlx::query_as("SELECT * FROM integrations ORDER BY created_at ASC")
            .fetch_all(&state.db)
            .await?;
    let mut integrations: Vec<Integration> = Vec::with_capacity(rows.len());
    for row in rows {
        integrations.push(masked_view(&state, row).await?);
    }
    let available_kinds: Vec<IntegrationMetaView> = available_integrations()
        .into_iter()
        .map(Into::into)
        .collect();
    Ok(Json(ListResponse {
        integrations,
        available_kinds,
    }))
}

#[utoipa::path(
    get,
    path = "/api/integrations/{id}",
    tag = "integrations",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Integration UUID.")),
    responses(
        (status = 200, description = "One integration, secrets masked.", body = Integration),
        (status = 404, description = "No integration with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<Integration>> {
    auth.require(perms::INTEGRATION_READ)?;
    let row = fetch_row(&state, &id).await?;
    Ok(Json(masked_view(&state, row).await?))
}

#[utoipa::path(
    post,
    path = "/api/integrations",
    tag = "integrations",
    security(("bearer" = [])),
    request_body = CreateIntegrationRequest,
    responses(
        (status = 200, description = "Integration created. Secrets in the response are masked.",
            body = Integration),
        (status = 400, description = "Unknown `kind`, missing required field, or the provider \
                                       constructor rejected the config. Reason in the body.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateIntegrationRequest>,
) -> Result<Json<Integration>> {
    auth.require(perms::INTEGRATION_CREATE)?;
    let kind = req.kind.trim().to_string();
    let name = req.name.trim().to_string();
    if kind.is_empty() || name.is_empty() {
        return Err(AppError::BadRequest("kind and name are required".into()));
    }
    if !available_integrations().iter().any(|k| k.id == kind) {
        return Err(AppError::BadRequest(format!(
            "Unknown integration kind '{}'",
            kind
        )));
    }

    // Validate the config now — build and discard. Catches obvious mistakes
    // (missing required fields, malformed URLs) before we persist anything.
    build_single_provider(&kind, &req.config)
        .map_err(|e| AppError::BadRequest(format_err_chain(&e)))?;

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    // Either the JSON blob itself or a reference, depending on the backend.
    let config_value = state
        .secrets
        .store_integration_config(&id, &req.config)
        .await
        .map_err(AppError::Internal)?;

    sqlx::query(
        "INSERT INTO integrations (id, kind, name, config, enabled, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&kind)
    .bind(&name)
    .bind(&config_value)
    .bind(req.enabled)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;

    let row = fetch_row(&state, &id).await?;
    let view = masked_view(&state, row).await?;
    audit::log(
        &state.db,
        &auth,
        "integration.create",
        "integration",
        Some(&id),
        None,
        Some(serde_json::json!({"kind": &view.kind, "name": &view.name})),
    )
    .await;
    Ok(Json(view))
}

#[utoipa::path(
    put,
    path = "/api/integrations/{id}",
    tag = "integrations",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Integration UUID.")),
    request_body = UpdateIntegrationRequest,
    responses(
        (status = 200, description = "Updated integration, secrets masked. Secret fields \
                                       passed as `***` are preserved; empty strings clear \
                                       optional fields.",
            body = Integration),
        (status = 400, description = "Merged config failed provider validation.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No integration with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn update(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(req): Json<UpdateIntegrationRequest>,
) -> Result<Json<Integration>> {
    auth.require(perms::INTEGRATION_UPDATE)?;
    let row = fetch_row(&state, &id).await?;

    let mut existing_cfg = state
        .secrets
        .load_integration_config(&row)
        .await
        .map_err(AppError::Internal)?;
    if let Some(new_cfg) = &req.config {
        // For each key in the incoming config, replace UNLESS the value is the
        // secret sentinel (`***`) — that means "the user didn't change this
        // field; keep what's in the DB".
        for (k, v) in new_cfg {
            if is_secret_key(&row.kind, k) && v == SECRET_MASK {
                continue;
            }
            existing_cfg.insert(k.clone(), v.clone());
        }
        // Validate the merged config
        build_single_provider(&row.kind, &existing_cfg)
            .map_err(|e| AppError::BadRequest(format_err_chain(&e)))?;
    }

    let new_name = req.name.unwrap_or(row.name.clone());
    let new_enabled = req.enabled.unwrap_or(row.enabled);
    let now = Utc::now().to_rfc3339();
    let config_value = state
        .secrets
        .store_integration_config(&id, &existing_cfg)
        .await
        .map_err(AppError::Internal)?;

    sqlx::query("UPDATE integrations SET name=?, config=?, enabled=?, updated_at=? WHERE id=?")
        .bind(&new_name)
        .bind(&config_value)
        .bind(new_enabled)
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?;

    let row = fetch_row(&state, &id).await?;
    let view = masked_view(&state, row).await?;
    audit::log(
        &state.db,
        &auth,
        "integration.update",
        "integration",
        Some(&id),
        None,
        Some(serde_json::json!({"kind": &view.kind, "name": &view.name})),
    )
    .await;
    Ok(Json(view))
}

#[utoipa::path(
    delete,
    path = "/api/integrations/{id}",
    tag = "integrations",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Integration UUID.")),
    responses(
        (status = 200, description = "Integration removed.", body = crate::openapi::OkResponse),
        (status = 404, description = "No integration with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::INTEGRATION_DELETE)?;
    // Fetch first: once the row is gone we no longer know where its
    // credentials live in the secret backend.
    let row = fetch_row(&state, &id).await?;
    sqlx::query("DELETE FROM integrations WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    // Best-effort: the row is already gone, so failing here would report an
    // error for a delete that did happen. Log it and let the operator clean
    // up the orphaned secret.
    if let Err(e) = state.secrets.delete_integration_config(&row).await {
        tracing::warn!(
            "Integration '{}' deleted, but removing its credentials from the secret backend \
             failed: {:#}",
            row.name,
            e
        );
    }
    audit::log(
        &state.db,
        &auth,
        "integration.delete",
        "integration",
        Some(&id),
        None,
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(
    post,
    path = "/api/integrations/{id}/test",
    tag = "integrations",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Integration UUID.")),
    responses(
        (status = 200, description = "Provider reached and zones listed.",
            body = IntegrationTestResult),
        (status = 400, description = "Config rejected by the provider, or upstream API call \
                                       failed. The full error chain is in the body.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No integration with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Admin role required.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn test(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<IntegrationTestResult>> {
    auth.require(perms::INTEGRATION_TEST)?;
    let row = fetch_row(&state, &id).await?;
    let cfg = state
        .secrets
        .load_integration_config(&row)
        .await
        .map_err(AppError::Internal)?;
    let provider = build_single_provider(&row.kind, &cfg)
        .map_err(|e| AppError::BadRequest(format_err_chain(&e)))?;
    let zones = provider.list_zones().await.map_err(|e| {
        tracing::warn!("Integration test failed for '{}': {:?}", row.name, e);
        AppError::BadRequest(format_err_chain(&e))
    })?;
    Ok(Json(IntegrationTestResult {
        ok: true,
        provider: provider.name().to_string(),
        zone_count: zones.len(),
        zones,
    }))
}

/// Render an anyhow error and its source chain into a single human-readable
/// string. E.g. "PDNS: connecting to API: error sending request: tcp connect…"
fn format_err_chain(err: &anyhow::Error) -> String {
    let mut parts: Vec<String> = vec![err.to_string()];
    let mut src = err.source();
    while let Some(e) = src {
        parts.push(e.to_string());
        src = e.source();
    }
    parts.dedup();
    parts.join(": ")
}

/// Convenience for accepting a flat config map. Unused for now but documents
/// the shape we expect from the wire.
#[allow(dead_code)]
fn _config_shape() -> BTreeMap<String, String> {
    Default::default()
}
