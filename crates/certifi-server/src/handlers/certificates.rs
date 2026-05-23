use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::events::{emit, CertEvent};
use crate::integrations::{self, DnsProvider};
use crate::models::*;
use crate::rbac::perms;
use crate::services::pfx::{build_pfx, generate_pfx_password};
use crate::services::renewal::run_issuance;
use crate::services::secret;
use crate::AppState;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use certifi_types::normalize_request;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

// ── Request / Response types ─────────────────────────────────────────────────
// IssueCertRequest / IssueCertResponse come from certifi-types via `models::*`.

#[derive(Serialize, ToSchema)]
pub struct PfxResponse {
    pub pfx_b64: String,
    pub password: String,
    pub filename: String,
}

/// Returned by `GET /api/certificates/:id/pem` — everything the cert detail
/// page needs to render its tabbed viewer in one round-trip.
#[derive(Serialize, ToSchema)]
pub struct PemBundle {
    pub fullchain_pem: Option<String>,
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub privkey_pem: Option<String>,
    /// Plaintext PFX password (decrypted from `pfx_password_enc`). `None` if
    /// no PFX has been generated yet or if decryption failed (e.g. COOKIE_KEY
    /// changed — the caller can simply generate a new PFX in that case).
    pub pfx_password: Option<String>,
}

/// Body of `PUT /api/certificates/:id/auto-renew`.
///
/// Only used for the OpenAPI schema — the handler accepts a loose
/// `serde_json::Value` so it can return precise per-field error messages.
/// Both shapes are wire-compatible, so consumers can rely on this struct's
/// schema in /api/openapi.json.
#[allow(dead_code)]
#[derive(Deserialize, ToSchema)]
pub struct UpdateAutoRenewRequest {
    pub auto_renew: bool,
}

/// Body of `PUT /api/certificates/:id/description`. `null` (or omitting the
/// field) clears the label; an empty string is also treated as `null`.
///
/// Like `UpdateAutoRenewRequest`, this is the OpenAPI shape — the runtime
/// handler validates `serde_json::Value` directly for richer error text.
#[allow(dead_code)]
#[derive(Deserialize, ToSchema)]
pub struct UpdateDescriptionRequest {
    #[serde(default)]
    pub description: Option<String>,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/certificates",
    tag = "certificates",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "All certificates known to this Certifi instance.",
            body = [CertificateView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<CertificateView>>> {
    let all =
        sqlx::query_as::<_, Certificate>("SELECT * FROM certificates ORDER BY created_at DESC")
            .fetch_all(&state.db)
            .await?;

    // Global grant → return everything; otherwise filter to certs whose
    // entire domain set the caller can read via a zone-scoped grant.
    if auth.has(perms::CERTIFICATE_LIST) {
        return Ok(Json(all.into_iter().map(CertificateView::from).collect()));
    }
    let mut visible = Vec::with_capacity(all.len());
    for cert in all {
        let sans: Vec<String> = serde_json::from_str(&cert.sans).unwrap_or_default();
        let mut domains: Vec<String> = sans;
        domains.insert(0, cert.common_name.clone());
        if auth.has_for_domains(perms::CERTIFICATE_LIST, &domains) {
            visible.push(CertificateView::from(cert));
        }
    }
    if visible.is_empty()
        && !auth
            .scoped
            .iter()
            .any(|g| g.permissions.contains(perms::CERTIFICATE_LIST))
    {
        // User has neither global nor any zone-scoped certificate.list — surface
        // as Forbidden instead of an empty list so the SPA can react.
        return Err(AppError::Forbidden);
    }
    Ok(Json(visible))
}

#[utoipa::path(
    get,
    path = "/api/certificates/{id}",
    tag = "certificates",
    security(("bearer" = [])),
    params(
        ("id" = String, Path, description = "Certificate UUID."),
    ),
    responses(
        (status = 200, description = "Certificate.", body = CertificateView),
        (status = 404, description = "No certificate with that id.", body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn get(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<CertificateView>> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_READ, &cert_domains(&cert))?;
    Ok(Json(CertificateView::from(cert)))
}

/// All domains a cert covers — CN first, then SANs. Used to drive
/// scope-aware authorization checks.
fn cert_domains(cert: &Certificate) -> Vec<String> {
    let sans: Vec<String> = serde_json::from_str(&cert.sans).unwrap_or_default();
    let mut out = Vec::with_capacity(sans.len() + 1);
    out.push(cert.common_name.clone());
    out.extend(sans);
    out
}

#[utoipa::path(
    post,
    path = "/api/certificates",
    tag = "certificates",
    security(("bearer" = [])),
    request_body = IssueCertRequest,
    responses(
        (status = 202, description = "New cert queued for issuance. \
                                       Poll `GET /api/certificates/{id}` for status.",
            body = IssueCertResponse),
        (status = 200, description = "Idempotent hit — an existing active or in-flight \
                                       cert with the same `(common_name, sans)` was returned. \
                                       `deduplicated` is `true` in the body.",
            body = IssueCertResponse),
        (status = 400, description = "Validation failure: empty `common_name`, invalid \
                                       `key_algo`, no DNS integrations configured, or one of \
                                       the requested domains isn't covered by any managed zone.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<IssueCertRequest>,
) -> Result<(StatusCode, Json<IssueCertResponse>)> {
    // Authorize against the *requested* domain set. Done before any
    // validation so we don't leak via error messages whether a domain
    // exists or not when the caller has no permission for it.
    let mut domains = vec![req.common_name.clone()];
    if let Some(s) = &req.sans {
        domains.extend(s.iter().cloned());
    }
    auth.require_for_domains(perms::CERTIFICATE_CREATE, &domains)?;

    if req.common_name.trim().is_empty() {
        return Err(AppError::BadRequest("common_name required".into()));
    }

    // Normalize once: lowercase, trim, strip trailing dots, dedup SANs, drop
    // the CN from the SAN set. Used for both dedup and as the canonical value
    // we persist on insert.
    let (cn, sans) = normalize_request(&req.common_name, req.sans.as_deref().unwrap_or(&[]));

    let auto_renew = req.auto_renew.unwrap_or(true);

    let description = req
        .description
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let key_algo = req
        .key_algo
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    if let Some(ref algo) = key_algo {
        if !VALID_KEY_ALGOS.contains(&algo.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid key_algo '{}'. Valid options: {}",
                algo,
                VALID_KEY_ALGOS.join(", ")
            )));
        }
    }

    // Idempotent dedup: if an active cert with the same (CN, SAN set) already
    // exists, return it instead of issuing a new one. The daily renewal
    // scheduler keeps such certs fresh, so the caller can rely on the cert
    // being valid even when near expiry — no per-request renewal logic here.
    if let Some(existing) = find_matching_active_cert(&state.db, &cn, &sans).await? {
        let existing_sans: Vec<String> = serde_json::from_str(&existing.sans).unwrap_or_default();
        return Ok((
            StatusCode::OK,
            Json(IssueCertResponse {
                id: existing.id,
                status: existing.status,
                common_name: existing.common_name,
                sans: existing_sans,
                auto_renew: existing.auto_renew,
                key_algo: existing.key_algo,
                description: existing.description,
                deduplicated: true,
            }),
        ));
    }

    // Prevent duplicate in-progress issuances. Same (CN, SAN set) match as
    // above but against pending/issuing rows so two concurrent POSTs don't
    // both kick off ACME.
    if let Some(in_flight) = find_matching_in_flight_cert(&state.db, &cn, &sans).await? {
        let in_flight_sans: Vec<String> = serde_json::from_str(&in_flight.sans).unwrap_or_default();
        return Ok((
            StatusCode::OK,
            Json(IssueCertResponse {
                id: in_flight.id,
                status: in_flight.status,
                common_name: in_flight.common_name,
                sans: in_flight_sans,
                auto_renew: in_flight.auto_renew,
                key_algo: in_flight.key_algo,
                description: in_flight.description,
                deduplicated: true,
            }),
        ));
    }

    // Pre-flight zone validation. Fail fast on domains the DNS providers
    // don't actually manage — otherwise we'd queue the issuance, the ACME
    // flow would run, the DNS-01 challenge would fail at the deploy step,
    // and the caller would only learn about it through a `failed` status
    // minutes later. Cheaper to do one list_zones() call up-front (unioned
    // across all enabled integrations).
    let provider = integrations::build_provider(&state.db)
        .await
        .map_err(|e| AppError::BadRequest(format!("DNS integrations not available: {}", e)))?;
    if provider.is_empty() {
        return Err(AppError::BadRequest(
            "No DNS integrations configured. Add one in Settings → DNS Integrations.".into(),
        ));
    }
    let zones = provider.list_zones().await.map_err(|e| {
        AppError::BadRequest(format!(
            "Could not list zones from DNS providers — check your integration settings: {}",
            e
        ))
    })?;
    let zones_n: Vec<String> = zones
        .iter()
        .map(|z| z.trim_end_matches('.').to_lowercase())
        .filter(|z| !z.is_empty())
        .collect();

    let requested: Vec<&str> = std::iter::once(cn.as_str())
        .chain(sans.iter().map(|s| s.as_str()))
        .collect();
    let uncovered: Vec<&str> = requested
        .iter()
        .copied()
        .filter(|d| {
            !zones_n
                .iter()
                .any(|z| *d == z || d.ends_with(&format!(".{}", z)))
        })
        .collect();
    if !uncovered.is_empty() {
        let zones_summary = if zones_n.is_empty() {
            "(none — check DNS integration settings)".to_string()
        } else {
            zones_n.join(", ")
        };
        return Err(AppError::BadRequest(format!(
            "No managed DNS zone covers: {}. Available zones: {}",
            uncovered.join(", "),
            zones_summary
        )));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let sans_json = serde_json::to_string(&sans).unwrap();

    sqlx::query(
        "INSERT INTO certificates (id, common_name, sans, status, auto_renew, key_algo, description, created_at, updated_at)
         VALUES (?, ?, ?, 'pending', ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&cn)
    .bind(&sans_json)
    .bind(auto_renew)
    .bind(&key_algo)
    .bind(&description)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;
    emit(&state.events, CertEvent::changed(&id));

    let db = state.db.clone();
    let config = state.config.clone();
    let events = state.events.clone();
    let id_clone = id.clone();
    let cn_clone = cn.clone();
    let sans_clone = sans.clone();
    let key_algo_clone = key_algo.clone();

    tokio::spawn(async move {
        let settings = match load_effective_settings(&db, &config).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to load settings for issuance: {:?}", e);
                return;
            }
        };
        if let Err(e) = run_issuance(
            &db,
            &settings,
            &events,
            &id_clone,
            &cn_clone,
            &sans_clone,
            key_algo_clone.as_deref(),
        )
        .await
        {
            let msg = e.to_string();
            tracing::error!("Issuance task error for {}: {}", cn_clone, msg);
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query(
                "UPDATE certificates SET status='failed', error=?, updated_at=? WHERE id=?",
            )
            .bind(&msg)
            .bind(&now)
            .bind(&id_clone)
            .execute(&db)
            .await;
            emit(&events, CertEvent::changed(&id_clone));
        }
    });

    audit::log(
        &state.db,
        &auth,
        "certificate.create",
        "certificate",
        Some(&id),
        None,
        Some(serde_json::json!({
            "common_name": cn,
            "sans": sans,
            "auto_renew": auto_renew,
            "key_algo": key_algo,
            "description": description,
        })),
    )
    .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(IssueCertResponse {
            id,
            status: "pending".into(),
            common_name: cn,
            sans,
            auto_renew,
            key_algo,
            description,
            deduplicated: false,
        }),
    ))
}

#[utoipa::path(
    post,
    path = "/api/certificates/{id}/renew",
    tag = "certificates",
    security(("bearer" = [])),
    params(
        ("id" = String, Path, description = "Certificate UUID."),
    ),
    responses(
        (status = 202, description = "Renewal queued. The cert's status flips to \
                                       `pending` and the renewal scheduler runs immediately.",
            body = IssueCertResponse),
        (status = 404, description = "No certificate with that id.",
            body = crate::openapi::ErrorBody),
        (status = 409, description = "Cert is already being issued / renewed.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn renew(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<IssueCertResponse>)> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_RENEW, &cert_domains(&cert))?;
    audit::log(
        &state.db,
        &auth,
        "certificate.renew",
        "certificate",
        Some(&id),
        None,
        Some(serde_json::json!({"common_name": cert.common_name})),
    )
    .await;

    if cert.status == "issuing" || cert.status == "pending" {
        return Err(AppError::Conflict(
            "Certificate is already being issued".into(),
        ));
    }

    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE certificates SET status='pending', error=NULL, updated_at=? WHERE id=?")
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?;
    emit(&state.events, CertEvent::changed(&id));

    let sans: Vec<String> = serde_json::from_str(&cert.sans).unwrap_or_default();
    let cn = cert.common_name.clone();
    let auto_renew = cert.auto_renew;
    let key_algo = cert.key_algo.clone();
    let db = state.db.clone();
    let config = state.config.clone();
    let events = state.events.clone();
    let id_clone = id.clone();
    let key_algo_clone = key_algo.clone();

    tokio::spawn(async move {
        let settings = match load_effective_settings(&db, &config).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to load settings for renewal: {:?}", e);
                return;
            }
        };
        if let Err(e) = run_issuance(
            &db,
            &settings,
            &events,
            &id_clone,
            &cn,
            &sans,
            key_algo_clone.as_deref(),
        )
        .await
        {
            let msg = e.to_string();
            tracing::error!("Renewal task error for {}: {}", cn, msg);
            let now = Utc::now().to_rfc3339();
            let _ = sqlx::query(
                "UPDATE certificates SET status='failed', error=?, updated_at=? WHERE id=?",
            )
            .bind(&msg)
            .bind(&now)
            .bind(&id_clone)
            .execute(&db)
            .await;
            emit(&events, CertEvent::changed(&id_clone));
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(IssueCertResponse {
            id,
            status: "pending".into(),
            common_name: cert.common_name,
            sans: serde_json::from_str(&cert.sans).unwrap_or_default(),
            auto_renew,
            key_algo,
            description: cert.description,
            deduplicated: false,
        }),
    ))
}

/// PUT /api/certificates/:id/description — update the operator-set label.
#[utoipa::path(
    put,
    path = "/api/certificates/{id}/description",
    tag = "certificates",
    security(("bearer" = [])),
    params(
        ("id" = String, Path, description = "Certificate UUID."),
    ),
    request_body = UpdateDescriptionRequest,
    responses(
        (status = 200, description = "Description updated.", body = crate::openapi::OkResponse),
        (status = 400, description = "`description` must be a string or null.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No certificate with that id.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn update_description(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_UPDATE, &cert_domains(&cert))?;
    // Accept null or a string. Strings are trimmed; empty strings become null.
    let description: Option<String> = match body.get("description") {
        Some(serde_json::Value::Null) | None => None,
        Some(serde_json::Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.to_string())
            }
        }
        Some(_) => {
            return Err(AppError::BadRequest(
                "description must be a string or null".into(),
            ))
        }
    };
    let now = Utc::now().to_rfc3339();
    let affected = sqlx::query("UPDATE certificates SET description=?, updated_at=? WHERE id=?")
        .bind(&description)
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Certificate not found".into()));
    }
    emit(&state.events, CertEvent::changed(&id));
    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(
    put,
    path = "/api/certificates/{id}/auto-renew",
    tag = "certificates",
    security(("bearer" = [])),
    params(
        ("id" = String, Path, description = "Certificate UUID."),
    ),
    request_body = UpdateAutoRenewRequest,
    responses(
        (status = 200, description = "Auto-renew flag updated.", body = crate::openapi::OkResponse),
        (status = 400, description = "Body missing `auto_renew` boolean.",
            body = crate::openapi::ErrorBody),
        (status = 404, description = "No certificate with that id.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn update_auto_renew(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_UPDATE, &cert_domains(&cert))?;
    let auto_renew = body
        .get("auto_renew")
        .and_then(|v| v.as_bool())
        .ok_or_else(|| AppError::BadRequest("auto_renew (bool) required".into()))?;

    let now = Utc::now().to_rfc3339();
    let affected = sqlx::query("UPDATE certificates SET auto_renew=?, updated_at=? WHERE id=?")
        .bind(auto_renew)
        .bind(&now)
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("Certificate not found".into()));
    }
    emit(&state.events, CertEvent::changed(&id));
    Ok(Json(serde_json::json!({"ok": true})))
}

#[utoipa::path(
    delete,
    path = "/api/certificates/{id}",
    tag = "certificates",
    security(("bearer" = [])),
    params(
        ("id" = String, Path, description = "Certificate UUID."),
    ),
    responses(
        (status = 200, description = "Cert and its key material removed.",
            body = crate::openapi::OkResponse),
        (status = 404, description = "No certificate with that id.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    // We need the cert's domains to authorize against, so fetch first.
    // If the cert doesn't exist the user sees 404 regardless of perm.
    let existing = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_DELETE, &cert_domains(&existing))?;

    let affected = sqlx::query("DELETE FROM certificates WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();

    if affected == 0 {
        return Err(AppError::NotFound("Certificate not found".into()));
    }
    emit(&state.events, CertEvent::deleted(&id));
    audit::log(
        &state.db,
        &auth,
        "certificate.delete",
        "certificate",
        Some(&id),
        Some(serde_json::json!({
            "common_name": existing.common_name,
            "sans": cert_domains(&existing),
        })),
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

// ── Download handlers ─────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/certificates/{id}/download/fullchain.pem",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "PEM-encoded leaf followed by issuer chain.",
            content_type = "application/x-pem-file", body = String),
        (status = 404, description = "Certificate not found, or material not yet issued.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn download_fullchain(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let c = fetch_cert(&s, &id).await?;
    a.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&c))?;
    let pem = c
        .fullchain_pem
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;
    Ok(pem_dl(pem, &format!("{}-fullchain.pem", c.common_name)))
}

#[utoipa::path(
    get,
    path = "/api/certificates/{id}/download/privkey.pem",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "PEM-encoded private key. Treat as sensitive.",
            content_type = "application/x-pem-file", body = String),
        (status = 404, description = "Certificate not found, or material not yet issued.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn download_privkey(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let c = fetch_cert(&s, &id).await?;
    a.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&c))?;
    let pem = c
        .privkey_pem
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;
    Ok(pem_dl(pem, &format!("{}-privkey.pem", c.common_name)))
}

#[utoipa::path(
    get,
    path = "/api/certificates/{id}/download/cert.pem",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "PEM-encoded leaf certificate only (no chain).",
            content_type = "application/x-pem-file", body = String),
        (status = 404, description = "Certificate not found, or material not yet issued.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn download_cert(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let c = fetch_cert(&s, &id).await?;
    a.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&c))?;
    let pem = c
        .cert_pem
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;
    Ok(pem_dl(pem, &format!("{}-cert.pem", c.common_name)))
}

#[utoipa::path(
    get,
    path = "/api/certificates/{id}/download/chain.pem",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "PEM-encoded intermediate issuer chain only \
                                       (no leaf, no root).",
            content_type = "application/x-pem-file", body = String),
        (status = 404, description = "Certificate not found, or material not yet issued.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn download_chain(
    State(s): State<AppState>,
    a: AuthUser,
    Path(id): Path<String>,
) -> Result<Response> {
    let c = fetch_cert(&s, &id).await?;
    a.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&c))?;
    let pem = c
        .chain_pem
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;
    Ok(pem_dl(pem, &format!("{}-chain.pem", c.common_name)))
}

#[utoipa::path(
    post,
    path = "/api/certificates/{id}/download/pfx",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "PKCS#12 archive (base64) plus its generated password \
                                       and a suggested filename. The password is stable across \
                                       calls (decrypted from `pfx_password_enc` via \
                                       `COOKIE_KEY`) until the key rotates.",
            body = PfxResponse),
        (status = 404, description = "Certificate not found, or material not yet issued.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn download_pfx(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<PfxResponse>> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&cert))?;
    let fullchain = cert
        .fullchain_pem
        .clone()
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;
    let privkey = cert
        .privkey_pem
        .clone()
        .ok_or_else(|| AppError::NotFound("Not available yet".into()))?;

    // Reuse the previously-stored password if we can decrypt it; otherwise
    // mint a fresh one and persist (encrypted). This way the user can come
    // back later, see the same password in the UI, and the on-disk PFX they
    // already saved keeps working.
    let password = match cert.pfx_password_enc.as_deref() {
        Some(enc) => match secret::decrypt(enc, &state.config.cookie_key) {
            Ok(pw) => pw,
            Err(e) => {
                tracing::warn!(
                    "PFX password decrypt failed for cert {} ({}); rotating",
                    id,
                    e
                );
                rotate_pfx_password(&state, &id).await?
            }
        },
        None => rotate_pfx_password(&state, &id).await?,
    };

    let pfx_bytes = build_pfx(&fullchain, &privkey, &password, &cert.common_name)?;
    let pfx_b64 = STANDARD.encode(&pfx_bytes);

    Ok(Json(PfxResponse {
        pfx_b64,
        password,
        filename: format!("{}.pfx", cert.common_name),
    }))
}

/// Generate a fresh PFX password, encrypt it with the cookie key, and persist
/// it on the certificate row. Returns the plaintext password.
async fn rotate_pfx_password(state: &AppState, id: &str) -> Result<String> {
    let password = generate_pfx_password();
    let enc = secret::encrypt(&password, &state.config.cookie_key).map_err(AppError::Internal)?;
    let now = Utc::now().to_rfc3339();
    sqlx::query("UPDATE certificates SET pfx_password_enc = ?, updated_at = ? WHERE id = ?")
        .bind(&enc)
        .bind(&now)
        .bind(id)
        .execute(&state.db)
        .await?;
    Ok(password)
}

/// Return all PEM blobs and (if known) the saved PFX password for the cert.
/// Powers the tabbed viewer on the cert detail page.
#[utoipa::path(
    get,
    path = "/api/certificates/{id}/pem",
    tag = "certificates",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Certificate UUID.")),
    responses(
        (status = 200, description = "All PEM blobs the server has for this cert, plus the \
                                       stored PFX password if one was generated.",
            body = PemBundle),
        (status = 404, description = "No certificate with that id.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn pem_bundle(
    State(state): State<AppState>,
    auth: AuthUser,
    Path(id): Path<String>,
) -> Result<Json<PemBundle>> {
    let cert = fetch_cert(&state, &id).await?;
    auth.require_for_domains(perms::CERTIFICATE_DOWNLOAD, &cert_domains(&cert))?;
    let pfx_password = cert
        .pfx_password_enc
        .as_deref()
        .and_then(|enc| secret::decrypt(enc, &state.config.cookie_key).ok());

    Ok(Json(PemBundle {
        fullchain_pem: cert.fullchain_pem,
        cert_pem: cert.cert_pem,
        chain_pem: cert.chain_pem,
        privkey_pem: cert.privkey_pem,
        pfx_password,
    }))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn fetch_cert(state: &AppState, id: &str) -> Result<Certificate> {
    sqlx::query_as::<_, Certificate>("SELECT * FROM certificates WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| AppError::NotFound("Certificate not found".into()))
}

/// Find an issued cert that matches the request exactly.
/// Caller passes already-normalized (CN, sorted SAN set).
async fn find_matching_active_cert(
    db: &sqlx::SqlitePool,
    cn: &str,
    sans: &[String],
) -> Result<Option<Certificate>> {
    find_matching_cert(db, cn, sans, &["active"]).await
}

/// Find a cert currently being issued that matches the request exactly.
/// Used to fold concurrent POSTs onto the same issuance.
async fn find_matching_in_flight_cert(
    db: &sqlx::SqlitePool,
    cn: &str,
    sans: &[String],
) -> Result<Option<Certificate>> {
    find_matching_cert(db, cn, sans, &["pending", "issuing"]).await
}

/// Internal: scan rows where the common_name matches (case-insensitive, dot-
/// stripped) and status is one of the given values, then pick the first whose
/// normalized SAN set equals the requested one. Performance-fine for small
/// cert tables; revisit with a generated column if this grows past ~10k rows.
async fn find_matching_cert(
    db: &sqlx::SqlitePool,
    cn: &str,
    sans: &[String],
    statuses: &[&str],
) -> Result<Option<Certificate>> {
    // SQLite has no array binding — build the IN list inline. Values come from
    // a static slice in this file, so no injection risk.
    let placeholders = statuses.iter().map(|_| "?").collect::<Vec<_>>().join(",");
    let q = format!(
        "SELECT * FROM certificates \
         WHERE LOWER(REPLACE(common_name, '.', '')) = LOWER(REPLACE(?, '.', '')) \
           AND status IN ({}) \
         ORDER BY created_at DESC",
        placeholders
    );
    let mut query = sqlx::query_as::<_, Certificate>(&q).bind(cn);
    for s in statuses {
        query = query.bind(*s);
    }
    // The CN-normalization in SQL strips ALL dots, which is broader than our
    // Rust normalizer (which only strips trailing dots). That's fine: we re-
    // check the exact CN match in Rust below alongside the SAN set check.
    let candidates = query.fetch_all(db).await?;

    for cert in candidates {
        let stored_sans: Vec<String> = serde_json::from_str(&cert.sans).unwrap_or_default();
        let (cert_cn, cert_sans) =
            certifi_types::normalize_request(&cert.common_name, &stored_sans);
        if cert_cn == cn && cert_sans == *sans {
            return Ok(Some(cert));
        }
    }
    Ok(None)
}

async fn load_effective_settings(
    db: &sqlx::SqlitePool,
    config: &crate::config::Config,
) -> anyhow::Result<std::collections::HashMap<String, String>> {
    let rows = sqlx::query_as::<_, Setting>("SELECT * FROM settings")
        .fetch_all(db)
        .await?;
    let map: std::collections::HashMap<String, String> =
        rows.into_iter().map(|s| (s.key, s.value)).collect();
    Ok(config.apply_env_overrides(map))
}

fn pem_dl(pem: String, filename: &str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (
                header::CONTENT_DISPOSITION,
                &format!("attachment; filename=\"{}\"", filename),
            ),
        ],
        pem,
    )
        .into_response()
}
