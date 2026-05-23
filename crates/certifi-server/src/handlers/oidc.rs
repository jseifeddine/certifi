//! OIDC SSO handlers — auth flow + admin config + group→role mappings.
//!
//! Flow:
//! 1. `GET /api/auth/oidc/start?return_to=…` — server stores a freshly-
//!    minted `(state, nonce, pkce_verifier)` row in `oidc_states`, returns
//!    `{authorize_url, state}`. Browser navigates to authorize_url.
//! 2. IdP redirects back to `oidc_redirect_uri?code=…&state=…` — registered
//!    as `https://<host>/api/oidc/callback`, i.e. it lands directly on the
//!    backend, not on a SPA route.
//! 3. The server looks up + deletes the state row, exchanges the code,
//!    verifies the id_token, JIT-provisions the user if needed, syncs role
//!    assignments from `oidc_group_mappings`, mints a session, sets the
//!    `session=` cookie, and 302-redirects to the `return_to` captured at
//!    /start time (or `/certificates` by default). The SPA loads with the
//!    cookie already in place and `/api/auth/me` resolves the user.

use crate::audit;
use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::handlers::settings::load_all_settings;
use crate::models::*;
use crate::rbac::{self, perms};
use crate::services::oidc as svc;
use crate::services::secret;
use crate::services::sessions;
use crate::AppState;
use axum::extract::{Json, Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use chrono::Utc;
use openidconnect::{Nonce, PkceCodeVerifier};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use utoipa::ToSchema;
use uuid::Uuid;

// ── /api/auth/oidc — public config endpoint ──────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct OidcStatus {
    /// True iff OIDC is fully configured and enabled. The login page uses
    /// this to decide whether to render the SSO button.
    pub enabled: bool,
    /// Human-readable display name (defaults to the issuer hostname).
    pub provider_name: String,
    /// When true, /login auto-redirects to the IdP instead of showing the
    /// local form. `/login?local=1` overrides for one visit.
    pub force_login: bool,
}

#[utoipa::path(
    get,
    path = "/api/auth/oidc",
    tag = "auth",
    responses(
        (status = 200, description = "Whether OIDC is configured + usable for sign-in.",
            body = OidcStatus),
    ),
)]
pub async fn status(State(state): State<AppState>) -> Result<Json<OidcStatus>> {
    let settings = svc::OidcSettings::load(&state).await.unwrap_or(None);
    Ok(match settings {
        Some(s) => Json(OidcStatus {
            enabled: true,
            provider_name: friendly_provider_name(&s.issuer),
            force_login: s.force_login,
        }),
        None => Json(OidcStatus {
            enabled: false,
            provider_name: "OIDC".into(),
            force_login: false,
        }),
    })
}

fn friendly_provider_name(issuer: &str) -> String {
    url::Url::parse(issuer)
        .ok()
        .and_then(|u| u.host_str().map(str::to_string))
        .unwrap_or_else(|| "OIDC".to_string())
}

// ── /api/auth/oidc/start ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartQuery {
    /// Optional path the browser was trying to reach when bounced to login.
    #[serde(default)]
    pub return_to: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct StartResponse {
    pub authorize_url: String,
    pub state: String,
}

#[utoipa::path(
    get,
    path = "/api/auth/oidc/start",
    tag = "auth",
    params(
        ("return_to" = Option<String>, Query,
            description = "Path the SPA wants to land on after sign-in (preserved through the IdP round trip).")
    ),
    responses(
        (status = 200, description = "Authorize URL + state token to keep in the browser.",
            body = StartResponse),
        (status = 400, description = "OIDC is not configured.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn start(
    State(state): State<AppState>,
    Query(q): Query<StartQuery>,
) -> Result<Json<StartResponse>> {
    let settings = svc::OidcSettings::load(&state)
        .await
        .map_err(|e| AppError::BadRequest(format!("OIDC misconfigured: {:#}", e)))?
        .ok_or_else(|| AppError::BadRequest("OIDC is not enabled".into()))?;

    let (client, _end_session_url) = svc::build_client(&state.config, &settings)
        .await
        .map_err(|e| AppError::BadRequest(format!("OIDC discovery: {:#}", e)))?;

    let (auth_url, csrf, nonce, pkce_verifier) = svc::authorize_url(&client, &settings.scopes);

    // Persist the state row so /callback can look up nonce + pkce_verifier.
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO oidc_states (state, nonce, pkce_verifier, return_to, created_at)
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(csrf.secret())
    .bind(nonce.secret())
    .bind(pkce_verifier.secret())
    .bind(&q.return_to)
    .bind(&now)
    .execute(&state.db)
    .await?;

    // Sweep anything older than 10 minutes so the table can't grow forever
    // if a user starts but never finishes a sign-in.
    let cutoff = (Utc::now() - chrono::Duration::minutes(10)).to_rfc3339();
    let _ = sqlx::query("DELETE FROM oidc_states WHERE created_at < ?")
        .bind(&cutoff)
        .execute(&state.db)
        .await;

    Ok(Json(StartResponse {
        authorize_url: auth_url,
        state: csrf.secret().to_string(),
    }))
}

// ── /api/oidc/callback ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CallbackQuery {
    /// Authorization code from the IdP. Absent when the IdP rejected the
    /// sign-in (in which case `error` is populated instead).
    #[serde(default)]
    pub code: Option<String>,
    /// CSRF token we minted at /start and stored in `oidc_states`.
    #[serde(default)]
    pub state: Option<String>,
    /// OAuth/OIDC error code (e.g. `access_denied`) if the IdP refused.
    #[serde(default)]
    pub error: Option<String>,
    /// Human-readable detail accompanying `error`.
    #[serde(default)]
    pub error_description: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/oidc/callback",
    tag = "auth",
    params(
        ("code" = Option<String>, Query, description = "Authorization code from the IdP."),
        ("state" = Option<String>, Query, description = "CSRF state minted at /start."),
        ("error" = Option<String>, Query, description = "OAuth error code if the IdP refused."),
        ("error_description" = Option<String>, Query, description = "Detail for `error`."),
    ),
    responses(
        (status = 303, description = "Sign-in succeeded — `Set-Cookie: session=…` + redirect to the original return_to (or /certificates). On any failure, redirect to /login?error=… instead."),
    ),
)]
pub async fn callback(State(state): State<AppState>, Query(q): Query<CallbackQuery>) -> Response {
    // Any failure on this path becomes a 303 to /login with the error
    // surfaced in the URL — the browser landed here from the IdP, not from
    // an XHR, so a JSON 4xx would render as raw text.
    match callback_inner(&state, q).await {
        Ok((session_id, return_to)) => redirect_with_cookie(&session_id, &return_to),
        Err(e) => redirect_to_login_with_error(&e.to_string()),
    }
}

async fn callback_inner(state: &AppState, q: CallbackQuery) -> anyhow::Result<(String, String)> {
    if let Some(err) = q.error.as_deref() {
        let msg = q.error_description.as_deref().unwrap_or(err);
        anyhow::bail!("{}", msg);
    }
    let code = q
        .code
        .ok_or_else(|| anyhow::anyhow!("OIDC redirect missing code"))?;
    let state_token = q
        .state
        .ok_or_else(|| anyhow::anyhow!("OIDC redirect missing state"))?;

    // 1. Look up + delete the state row. Reject if missing or older than 10m.
    let row: Option<(String, String, Option<String>, String)> = sqlx::query_as(
        "SELECT nonce, pkce_verifier, return_to, created_at FROM oidc_states WHERE state = ?",
    )
    .bind(&state_token)
    .fetch_optional(&state.db)
    .await?;
    let (nonce, pkce_verifier, return_to, created_at) =
        row.ok_or_else(|| anyhow::anyhow!("Unknown or expired OIDC state"))?;
    // Delete-on-use so a leaked state token can't be replayed.
    let _ = sqlx::query("DELETE FROM oidc_states WHERE state = ?")
        .bind(&state_token)
        .execute(&state.db)
        .await;
    if let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&created_at) {
        if (Utc::now() - ts.with_timezone(&Utc)).num_minutes() > 10 {
            anyhow::bail!("OIDC state expired");
        }
    }

    // 2. Build the client and exchange the code.
    let settings = svc::OidcSettings::load(state)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC: {:#}", e))?
        .ok_or_else(|| anyhow::anyhow!("OIDC is not enabled"))?;
    let (client, end_session_url) = svc::build_client(&state.config, &settings)
        .await
        .map_err(|e| anyhow::anyhow!("OIDC discovery: {:#}", e))?;

    let result = svc::exchange_code(
        &client,
        &settings,
        code,
        PkceCodeVerifier::new(pkce_verifier),
        &Nonce::new(nonce),
        end_session_url,
    )
    .await
    .map_err(|e| anyhow::anyhow!("OIDC sign-in failed: {:#}", e))?;

    // 3. Resolve / provision the local user.
    let now = Utc::now().to_rfc3339();
    let user_id = upsert_identity_and_user(state, &settings, &result, &now).await?;

    // 4. Sync role assignments from the configured group mappings.
    sync_oidc_role_assignments(state, &user_id, &result.groups, &now).await?;

    // 5. Mint a DB-backed session — same machinery the local login uses.
    let oidc_tail = Some((result.id_token.as_str(), result.end_session_url.as_deref()));
    let session_id = sessions::create(&state.db, &user_id, None, None, oidc_tail).await?;

    // `return_to` only made it into the state row if /start was told about
    // it. Refuse anything that isn't a local path so this can't be turned
    // into an open redirect.
    let dest = return_to
        .filter(|r| r.starts_with('/') && !r.starts_with("//"))
        .unwrap_or_else(|| "/certificates".to_string());
    Ok((session_id, dest))
}

fn redirect_with_cookie(session_id: &str, location: &str) -> Response {
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(location).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
    resp.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&sessions::cookie_for(session_id)).unwrap(),
    );
    resp
}

fn redirect_to_login_with_error(msg: &str) -> Response {
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("error", msg)
        .finish();
    let target = format!("/login?{}", query);
    let mut resp = Response::new(axum::body::Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    resp.headers_mut().insert(
        header::LOCATION,
        HeaderValue::from_str(&target).unwrap_or_else(|_| HeaderValue::from_static("/login")),
    );
    resp
}

/// Find or create the user behind an `(issuer, sub)` identity. Returns the
/// internal user_id.
async fn upsert_identity_and_user(
    state: &AppState,
    settings: &svc::OidcSettings,
    login: &svc::OidcLoginResult,
    now: &str,
) -> Result<String> {
    // 1. Existing identity?
    let existing: Option<(String, String)> = sqlx::query_as(
        "SELECT id, user_id FROM identities
         WHERE provider = 'oidc' AND issuer = ? AND subject = ?",
    )
    .bind(&login.issuer)
    .bind(&login.subject)
    .fetch_optional(&state.db)
    .await?;

    if let Some((identity_id, user_id)) = existing {
        // Touch last_login_at; keep email fresh if the IdP provided one.
        sqlx::query(
            "UPDATE identities SET last_login_at = ?, email = COALESCE(?, email) WHERE id = ?",
        )
        .bind(now)
        .bind(&login.email)
        .bind(&identity_id)
        .execute(&state.db)
        .await?;
        return Ok(user_id);
    }

    // 2. No identity row yet. If JIT provisioning is off, reject.
    if !settings.create_users {
        return Err(AppError::BadRequest(
            "This account is not provisioned in Certifi and JIT user creation is disabled".into(),
        ));
    }

    // 3. Resolve a username — claim → email-local-part → subject.
    let candidate_username = login
        .username
        .clone()
        .or_else(|| {
            login
                .email
                .as_ref()
                .and_then(|e| e.split('@').next().map(str::to_string))
        })
        .unwrap_or_else(|| format!("oidc-{}", &login.subject[..login.subject.len().min(12)]));
    let username = make_unique_username(&state.db, &candidate_username).await?;

    let user_id = Uuid::new_v4().to_string();
    let unusable = secret::random_password_hash()
        .map_err(|e| AppError::Internal(anyhow::anyhow!("hash error: {:?}", e)))?;
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, is_admin, email, created_at, updated_at)
         VALUES (?, ?, ?, 0, ?, ?, ?)",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(&unusable)
    .bind(&login.email)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    // 4. Persist the identity row.
    sqlx::query(
        "INSERT INTO identities
            (id, user_id, provider, issuer, subject, email, last_login_at, created_at)
         VALUES (?, ?, 'oidc', ?, ?, ?, ?, ?)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(&login.issuer)
    .bind(&login.subject)
    .bind(&login.email)
    .bind(now)
    .bind(now)
    .execute(&state.db)
    .await?;

    tracing::info!(
        "OIDC: provisioned user '{}' for {}#{}",
        username,
        login.issuer,
        login.subject
    );
    Ok(user_id)
}

/// If the candidate username is taken, append `-2`, `-3`, … until we find a
/// free one. Avoids guessing-attack surface on existing usernames because
/// OIDC sign-in is gated on a verified identity anyway.
async fn make_unique_username(db: &sqlx::SqlitePool, candidate: &str) -> Result<String> {
    let base = candidate.trim();
    let base = if base.is_empty() { "user" } else { base };
    let mut attempt = base.to_string();
    let mut suffix = 2;
    loop {
        let row: Option<(String,)> = sqlx::query_as("SELECT id FROM users WHERE username = ?")
            .bind(&attempt)
            .fetch_optional(db)
            .await?;
        if row.is_none() {
            return Ok(attempt);
        }
        attempt = format!("{}-{}", base, suffix);
        suffix += 1;
    }
}

/// Reconcile a user's `source = 'oidc'` role assignments with the live group
/// claim. Adds any (role, scope) the user should have based on group
/// mappings, removes any OIDC-sourced grant the user no longer qualifies for.
/// Hand-administered (`source = 'manual'`) assignments are left untouched.
async fn sync_oidc_role_assignments(
    state: &AppState,
    user_id: &str,
    groups: &[String],
    now: &str,
) -> Result<()> {
    // Resolve every (role_id, scope) the user should have based on the
    // group claim.
    let group_set: BTreeSet<&str> = groups.iter().map(|s| s.as_str()).collect();
    let mappings: Vec<(String, String, String)> =
        sqlx::query_as("SELECT group_name, role_id, scope FROM oidc_group_mappings")
            .fetch_all(&state.db)
            .await?;
    let mut desired: BTreeSet<(String, String)> = BTreeSet::new();
    for (group, role_id, scope) in mappings {
        if group_set.contains(group.as_str()) {
            desired.insert((role_id, scope));
        }
    }

    // Current OIDC-sourced assignments.
    let current: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT id, role_id, scope FROM role_assignments WHERE user_id = ? AND source = 'oidc'",
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await?;

    let mut current_set: BTreeSet<(String, String)> = BTreeSet::new();
    for (id, role_id, scope) in &current {
        current_set.insert((role_id.clone(), scope.clone()));
        // Drop anything no longer desired.
        if !desired.contains(&(role_id.clone(), scope.clone())) {
            sqlx::query("DELETE FROM role_assignments WHERE id = ?")
                .bind(id)
                .execute(&state.db)
                .await?;
        }
    }

    // Insert anything missing.
    for (role_id, scope) in &desired {
        if !current_set.contains(&(role_id.clone(), scope.clone())) {
            sqlx::query(
                "INSERT INTO role_assignments
                    (id, user_id, role_id, scope, granted_by, granted_at, source)
                 VALUES (?, ?, ?, ?, NULL, ?, 'oidc')
                 ON CONFLICT(user_id, role_id, scope) DO UPDATE SET source = 'oidc'",
            )
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(role_id)
            .bind(scope)
            .bind(now)
            .execute(&state.db)
            .await?;
        }
    }

    // Keep the legacy `users.is_admin` column in sync with role_assignments
    // so anything still reading the column (older list paths, audit log
    // payloads) sees the right value. The new code paths derive is_admin
    // from role_assignments directly, but the column shouldn't lie.
    sqlx::query(
        "UPDATE users SET is_admin = EXISTS(
            SELECT 1 FROM role_assignments
            WHERE user_id = ? AND role_id = ? AND scope = 'global'
         ) WHERE id = ?",
    )
    .bind(user_id)
    .bind(rbac::system_roles::SUPER_ADMIN)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}

// ── /api/oidc/config — admin read/write of OIDC settings ─────────────────────

#[derive(Serialize, ToSchema)]
pub struct OidcConfigView {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    /// Always returned as the masked sentinel `***` if a value is stored.
    /// The plaintext only ever leaves the server inside the token exchange.
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: String,
    pub group_claim: String,
    pub username_claim: String,
    pub email_claim: String,
    pub create_users: bool,
    pub force_login: bool,
    /// Keys whose value comes from an environment variable (read-only in UI).
    pub locked: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct OidcConfigUpdate {
    pub enabled: Option<bool>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    /// `***` is treated as "preserve current value" so the SPA can round-trip
    /// the view without leaking the secret.
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub scopes: Option<String>,
    pub group_claim: Option<String>,
    pub username_claim: Option<String>,
    pub email_claim: Option<String>,
    pub create_users: Option<bool>,
    pub force_login: Option<bool>,
}

const SECRET_MASK: &str = "***";

#[utoipa::path(
    get,
    path = "/api/oidc/config",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, description = "Current OIDC configuration. `client_secret` is masked.",
            body = OidcConfigView),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `settings.read`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn get_config(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<OidcConfigView>> {
    auth.require(perms::SETTINGS_READ)?;
    let map = load_all_settings(&state).await?;
    let locked: Vec<String> = state
        .config
        .locked_keys()
        .into_iter()
        .filter(|k| k.starts_with("oidc_"))
        .map(|s| s.to_string())
        .collect();

    let client_secret = if map
        .get(S_OIDC_CLIENT_SECRET)
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        SECRET_MASK.to_string()
    } else {
        String::new()
    };

    Ok(Json(OidcConfigView {
        enabled: map
            .get(S_OIDC_ENABLED)
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false),
        issuer: map.get(S_OIDC_ISSUER).cloned().unwrap_or_default(),
        client_id: map.get(S_OIDC_CLIENT_ID).cloned().unwrap_or_default(),
        client_secret,
        redirect_uri: map.get(S_OIDC_REDIRECT_URI).cloned().unwrap_or_default(),
        scopes: map
            .get(S_OIDC_SCOPES)
            .cloned()
            .unwrap_or_else(|| OIDC_DEFAULT_SCOPES.to_string()),
        group_claim: map
            .get(S_OIDC_GROUP_CLAIM)
            .cloned()
            .unwrap_or_else(|| OIDC_DEFAULT_GROUP_CLAIM.to_string()),
        username_claim: map
            .get(S_OIDC_USERNAME_CLAIM)
            .cloned()
            .unwrap_or_else(|| OIDC_DEFAULT_USERNAME_CLAIM.to_string()),
        email_claim: map
            .get(S_OIDC_EMAIL_CLAIM)
            .cloned()
            .unwrap_or_else(|| OIDC_DEFAULT_EMAIL_CLAIM.to_string()),
        create_users: map
            .get(S_OIDC_CREATE_USERS)
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false),
        force_login: map
            .get(S_OIDC_FORCE_LOGIN)
            .map(|s| s == "true" || s == "1")
            .unwrap_or(false),
        locked,
    }))
}

#[utoipa::path(
    put,
    path = "/api/oidc/config",
    tag = "auth",
    security(("bearer" = [])),
    request_body = OidcConfigUpdate,
    responses(
        (status = 200, description = "OIDC settings updated.", body = crate::openapi::OkResponse),
        (status = 400, description = "Attempt to update an env-locked field.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `settings.update`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn put_config(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<OidcConfigUpdate>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::SETTINGS_UPDATE)?;

    let locked: BTreeSet<&'static str> = state
        .config
        .locked_keys()
        .into_iter()
        .filter(|k| k.starts_with("oidc_"))
        .collect();

    let now = Utc::now().to_rfc3339();
    let mut updates: Vec<(&'static str, String)> = Vec::new();

    macro_rules! str_field {
        ($opt:expr, $key:expr) => {
            if let Some(v) = $opt {
                if locked.contains($key) {
                    return Err(AppError::BadRequest(format!(
                        "Setting '{}' is locked by an environment variable",
                        $key
                    )));
                }
                updates.push(($key, v.clone()));
            }
        };
    }
    macro_rules! bool_field {
        ($opt:expr, $key:expr) => {
            if let Some(v) = $opt {
                if locked.contains($key) {
                    return Err(AppError::BadRequest(format!(
                        "Setting '{}' is locked by an environment variable",
                        $key
                    )));
                }
                updates.push(($key, (if v { "true" } else { "false" }).to_string()));
            }
        };
    }

    bool_field!(req.enabled, S_OIDC_ENABLED);
    str_field!(req.issuer, S_OIDC_ISSUER);
    str_field!(req.client_id, S_OIDC_CLIENT_ID);
    str_field!(req.redirect_uri, S_OIDC_REDIRECT_URI);
    str_field!(req.scopes, S_OIDC_SCOPES);
    str_field!(req.group_claim, S_OIDC_GROUP_CLAIM);
    str_field!(req.username_claim, S_OIDC_USERNAME_CLAIM);
    str_field!(req.email_claim, S_OIDC_EMAIL_CLAIM);
    bool_field!(req.create_users, S_OIDC_CREATE_USERS);
    bool_field!(req.force_login, S_OIDC_FORCE_LOGIN);

    // Secret: '***' = preserve; '' = clear; anything else = encrypt + store.
    if let Some(raw) = req.client_secret {
        if locked.contains(S_OIDC_CLIENT_SECRET) {
            return Err(AppError::BadRequest(
                "Setting 'oidc_client_secret' is locked by an environment variable".into(),
            ));
        }
        if raw == SECRET_MASK {
            // no-op
        } else if raw.is_empty() {
            updates.push((S_OIDC_CLIENT_SECRET, String::new()));
        } else {
            let enc = secret::encrypt(&raw, &state.config.cookie_key)
                .map_err(|e| AppError::Internal(anyhow::anyhow!("encrypt: {:?}", e)))?;
            updates.push((S_OIDC_CLIENT_SECRET, enc));
        }
    }

    let changed_keys: Vec<&'static str> = updates.iter().map(|(k, _)| *k).collect();
    for (key, value) in updates {
        sqlx::query(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        )
        .bind(key)
        .bind(&value)
        .bind(&now)
        .execute(&state.db)
        .await?;
    }
    audit::log(
        &state.db,
        &auth,
        "oidc.config.update",
        "oidc",
        None,
        None,
        Some(serde_json::json!({"keys": changed_keys})),
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}

// ── /api/oidc/group-mappings ─────────────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct GroupMappingView {
    pub id: String,
    pub group_name: String,
    pub role_id: String,
    pub role_name: String,
    pub scope: String,
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateGroupMappingRequest {
    pub group_name: String,
    pub role_id: String,
    #[serde(default = "default_scope")]
    pub scope: String,
}
fn default_scope() -> String {
    "global".to_string()
}

#[utoipa::path(
    get,
    path = "/api/oidc/group-mappings",
    tag = "auth",
    security(("bearer" = [])),
    responses(
        (status = 200, body = [GroupMappingView]),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.list`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list_group_mappings(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<Vec<GroupMappingView>>> {
    auth.require(perms::ROLE_LIST)?;
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT m.id, m.group_name, m.role_id, r.name, m.scope || '|' || m.created_at
         FROM oidc_group_mappings m
         JOIN roles r ON r.id = m.role_id
         ORDER BY m.group_name, r.name",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|(id, group_name, role_id, role_name, scope_and_ts)| {
                let mut parts = scope_and_ts.splitn(2, '|');
                let scope = parts.next().unwrap_or("global").to_string();
                let created_at = parts.next().unwrap_or("").to_string();
                GroupMappingView {
                    id,
                    group_name,
                    role_id,
                    role_name,
                    scope,
                    created_at,
                }
            })
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api/oidc/group-mappings",
    tag = "auth",
    security(("bearer" = [])),
    request_body = CreateGroupMappingRequest,
    responses(
        (status = 200, body = GroupMappingView),
        (status = 400, description = "Unknown role, or invalid scope.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.assign`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn create_group_mapping(
    State(state): State<AppState>,
    auth: AuthUser,
    Json(req): Json<CreateGroupMappingRequest>,
) -> Result<Json<GroupMappingView>> {
    auth.require(perms::ROLE_ASSIGN)?;
    let group_name = req.group_name.trim().to_string();
    if group_name.is_empty() {
        return Err(AppError::BadRequest("group_name required".into()));
    }
    let role_row: Option<(String,)> = sqlx::query_as("SELECT name FROM roles WHERE id = ?")
        .bind(&req.role_id)
        .fetch_optional(&state.db)
        .await?;
    let Some((role_name,)) = role_row else {
        return Err(AppError::BadRequest("Unknown role".into()));
    };

    let scope = req.scope.trim().to_string();
    if scope != "global" && !scope.starts_with("zone:") {
        return Err(AppError::BadRequest(
            "scope must be 'global' or 'zone:<fqdn>'".into(),
        ));
    }

    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO oidc_group_mappings (id, group_name, role_id, scope, created_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(group_name, role_id, scope) DO NOTHING",
    )
    .bind(&id)
    .bind(&group_name)
    .bind(&req.role_id)
    .bind(&scope)
    .bind(&now)
    .execute(&state.db)
    .await?;

    let (canonical_id, created_at): (String, String) = sqlx::query_as(
        "SELECT id, created_at FROM oidc_group_mappings
         WHERE group_name = ? AND role_id = ? AND scope = ?",
    )
    .bind(&group_name)
    .bind(&req.role_id)
    .bind(&scope)
    .fetch_one(&state.db)
    .await?;

    audit::log(
        &state.db,
        &auth,
        "oidc.group_mapping.create",
        "oidc_group_mapping",
        Some(&canonical_id),
        None,
        Some(serde_json::json!({
            "group_name": &group_name,
            "role_id": &req.role_id,
            "scope": &scope,
        })),
    )
    .await;

    Ok(Json(GroupMappingView {
        id: canonical_id,
        group_name,
        role_id: req.role_id,
        role_name,
        scope,
        created_at,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/oidc/group-mappings/{id}",
    tag = "auth",
    security(("bearer" = [])),
    params(("id" = String, Path, description = "Mapping id.")),
    responses(
        (status = 200, body = crate::openapi::OkResponse),
        (status = 404, body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
        (status = 403, description = "Missing `role.assign`.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn delete_group_mapping(
    State(state): State<AppState>,
    auth: AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>> {
    auth.require(perms::ROLE_ASSIGN)?;
    let affected = sqlx::query("DELETE FROM oidc_group_mappings WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?
        .rows_affected();
    if affected == 0 {
        return Err(AppError::NotFound("Mapping not found".into()));
    }
    audit::log(
        &state.db,
        &auth,
        "oidc.group_mapping.delete",
        "oidc_group_mapping",
        Some(&id),
        None,
        None,
    )
    .await;
    Ok(Json(serde_json::json!({"ok": true})))
}
