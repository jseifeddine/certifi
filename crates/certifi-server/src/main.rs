mod audit;
mod auth;
mod config;
mod db;
mod error;
mod events;
mod handlers;
mod integrations;
mod models;
mod openapi;
mod rbac;
mod services;

use crate::config::Config;
use crate::events::CertEventSender;
use crate::handlers::users::hash_password;
use crate::models::*;
use axum::http::Method;
use axum::routing::{delete, get, post, put};
use axum::Router;
use sqlx::SqlitePool;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub config: Config,
    pub events: CertEventSender,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "certifi=info,tower_http=warn".parse().unwrap()),
        )
        .init();

    let config = Config::from_env()?;
    let db = db::create_pool(&config.db_path()).await?;

    seed_settings(&db).await?;
    // Seed RBAC permissions + system roles before the admin user so the
    // first-boot admin can receive a SuperAdmin assignment in the same
    // transaction window.
    rbac::seed(&db).await?;
    ensure_admin(&db).await?;
    // Backfill role assignments for any user that pre-dates RBAC.
    rbac::migrate_existing_users(&db).await?;

    let events = events::channel();
    let state = AppState {
        db: db.clone(),
        config: config.clone(),
        events: events.clone(),
    };

    // First-boot IaC provisioning. Reads CERTIFI_PROVISIONING_FILE if set
    // and not already applied (sentinel in settings). Runs AFTER the RBAC
    // seed so group→role mappings can reference the system roles. Needs
    // `state` for the cookie_key (used to encrypt the OIDC client secret).
    if let Err(e) = services::provisioning::apply_if_present(&state).await {
        // Hard fail — a half-provisioned instance is worse than no instance.
        // The operator sees the exact error in the boot log.
        anyhow::bail!("provisioning failed: {:#}", e);
    }

    // Spawn daily renewal scheduler
    {
        let db_clone = db.clone();
        let cfg_clone = config.clone();
        let events_clone = events.clone();
        tokio::spawn(async move {
            services::renewal::run_renewal_scheduler(db_clone, cfg_clone, events_clone).await;
        });
    }

    let cors = CorsLayer::new()
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers(Any)
        .allow_origin(Any);

    let app = Router::new()
        // Auth
        .route("/api/auth/login", post(handlers::auth::login))
        .route("/api/auth/login/totp", post(handlers::auth::login_totp))
        .route("/api/auth/logout", post(handlers::auth::logout))
        .route("/api/auth/me", get(handlers::auth::me))
        // TOTP self-management
        .route(
            "/api/auth/totp",
            get(handlers::totp::status).delete(handlers::totp::disable),
        )
        .route("/api/auth/totp/enroll", post(handlers::totp::enroll))
        .route("/api/auth/totp/confirm", post(handlers::totp::confirm))
        // OIDC SSO. /api/oidc/callback is the IdP-facing redirect_uri:
        // the IdP redirects the browser straight here, the server completes
        // the exchange and 302s back into the SPA with the session cookie
        // already set — no JS round-trip, no SPA-rendered intermediate page.
        .route("/api/auth/oidc", get(handlers::oidc::status))
        .route("/api/auth/oidc/start", get(handlers::oidc::start))
        .route("/api/oidc/callback", get(handlers::oidc::callback))
        .route(
            "/api/oidc/config",
            get(handlers::oidc::get_config).put(handlers::oidc::put_config),
        )
        .route(
            "/api/oidc/group-mappings",
            get(handlers::oidc::list_group_mappings).post(handlers::oidc::create_group_mapping),
        )
        .route(
            "/api/oidc/group-mappings/:id",
            delete(handlers::oidc::delete_group_mapping),
        )
        // Certificates
        .route(
            "/api/certificates",
            get(handlers::certificates::list).post(handlers::certificates::create),
        )
        .route(
            "/api/certificates/:id",
            get(handlers::certificates::get).delete(handlers::certificates::delete),
        )
        .route("/api/certificates/:id/renew", post(handlers::certificates::renew))
        .route("/api/certificates/:id/auto-renew", put(handlers::certificates::update_auto_renew))
        .route("/api/certificates/:id/description", put(handlers::certificates::update_description))
        .route("/api/certificates/:id/download/fullchain.pem", get(handlers::certificates::download_fullchain))
        .route("/api/certificates/:id/download/privkey.pem", get(handlers::certificates::download_privkey))
        .route("/api/certificates/:id/download/cert.pem", get(handlers::certificates::download_cert))
        .route("/api/certificates/:id/download/chain.pem", get(handlers::certificates::download_chain))
        .route("/api/certificates/:id/download/pfx", post(handlers::certificates::download_pfx))
        .route("/api/certificates/:id/pem", get(handlers::certificates::pem_bundle))
        // Domains (from DNS integrations — union of all enabled)
        .route("/api/domains", get(handlers::domains::list_domains))
        // DNS integrations (multi-provider CRUD)
        .route(
            "/api/integrations",
            get(handlers::integrations::list).post(handlers::integrations::create),
        )
        .route(
            "/api/integrations/:id",
            get(handlers::integrations::get)
                .put(handlers::integrations::update)
                .delete(handlers::integrations::delete),
        )
        .route("/api/integrations/:id/test", post(handlers::integrations::test))
        // Settings (ACME + key algorithm only — DNS integration is its own resource now)
        .route(
            "/api/settings",
            get(handlers::settings::get_settings).put(handlers::settings::update_settings),
        )
        .route("/api/settings/acme/register", post(handlers::settings::register_acme))
        // API Tokens
        .route("/api/tokens", get(handlers::tokens::list).post(handlers::tokens::create))
        .route("/api/tokens/:id", delete(handlers::tokens::delete))
        // Users
        .route("/api/users", get(handlers::users::list).post(handlers::users::create))
        .route(
            "/api/users/:id",
            delete(handlers::users::delete).put(handlers::users::update),
        )
        .route("/api/users/:id/password", put(handlers::users::change_password))
        // Roles + permissions (RBAC)
        .route("/api/permissions", get(handlers::roles::list_permissions))
        .route("/api/roles", get(handlers::roles::list_roles).post(handlers::roles::create_role))
        .route("/api/roles/:id", delete(handlers::roles::delete_role))
        .route(
            "/api/users/:id/roles",
            get(handlers::roles::list_user_assignments).post(handlers::roles::assign_role),
        )
        .route(
            "/api/users/:user_id/roles/:assignment_id",
            delete(handlers::roles::revoke_assignment),
        )
        // Live updates (SSE)
        .route("/api/events", get(handlers::events::stream))
        // Health
        .route("/api/health", get(handlers::health::health))
        // OpenAPI spec — feeds the Swagger UI rendered under /docs/openapi in
        // the web admin. Unauthenticated; this is metadata, not credentials.
        // Path has no `.json` suffix on purpose: some reverse-proxy / nginx
        // setups route by file extension and serve `*.json` from a static
        // directory, which would intercept this before it reaches the
        // backend. The Content-Type header is what marks the body as JSON.
        .route("/api/openapi", get(openapi::openapi_json))
        // Markdown docs baked into the binary. Same files the web admin's
        // Docs page renders and that `certifi-cli docs` fetches.
        .route("/api/docs", get(handlers::docs::list_docs))
        .route("/api/docs/:slug", get(handlers::docs::get_doc))
        // Audit log
        .route("/api/audit", get(handlers::audit::list))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    tracing::info!("Certifi listening on {}", config.listen_addr);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Insert safe defaults for settings that have no user-supplied value yet.
/// Does NOT overwrite any existing rows (INSERT OR IGNORE).
async fn seed_settings(db: &SqlitePool) -> anyhow::Result<()> {
    let now = chrono::Utc::now().to_rfc3339();
    let defaults: &[(&str, &str)] = &[(S_ACME_CA, ACME_LE_PROD), (S_KEY_ALGO, "ec-p384")];
    for (key, value) in defaults {
        sqlx::query("INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)")
            .bind(key)
            .bind(value)
            .bind(&now)
            .execute(db)
            .await?;
    }
    Ok(())
}

/// On a fresh database, create the `admin` user and log the generated password.
///
/// If `RESET_ADMIN_PASSWORD=1` is set, regenerate the password for the
/// existing `admin` user instead and log the new value (recovery path for
/// when the original startup password has been lost from container logs).
///
/// If `SKIP_DEFAULT_ADMIN=1` is set, do not create the local admin user at
/// all — operators provisioning SSO-only deployments via
/// CERTIFI_PROVISIONING_FILE don't want a stray local admin row sitting
/// around. `RESET_ADMIN_PASSWORD` is still honored if an admin row exists.
async fn ensure_admin(db: &SqlitePool) -> anyhow::Result<()> {
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(db)
        .await?;

    let reset = std::env::var("RESET_ADMIN_PASSWORD")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);
    let skip = std::env::var("SKIP_DEFAULT_ADMIN")
        .map(|v| matches!(v.as_str(), "1" | "true" | "yes"))
        .unwrap_or(false);

    if count == 0 && skip {
        tracing::info!(
            "SKIP_DEFAULT_ADMIN=1: not seeding a local admin user on this empty database. \
             Make sure your provisioning file or another bootstrap path actually creates one — \
             otherwise the instance will have zero users.",
        );
        return Ok(());
    }

    if count == 0 {
        let password = random_password();
        let hash = hash_password(&password)?;
        let now = chrono::Utc::now().to_rfc3339();
        let id = Uuid::new_v4().to_string();

        sqlx::query(
            "INSERT INTO users (id, username, password_hash, is_admin, created_at, updated_at)
             VALUES (?, 'admin', ?, 1, ?, ?)",
        )
        .bind(&id)
        .bind(&hash)
        .bind(&now)
        .bind(&now)
        .execute(db)
        .await?;

        // Also mint a bootstrap API token tied to this admin so headless
        // / IaC deployments have a credential their automation can use
        // immediately. `permissions = NULL` means "inherit the issuing
        // user's permissions" — i.e. full SuperAdmin once RBAC reconciles.
        let token = auth::generate_api_token();
        let token_hash = auth::hash_token(&token);
        let token_id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO api_tokens (id, user_id, name, token_hash, created_at, expires_at, permissions)
             VALUES (?, ?, 'bootstrap', ?, ?, NULL, NULL)",
        )
        .bind(&token_id).bind(&id).bind(&token_hash).bind(&now)
        .execute(db)
        .await?;

        log_admin_credentials(&password, Some(&token), "INITIAL ADMIN CREDENTIALS");
    } else if reset {
        let password = random_password();
        let hash = hash_password(&password)?;
        let now = chrono::Utc::now().to_rfc3339();
        let affected = sqlx::query(
            "UPDATE users SET password_hash = ?, updated_at = ? WHERE username = 'admin'",
        )
        .bind(&hash)
        .bind(&now)
        .execute(db)
        .await?
        .rows_affected();

        if affected == 0 {
            tracing::error!("RESET_ADMIN_PASSWORD=1 set, but no user named 'admin' exists");
        } else {
            log_admin_credentials(&password, None, "ADMIN PASSWORD RESET");
            tracing::warn!(
                "Unset RESET_ADMIN_PASSWORD before the next restart to avoid rotating again."
            );
        }
    }
    Ok(())
}

fn random_password() -> String {
    use rand::Rng;
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

fn log_admin_credentials(password: &str, api_token: Option<&str>, banner: &str) {
    tracing::warn!("╔════════════════════════════════════════════════════════════╗");
    tracing::warn!("║  CERTIFI — {:<48}║", banner);
    tracing::warn!("║  Username:  admin                                          ║");
    tracing::warn!("║  Password:  {:<47}║", password);
    if let Some(tok) = api_token {
        tracing::warn!("║                                                            ║");
        tracing::warn!("║  Bootstrap API token (for headless / IaC use):             ║");
        tracing::warn!("║  {:<58}║", tok);
        tracing::warn!("║  Use as: Authorization: Bearer <token>                     ║");
    }
    tracing::warn!("╚════════════════════════════════════════════════════════════╝");
    tracing::warn!("Change this password immediately after first login.");
    if api_token.is_some() {
        tracing::warn!(
            "The bootstrap token has full admin permissions. Rotate via \
             DELETE /api/tokens/<id> once you've provisioned your own."
        );
    }
}
