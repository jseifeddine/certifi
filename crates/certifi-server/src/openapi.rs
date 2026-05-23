//! OpenAPI 3.1 spec aggregator for the Certifi REST API.
//!
//! `ApiDoc` collects every `#[utoipa::path]`-annotated handler and every
//! `#[derive(ToSchema)]` type and exposes them as a single JSON document at
//! `GET /api/openapi.json`. The web admin renders that document with
//! swagger-ui-react under `/docs/openapi`; the CLI prints the matching
//! markdown narrative via `certifi-cli docs api`.
//!
//! Because every schema is generated from the actual Rust types that handlers
//! consume and produce, the spec cannot drift from the wire — changing a
//! response field or a status code regenerates the OpenAPI document on the
//! next build.

use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi, ToSchema};

// ── Shared response shapes ───────────────────────────────────────────────────

/// `{"ok": true}` — the canonical "did the thing succeed" body returned by
/// most mutating endpoints that don't have a resource to send back.
#[derive(Serialize, ToSchema)]
pub struct OkResponse {
    pub ok: bool,
}

/// `{"error": "..."}` — the body of every non-2xx response from the API.
#[derive(Serialize, ToSchema)]
pub struct ErrorBody {
    pub error: String,
}

/// `{"ok": true, "account_url": "..."}` — returned by
/// `POST /api/settings/acme/register`.
#[derive(Serialize, ToSchema)]
pub struct AcmeRegisterResponse {
    pub ok: bool,
    pub account_url: String,
}

// ── Security scheme ──────────────────────────────────────────────────────────

/// Attach a single bearer-token security scheme to the spec so Swagger UI's
/// "Authorize" button knows how to send credentials. Both API tokens (prefix
/// `dapi_`) and short-lived session JWTs are accepted under the same scheme.
pub struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .as_mut()
            .expect("components are always present");
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT or dapi_-prefixed API token")
                    .description(Some(
                        "API token (`dapi_...`) created from the Tokens page, or a session \
                         JWT returned by `POST /api/auth/login`. The browser admin can also \
                         authenticate via the `session=<jwt>` cookie that login sets.",
                    ))
                    .build(),
            ),
        );
    }
}

// ── Spec aggregator ──────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Certifi REST API",
        version = env!("CARGO_PKG_VERSION"),
        description = "Programmatic interface to the Certifi ACME certificate manager. \
                       Every endpoint below is also documented in narrative form at \
                       /docs/api (see `docs/api.md` in the repo). The two share zero \
                       source: this spec is generated from the Rust handler annotations; \
                       the narrative is the human-readable companion.",
        license(name = "MIT"),
    ),
    paths(
        // Auth
        crate::handlers::auth::login,
        crate::handlers::auth::login_totp,
        crate::handlers::auth::logout,
        crate::handlers::auth::me,
        crate::handlers::totp::status,
        crate::handlers::totp::enroll,
        crate::handlers::totp::confirm,
        crate::handlers::totp::disable,
        // Certificates
        crate::handlers::certificates::list,
        crate::handlers::certificates::create,
        crate::handlers::certificates::get,
        crate::handlers::certificates::delete,
        crate::handlers::certificates::renew,
        crate::handlers::certificates::update_auto_renew,
        crate::handlers::certificates::update_description,
        crate::handlers::certificates::download_fullchain,
        crate::handlers::certificates::download_cert,
        crate::handlers::certificates::download_chain,
        crate::handlers::certificates::download_privkey,
        crate::handlers::certificates::download_pfx,
        crate::handlers::certificates::pem_bundle,
        // DNS integrations
        crate::handlers::integrations::list,
        crate::handlers::integrations::create,
        crate::handlers::integrations::get,
        crate::handlers::integrations::update,
        crate::handlers::integrations::delete,
        crate::handlers::integrations::test,
        // Domains
        crate::handlers::domains::list_domains,
        // Tokens
        crate::handlers::tokens::list,
        crate::handlers::tokens::create,
        crate::handlers::tokens::delete,
        // Users
        crate::handlers::users::list,
        crate::handlers::users::create,
        crate::handlers::users::update,
        crate::handlers::users::delete,
        crate::handlers::users::change_password,
        // Settings
        crate::handlers::settings::get_settings,
        crate::handlers::settings::update_settings,
        crate::handlers::settings::register_acme,
        // Roles + permissions (RBAC)
        crate::handlers::roles::list_permissions,
        crate::handlers::roles::list_roles,
        crate::handlers::roles::create_role,
        crate::handlers::roles::delete_role,
        crate::handlers::roles::list_user_assignments,
        crate::handlers::roles::assign_role,
        crate::handlers::roles::revoke_assignment,
        // OIDC
        crate::handlers::oidc::status,
        crate::handlers::oidc::start,
        crate::handlers::oidc::callback,
        crate::handlers::oidc::get_config,
        crate::handlers::oidc::put_config,
        crate::handlers::oidc::list_group_mappings,
        crate::handlers::oidc::create_group_mapping,
        crate::handlers::oidc::delete_group_mapping,
        // Audit
        crate::handlers::audit::list,
        // Events (SSE — documented but not invokable from Swagger)
        crate::handlers::events::stream,
        // Docs (markdown passthrough — used by the web admin and the CLI)
        crate::handlers::docs::list_docs,
        crate::handlers::docs::get_doc,
        // Health
        crate::handlers::health::health,
    ),
    components(schemas(
        // Shared response shapes
        OkResponse,
        ErrorBody,
        AcmeRegisterResponse,
        // Auth
        crate::handlers::auth::LoginRequest,
        crate::handlers::auth::LoginResponse,
        crate::handlers::auth::LoginTotpRequest,
        crate::handlers::auth::TotpChallenge,
        crate::handlers::auth::LoginOutcome,
        crate::handlers::auth::UserInfo,
        crate::handlers::totp::TotpStatus,
        crate::handlers::totp::EnrollResponse,
        crate::handlers::totp::ConfirmRequest,
        // Certificates
        certifi_types::IssueCertRequest,
        certifi_types::IssueCertResponse,
        certifi_types::CertificateView,
        crate::handlers::certificates::PfxResponse,
        crate::handlers::certificates::PemBundle,
        crate::handlers::certificates::UpdateAutoRenewRequest,
        crate::handlers::certificates::UpdateDescriptionRequest,
        // DNS integrations
        certifi_types::Integration,
        certifi_types::CreateIntegrationRequest,
        certifi_types::UpdateIntegrationRequest,
        certifi_types::IntegrationTestResult,
        crate::handlers::integrations::ListResponse,
        crate::handlers::integrations::IntegrationMetaView,
        crate::integrations::IntegrationMeta,
        crate::integrations::IntegrationField,
        // Tokens
        crate::handlers::tokens::CreateTokenRequest,
        crate::handlers::tokens::TokenCreatedResponse,
        crate::handlers::tokens::TokenView,
        // Users
        crate::handlers::users::CreateUserRequest,
        crate::handlers::users::UpdateUserRequest,
        crate::handlers::users::ChangePasswordRequest,
        crate::handlers::users::UserView,
        // Settings
        crate::handlers::settings::SettingsResponse,
        crate::handlers::settings::UpdateSettingsRequest,
        // Roles + permissions
        crate::handlers::roles::PermissionView,
        crate::handlers::roles::RoleView,
        crate::handlers::roles::RoleAssignmentView,
        crate::handlers::roles::CreateRoleRequest,
        crate::handlers::roles::AssignRoleRequest,
        // OIDC
        crate::handlers::oidc::OidcStatus,
        crate::handlers::oidc::StartResponse,
        crate::handlers::oidc::OidcConfigView,
        crate::handlers::oidc::OidcConfigUpdate,
        crate::handlers::oidc::GroupMappingView,
        crate::handlers::oidc::CreateGroupMappingRequest,
        // Audit
        crate::audit::AuditRecord,
        // Health + docs
        certifi_types::HealthResponse,
        crate::handlers::docs::DocSummary,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "auth",         description = "Login, logout, session introspection."),
        (name = "certificates", description = "Issue, list, renew, and download certificates."),
        (name = "integrations", description = "CRUD for DNS integrations used to solve ACME DNS-01 challenges."),
        (name = "domains",      description = "Convenience list of zones the configured integrations cover."),
        (name = "tokens",       description = "API tokens for non-interactive clients (e.g. the CLI)."),
        (name = "users",        description = "User management (admin-only)."),
        (name = "settings",     description = "ACME and key-algorithm settings (admin-only)."),
        (name = "roles",        description = "Roles, permissions, and per-user role assignments. Phase 1 of the RBAC system."),
        (name = "audit",        description = "Append-only audit log of every state-changing action."),
        (name = "events",       description = "Server-Sent Events stream of certificate state changes."),
        (name = "docs",         description = "In-band documentation: serves the markdown under /docs to keep web admin and CLI in sync with the repo."),
        (name = "health",       description = "Unauthenticated liveness probe."),
    ),
)]
pub struct ApiDoc;

// ── HTTP handler ─────────────────────────────────────────────────────────────

/// `GET /api/openapi.json` — the spec, JSON-encoded. Unauthenticated; this is
/// metadata, not credentials.
pub async fn openapi_json() -> Response {
    let spec = ApiDoc::openapi();
    let body = serde_json::to_vec(&spec).unwrap_or_else(|_| b"{}".to_vec());
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}
