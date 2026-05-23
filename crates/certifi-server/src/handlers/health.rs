//! Unauthenticated `GET /api/health`. Returns the app name, the package
//! version compiled into the binary, and a literal `"ok"` status. Used by
//! upstream load-balancers, the CLI's connectivity check, and the docs
//! page to display the version banner.

use axum::Json;
use certifi_types::HealthResponse;

#[utoipa::path(
    get,
    path = "/api/health",
    tag = "health",
    responses(
        (status = 200, description = "Server is running", body = HealthResponse),
    ),
)]
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        app: "Certifi".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}
