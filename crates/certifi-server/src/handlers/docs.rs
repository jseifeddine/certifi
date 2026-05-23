//! Serves the markdown files under `docs/` straight from the binary.
//!
//! Each `.md` file is pulled in at compile time with `include_str!`, so there
//! is no runtime filesystem dependency and the served content can never drift
//! from what was checked in alongside the code. The web admin renders these
//! under `/docs/<slug>` and the CLI fetches them with `certifi-cli docs
//! <slug>`.
//!
//! Endpoints are unauthenticated — these are user-facing documentation, the
//! same content that lives on GitHub.

use crate::error::AppError;
use axum::extract::Path as AxPath;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

/// One row of `GET /api/docs` — enough for the web admin's left nav to
/// render the index and link to `/api/docs/{slug}`.
#[derive(Serialize, ToSchema)]
pub struct DocSummary {
    /// URL-safe identifier, e.g. `"api"` for `docs/api.md`.
    pub slug: &'static str,
    /// Human-readable title pulled from the file's first `# ...` line.
    pub title: &'static str,
}

/// Table of contents: slug, title, raw markdown body. Order here is the
/// order shown in the web admin's docs sidebar.
const DOCS: &[(&str, &str, &str)] = &[
    (
        "readme",
        "Overview",
        include_str!("../../../../docs/README.md"),
    ),
    (
        "installation",
        "Installation",
        include_str!("../../../../docs/installation.md"),
    ),
    (
        "architecture",
        "Architecture",
        include_str!("../../../../docs/architecture.md"),
    ),
    ("api", "REST API", include_str!("../../../../docs/api.md")),
    ("cli", "CLI", include_str!("../../../../docs/cli.md")),
    (
        "certificates",
        "Certificates",
        include_str!("../../../../docs/certificates.md"),
    ),
    (
        "dns-providers",
        "DNS providers",
        include_str!("../../../../docs/dns-providers.md"),
    ),
    (
        "security",
        "Security",
        include_str!("../../../../docs/security.md"),
    ),
    (
        "development",
        "Development",
        include_str!("../../../../docs/development.md"),
    ),
];

fn find(slug: &str) -> Option<&'static (&'static str, &'static str, &'static str)> {
    DOCS.iter().find(|(s, _, _)| *s == slug)
}

#[utoipa::path(
    get,
    path = "/api/docs",
    tag = "docs",
    responses(
        (status = 200, description = "Documentation table of contents", body = [DocSummary]),
    ),
)]
pub async fn list_docs() -> Json<Vec<DocSummary>> {
    Json(
        DOCS.iter()
            .map(|(slug, title, _)| DocSummary { slug, title })
            .collect(),
    )
}

#[utoipa::path(
    get,
    path = "/api/docs/{slug}",
    tag = "docs",
    params(
        ("slug" = String, Path, description = "Doc slug returned by `GET /api/docs`, e.g. `api`, `cli`."),
    ),
    responses(
        (status = 200, description = "Raw markdown body of the requested doc.", body = String, content_type = "text/markdown; charset=utf-8"),
        (status = 404, description = "No doc with that slug.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn get_doc(AxPath(slug): AxPath<String>) -> Result<Response, AppError> {
    let (_, _, body) =
        find(&slug).ok_or_else(|| AppError::NotFound(format!("No doc '{}'", slug)))?;
    Ok((
        [(header::CONTENT_TYPE, "text/markdown; charset=utf-8")],
        *body,
    )
        .into_response())
}
