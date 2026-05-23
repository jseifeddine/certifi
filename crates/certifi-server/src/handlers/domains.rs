use crate::auth::AuthUser;
use crate::error::{AppError, Result};
use crate::integrations::{self, DnsProvider};
use crate::rbac::perms;
use crate::AppState;
use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use utoipa::IntoParams;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SearchQuery {
    /// Case-insensitive substring filter — only zones containing this string
    /// are returned. Omit for the full list.
    pub q: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/domains",
    tag = "domains",
    security(("bearer" = [])),
    params(SearchQuery),
    responses(
        (status = 200, description = "Union of zones across all enabled DNS integrations.",
            body = [String]),
        (status = 400, description = "No DNS integrations configured, or the upstream call \
                                       failed. Error chain in the body.",
            body = crate::openapi::ErrorBody),
        (status = 401, description = "Not authenticated.", body = crate::openapi::ErrorBody),
    ),
)]
pub async fn list_domains(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(query): Query<SearchQuery>,
) -> Result<Json<Vec<String>>> {
    auth.require(perms::DOMAIN_LIST)?;
    let provider = integrations::build_provider(&state.db)
        .await
        .map_err(|e| AppError::BadRequest(format!("DNS integrations not available: {}", e)))?;

    let mut zones = provider
        .list_zones()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("{}: {}", provider.name(), e)))?;

    // Drop reverse-DNS zones — they're valid DNS zones but no public CA will
    // issue a TLS cert for `.in-addr.arpa` (IPv4 PTR) or `.ip6.arpa` (IPv6
    // PTR) names, so showing them in the autocomplete is pure noise.
    zones.retain(|z| {
        let lower = z.to_ascii_lowercase();
        let stripped = lower.trim_end_matches('.');
        !(stripped.ends_with(".in-addr.arpa")
            || stripped == "in-addr.arpa"
            || stripped.ends_with(".ip6.arpa")
            || stripped == "ip6.arpa")
    });

    // Sort alphabetically for consistent ordering
    zones.sort();

    if let Some(q) = &query.q {
        let q = q.to_lowercase();
        if !q.is_empty() {
            zones.retain(|z| z.to_lowercase().contains(&q));
        }
    }

    Ok(Json(zones))
}
