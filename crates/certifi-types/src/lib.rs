//! Wire types shared between certifi-server and certifi-client.
//!
//! Anything that crosses the HTTP boundary lives here so the two crates can
//! never drift. Server-internal types (DB rows, secrets, settings keys) stay
//! in certifi-server.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// POST /api/certificates request body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IssueCertRequest {
    pub common_name: String,
    #[serde(default)]
    pub sans: Option<Vec<String>>,
    #[serde(default)]
    pub auto_renew: Option<bool>,
    #[serde(default)]
    pub key_algo: Option<String>,
    /// Optional free-text label. Ignored on dedup hits — the existing cert's
    /// description is preserved.
    #[serde(default)]
    pub description: Option<String>,
}

/// POST /api/certificates and /api/certificates/:id/renew response.
///
/// When the server deduplicates against an existing active cert, it returns
/// that cert's id and current status here rather than creating a new row.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IssueCertResponse {
    pub id: String,
    pub status: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub auto_renew: bool,
    pub key_algo: Option<String>,
    pub description: Option<String>,
    /// True when the server returned an existing cert instead of issuing a new
    /// one. Lets clients distinguish "wait for issuance" from "already done".
    #[serde(default)]
    pub deduplicated: bool,
}

/// GET /api/certificates and GET /api/certificates/:id response shape.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CertificateView {
    pub id: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub status: String,
    pub auto_renew: bool,
    pub key_algo: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub error: Option<String>,
    pub has_files: bool,
}

/// GET /api/health response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub app: String,
    pub version: String,
}

/// One configured DNS integration. Multiple integrations can coexist; their
/// zones are unioned and the first match wins when issuing a cert.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Integration {
    pub id: String,
    pub kind: String,
    pub name: String,
    /// Provider-specific config as a key/value map (e.g. `{"cf_api_token": ...}`).
    /// Secret values may be masked when listed (replaced with `***`); raw values
    /// are only returned on individual GET if explicitly requested via the API.
    pub config: std::collections::BTreeMap<String, String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateIntegrationRequest {
    pub kind: String,
    pub name: String,
    #[serde(default)]
    pub config: std::collections::BTreeMap<String, String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateIntegrationRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub config: Option<std::collections::BTreeMap<String, String>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

fn default_true() -> bool {
    true
}

/// Result of `POST /api/integrations/:id/test` — lists the zones the provider
/// can see, so the operator can confirm the credentials are right.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IntegrationTestResult {
    pub ok: bool,
    pub provider: String,
    pub zone_count: usize,
    pub zones: Vec<String>,
}

/// Normalize a hostname for comparison: trim, lowercase, strip trailing dot.
/// Used by the server to dedupe cert requests and by the client when sanity-
/// checking that a returned cert covers what was asked for.
pub fn normalize_host(s: &str) -> String {
    s.trim().to_lowercase().trim_end_matches('.').to_string()
}

/// Returns (normalized_cn, sorted_unique_normalized_sans) with the CN removed
/// from the SAN set. Two cert requests with the same output here are
/// considered the same cert.
pub fn normalize_request(cn: &str, sans: &[String]) -> (String, Vec<String>) {
    let cn_n = normalize_host(cn);
    let mut sans_n: Vec<String> = sans
        .iter()
        .map(|s| normalize_host(s))
        .filter(|s| !s.is_empty() && *s != cn_n)
        .collect();
    sans_n.sort();
    sans_n.dedup();
    (cn_n, sans_n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_host_lowercases_trims_and_strips_trailing_dot() {
        assert_eq!(normalize_host("  Example.COM. "), "example.com");
        assert_eq!(normalize_host("HOST.local"), "host.local");
        assert_eq!(normalize_host("a.b.c."), "a.b.c");
    }

    #[test]
    fn normalize_host_is_idempotent() {
        let once = normalize_host(" WWW.Example.com. ");
        assert_eq!(once, normalize_host(&once));
    }

    #[test]
    fn normalize_request_drops_cn_from_sans_and_sorts_unique() {
        let (cn, sans) = normalize_request(
            "Example.com",
            &[
                "www.Example.com".into(),
                "example.com.".into(), // duplicate of the CN once normalized
                "api.example.com".into(),
                "API.example.com".into(), // case-duplicate of the line above
            ],
        );
        assert_eq!(cn, "example.com");
        // CN removed, remaining sorted + de-duplicated case-insensitively.
        assert_eq!(sans, vec!["api.example.com", "www.example.com"]);
    }

    #[test]
    fn normalize_request_ignores_empty_sans() {
        let (cn, sans) = normalize_request("host.test", &["".into(), "   ".into()]);
        assert_eq!(cn, "host.test");
        assert!(sans.is_empty());
    }

    #[test]
    fn normalize_request_is_order_independent() {
        // Two requests that differ only in SAN ordering / casing / trailing
        // dots must normalize identically — this is what the server's dedup
        // relies on.
        let a = normalize_request("site.io", &["b.site.io".into(), "a.site.io".into()]);
        let b = normalize_request("SITE.io.", &["A.site.io.".into(), "b.site.io".into()]);
        assert_eq!(a, b);
    }
}
