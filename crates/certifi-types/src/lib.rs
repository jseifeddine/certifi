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
    #[schema(value_type = Option<KeyAlgo>)]
    pub key_algo: Option<String>,
    /// Optional free-text label. Ignored on dedup hits (including a retry of a
    /// failed cert) — the existing cert's description is preserved.
    #[serde(default)]
    pub description: Option<String>,
}

/// POST /api/certificates and /api/certificates/:id/renew response.
///
/// When the server deduplicates against an existing cert it returns that
/// cert's id and current status here rather than creating a new row — whether
/// the match was active, in flight, or a `failed` cert being retried in place.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct IssueCertResponse {
    pub id: String,
    pub status: String,
    pub common_name: String,
    pub sans: Vec<String>,
    pub auto_renew: bool,
    #[schema(value_type = Option<KeyAlgo>)]
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
    #[schema(value_type = Option<KeyAlgo>)]
    pub key_algo: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub error: Option<String>,
    pub has_files: bool,
}

/// A private-key algorithm certifi can issue with. The single list every
/// other place reads: server-side validation, `GET /api/key-algorithms`, the
/// OpenAPI enum and the client's `--key-algo` checks.
///
/// Wire fields stay `String` (annotated with this schema) so an unknown value
/// still reaches the handler and gets a precise 400 instead of a generic
/// JSON-extractor rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub enum KeyAlgo {
    #[serde(rename = "ec-p256")]
    EcP256,
    #[serde(rename = "ec-p384")]
    EcP384,
    #[serde(rename = "rsa-2048")]
    Rsa2048,
    #[serde(rename = "rsa-4096")]
    Rsa4096,
}

impl KeyAlgo {
    /// Every supported algorithm, in the order clients should list them.
    pub const ALL: &'static [KeyAlgo] = &[
        KeyAlgo::EcP256,
        KeyAlgo::EcP384,
        KeyAlgo::Rsa2048,
        KeyAlgo::Rsa4096,
    ];

    /// Used when neither the request nor the global setting names one.
    pub const DEFAULT: KeyAlgo = KeyAlgo::EcP384;

    pub fn as_str(self) -> &'static str {
        match self {
            KeyAlgo::EcP256 => "ec-p256",
            KeyAlgo::EcP384 => "ec-p384",
            KeyAlgo::Rsa2048 => "rsa-2048",
            KeyAlgo::Rsa4096 => "rsa-4096",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyAlgo::EcP256 => "ECDSA P-256",
            KeyAlgo::EcP384 => "ECDSA P-384",
            KeyAlgo::Rsa2048 => "RSA 2048",
            KeyAlgo::Rsa4096 => "RSA 4096",
        }
    }

    pub fn parse(s: &str) -> Option<KeyAlgo> {
        KeyAlgo::ALL.iter().copied().find(|a| a.as_str() == s)
    }

    /// Comma-separated ids, for error messages.
    pub fn valid_list() -> String {
        KeyAlgo::ALL
            .iter()
            .map(|a| a.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// POST /api/certificates/:id/renew request body. The body itself is
/// optional; an empty body or `{}` renews with the current algorithm.
/// Unknown fields are rejected so a typo can't silently renew with the old key.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RenewCertRequest {
    /// Re-issue with this algorithm and keep it for later renewals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<KeyAlgo>)]
    pub key_algo: Option<String>,
}

/// One entry of `GET /api/key-algorithms`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyAlgorithmInfo {
    #[schema(value_type = KeyAlgo)]
    pub id: String,
    pub label: String,
}

/// GET /api/key-algorithms response.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KeyAlgorithmsResponse {
    /// What a create request without `key_algo` gets: the global setting,
    /// else the built-in default.
    #[schema(value_type = KeyAlgo)]
    pub default: String,
    /// True when `POST /api/certificates/:id/renew` honours `key_algo`.
    /// Servers before v1.3.0 have no such endpoint and answer 404.
    pub rekey: bool,
    pub algorithms: Vec<KeyAlgorithmInfo>,
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
    fn key_algo_ids_round_trip_through_serde_and_parse() {
        for a in KeyAlgo::ALL {
            let wire = serde_json::to_string(a).unwrap();
            assert_eq!(wire, format!("\"{}\"", a.as_str()));
            assert_eq!(KeyAlgo::parse(a.as_str()), Some(*a));
        }
        assert_eq!(KeyAlgo::parse("ec-p521"), None);
        assert_eq!(KeyAlgo::parse("EC-P256"), None);
    }

    #[test]
    fn renew_request_rejects_unknown_fields() {
        let ok: RenewCertRequest = serde_json::from_str(r#"{"key_algo":"ec-p256"}"#).unwrap();
        assert_eq!(ok.key_algo.as_deref(), Some("ec-p256"));
        let empty: RenewCertRequest = serde_json::from_str("{}").unwrap();
        assert!(empty.key_algo.is_none());
        assert!(serde_json::from_str::<RenewCertRequest>(r#"{"keyalgo":"ec-p256"}"#).is_err());
    }

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
