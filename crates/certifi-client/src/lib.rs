//! Rust client for the Certifi server.
//!
//! Point [`Client`] at any URL that reaches the server — either the backend
//! directly (`http://localhost:8080`) or through the web admin's reverse
//! proxy (`https://certifi.example.com`). The client always joins requests
//! onto `/api/...`, and both flows arrive at the same routes.

use std::time::Duration;

use certifi_types::{
    CertificateView, CreateIntegrationRequest, Integration, IntegrationTestResult,
    IssueCertRequest, IssueCertResponse, UpdateIntegrationRequest,
};
use reqwest::{header, StatusCode};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;
use url::Url;

pub use certifi_types;

// ── Wire types specific to GET /api/integrations ────────────────────────────
// The server's metadata views use `&'static str` internally; the wire format
// is plain strings, so the client mirrors them as owned `String`s.

/// One field on an integration kind, from the metadata catalogue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationField {
    pub key: String,
    pub label: String,
    pub field_type: String, // "text", "password", "number"
    pub required: bool,
    #[serde(default)]
    pub default: String,
    #[serde(default)]
    pub placeholder: String,
    #[serde(default)]
    pub hint: String,
}

/// One available integration kind (e.g. `pdns`, `cloudflare`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationKind {
    pub id: String,
    pub name: String,
    pub fields: Vec<IntegrationField>,
}

/// `GET /api/integrations` response: configured integrations plus the
/// metadata catalogue the operator needs to assemble a `create` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationListing {
    pub integrations: Vec<Integration>,
    pub available_kinds: Vec<IntegrationKind>,
}

/// One entry from `GET /api/docs`. Mirrors the server's `DocSummary` but
/// owns its strings — we can't pull in `utoipa`/`ToSchema` deps from a
/// client. The shape is the doc's URL slug and a display title.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DocSummary {
    pub slug: String,
    pub title: String,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid base URL: {0}")]
    InvalidBase(String),

    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    #[error("HTTP {status}: {body}")]
    Http { status: StatusCode, body: String },

    #[error("response decode failed: {0}")]
    Decode(String),

    #[error("timed out waiting for certificate to become valid")]
    Timeout,

    #[error("certificate issuance failed: {0}")]
    Issuance(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Authentication credentials. API tokens (prefix `dapi_`) and short-lived
/// JWTs are both accepted — the server sniffs the prefix internally.
#[derive(Debug, Clone)]
pub enum Auth {
    Token(String),
}

/// Async client. Cheap to clone — wraps a `reqwest::Client` which is itself a
/// reference-counted handle to a connection pool.
#[derive(Debug, Clone)]
pub struct Client {
    api_base: Url,
    http: reqwest::Client,
    auth: Auth,
}

impl Client {
    /// Build a client. `base` may be any URL the user supplies (`http://host:8080`
    /// or `https://certifi.example.com`); we strip any trailing slash and join
    /// onto `/api/` ourselves.
    pub fn new(base: &str, auth: Auth) -> Result<Self> {
        let mut parsed = Url::parse(base.trim()).map_err(|e| Error::InvalidBase(e.to_string()))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(Error::InvalidBase(format!(
                "scheme must be http or https, got '{}'",
                parsed.scheme()
            )));
        }
        // Reject pre-baked /api paths so we never produce /api/api/...
        let path = parsed.path().trim_end_matches('/');
        if path.starts_with("/api") {
            return Err(Error::InvalidBase(
                "base URL must NOT include /api — the client appends it".into(),
            ));
        }
        // Ensure the URL ends with a slash so .join("api/...") works predictably.
        parsed.set_path(&format!("{}/", path));
        let api_base = parsed
            .join("api/")
            .map_err(|e| Error::InvalidBase(e.to_string()))?;

        let http = reqwest::Client::builder()
            .user_agent(concat!("certifi-client/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(60))
            // Reap idle pooled connections aggressively so a half-closed
            // keepalive can't survive long enough to be reused on the next
            // call.
            .pool_idle_timeout(Duration::from_secs(5))
            .build()?;

        Ok(Self {
            api_base,
            http,
            auth,
        })
    }

    fn url(&self, path: &str) -> Result<Url> {
        self.api_base
            .join(path.trim_start_matches('/'))
            .map_err(|e| Error::InvalidBase(e.to_string()))
    }

    fn auth_header(&self) -> (header::HeaderName, String) {
        match &self.auth {
            Auth::Token(t) => (header::AUTHORIZATION, format!("Bearer {}", t)),
        }
    }

    async fn json_request<R: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&impl serde::Serialize>,
    ) -> Result<R> {
        let (k, v) = self.auth_header();
        let mut req = self
            .http
            .request(method, self.url(path)?)
            .header(k, v)
            .header(header::ACCEPT, "application/json");
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Http { status, body });
        }
        resp.json::<R>()
            .await
            .map_err(|e| Error::Decode(e.to_string()))
    }

    async fn bytes_request(&self, method: reqwest::Method, path: &str) -> Result<Vec<u8>> {
        let (k, v) = self.auth_header();
        let resp = self
            .http
            .request(method, self.url(path)?)
            .header(k, v)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(Error::Http { status, body });
        }
        Ok(resp.bytes().await?.to_vec())
    }

    // ── Endpoints ────────────────────────────────────────────────────────────

    pub async fn health(&self) -> Result<certifi_types::HealthResponse> {
        // /api/health is unauthenticated but our helper sends auth anyway —
        // the server ignores it on health.
        self.json_request(reqwest::Method::GET, "health", None::<&serde_json::Value>)
            .await
    }

    pub async fn list_certificates(&self) -> Result<Vec<CertificateView>> {
        self.json_request(
            reqwest::Method::GET,
            "certificates",
            None::<&serde_json::Value>,
        )
        .await
    }

    pub async fn get_certificate(&self, id: &str) -> Result<CertificateView> {
        self.json_request(
            reqwest::Method::GET,
            &format!("certificates/{}", id),
            None::<&serde_json::Value>,
        )
        .await
    }

    /// POST /api/certificates. Idempotent on (CN, SAN set): if a matching
    /// valid cert exists, the server returns it with `deduplicated = true`.
    pub async fn create_certificate(&self, req: &IssueCertRequest) -> Result<IssueCertResponse> {
        self.json_request(reqwest::Method::POST, "certificates", Some(req))
            .await
    }

    pub async fn renew_certificate(&self, id: &str) -> Result<IssueCertResponse> {
        self.json_request(
            reqwest::Method::POST,
            &format!("certificates/{}/renew", id),
            None::<&serde_json::Value>,
        )
        .await
    }

    pub async fn delete_certificate(&self, id: &str) -> Result<()> {
        let _: serde_json::Value = self
            .json_request(
                reqwest::Method::DELETE,
                &format!("certificates/{}", id),
                None::<&serde_json::Value>,
            )
            .await?;
        Ok(())
    }

    pub async fn download_fullchain(&self, id: &str) -> Result<Vec<u8>> {
        self.bytes_request(
            reqwest::Method::GET,
            &format!("certificates/{}/download/fullchain.pem", id),
        )
        .await
    }

    pub async fn download_privkey(&self, id: &str) -> Result<Vec<u8>> {
        self.bytes_request(
            reqwest::Method::GET,
            &format!("certificates/{}/download/privkey.pem", id),
        )
        .await
    }

    pub async fn download_cert(&self, id: &str) -> Result<Vec<u8>> {
        self.bytes_request(
            reqwest::Method::GET,
            &format!("certificates/{}/download/cert.pem", id),
        )
        .await
    }

    pub async fn download_chain(&self, id: &str) -> Result<Vec<u8>> {
        self.bytes_request(
            reqwest::Method::GET,
            &format!("certificates/{}/download/chain.pem", id),
        )
        .await
    }

    // ── DNS integrations ─────────────────────────────────────────────────────

    /// `GET /api/integrations` — configured integrations + available kinds.
    pub async fn list_integrations(&self) -> Result<IntegrationListing> {
        self.json_request(
            reqwest::Method::GET,
            "integrations",
            None::<&serde_json::Value>,
        )
        .await
    }

    /// `GET /api/integrations/:id`.
    pub async fn get_integration(&self, id: &str) -> Result<Integration> {
        self.json_request(
            reqwest::Method::GET,
            &format!("integrations/{}", id),
            None::<&serde_json::Value>,
        )
        .await
    }

    /// `POST /api/integrations`. Server validates the config against the
    /// provider before persisting.
    pub async fn create_integration(&self, req: &CreateIntegrationRequest) -> Result<Integration> {
        self.json_request(reqwest::Method::POST, "integrations", Some(req))
            .await
    }

    /// `PUT /api/integrations/:id`. Pass `***` as a config value to preserve
    /// the existing secret unchanged; an empty string clears the field.
    pub async fn update_integration(
        &self,
        id: &str,
        req: &UpdateIntegrationRequest,
    ) -> Result<Integration> {
        self.json_request(
            reqwest::Method::PUT,
            &format!("integrations/{}", id),
            Some(req),
        )
        .await
    }

    /// `DELETE /api/integrations/:id`.
    pub async fn delete_integration(&self, id: &str) -> Result<()> {
        let _: serde_json::Value = self
            .json_request(
                reqwest::Method::DELETE,
                &format!("integrations/{}", id),
                None::<&serde_json::Value>,
            )
            .await?;
        Ok(())
    }

    /// `POST /api/integrations/:id/test` — credentials + zone-listing probe.
    pub async fn test_integration(&self, id: &str) -> Result<IntegrationTestResult> {
        self.json_request(
            reqwest::Method::POST,
            &format!("integrations/{}/test", id),
            None::<&serde_json::Value>,
        )
        .await
    }

    // ── Docs (markdown passthrough) ──────────────────────────────────────────

    /// `GET /api/docs` — list the doc topics the server has baked into its
    /// binary. Unauthenticated on the server side, but our shared helpers
    /// send the bearer token regardless (the server ignores it).
    pub async fn list_docs(&self) -> Result<Vec<DocSummary>> {
        self.json_request(reqwest::Method::GET, "docs", None::<&serde_json::Value>)
            .await
    }

    /// `GET /api/docs/{slug}` — raw markdown body. Returns the bytes as a
    /// UTF-8 string (every file in `docs/` is UTF-8).
    pub async fn get_doc(&self, slug: &str) -> Result<String> {
        let bytes = self
            .bytes_request(reqwest::Method::GET, &format!("docs/{}", slug))
            .await?;
        String::from_utf8(bytes).map_err(|e| Error::Decode(e.to_string()))
    }

    /// Poll `GET /api/certificates/:id` until status is `active` or `failed`,
    /// or until `timeout` elapses. Returns the final view on success.
    ///
    /// Server status flow: `pending` → `issuing` → `active` | `failed`.
    pub async fn wait_until_ready(
        &self,
        id: &str,
        timeout: Duration,
        poll_interval: Duration,
    ) -> Result<CertificateView> {
        let started = std::time::Instant::now();
        loop {
            let cert = self.get_certificate(id).await?;
            match cert.status.as_str() {
                "active" => return Ok(cert),
                "failed" => {
                    return Err(Error::Issuance(
                        cert.error.unwrap_or_else(|| "unknown error".into()),
                    ))
                }
                _ => {}
            }
            if started.elapsed() >= timeout {
                return Err(Error::Timeout);
            }
            tokio::time::sleep(poll_interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(base: &str) -> Result<Client> {
        Client::new(base, Auth::Token("dapi_test".to_string()))
    }

    #[test]
    fn rejects_non_http_scheme() {
        let err = client("ftp://example.com").unwrap_err();
        assert!(matches!(err, Error::InvalidBase(_)));
    }

    #[test]
    fn rejects_base_that_already_contains_api() {
        // Guards against producing /api/api/... when a user pastes the API base.
        assert!(matches!(
            client("http://localhost:8080/api").unwrap_err(),
            Error::InvalidBase(_)
        ));
    }

    #[test]
    fn appends_api_to_a_bare_host() {
        let c = client("http://localhost:8080").unwrap();
        assert_eq!(c.api_base.as_str(), "http://localhost:8080/api/");
    }

    #[test]
    fn trailing_slash_is_normalized() {
        let c = client("http://localhost:8080/").unwrap();
        assert_eq!(c.api_base.as_str(), "http://localhost:8080/api/");
    }

    #[test]
    fn preserves_a_reverse_proxy_subpath() {
        let c = client("https://certifi.example.com/proxy").unwrap();
        assert_eq!(
            c.api_base.as_str(),
            "https://certifi.example.com/proxy/api/"
        );
    }

    #[test]
    fn url_joins_endpoint_paths_with_or_without_leading_slash() {
        let c = client("http://localhost:8080").unwrap();
        assert_eq!(
            c.url("certificates").unwrap().as_str(),
            "http://localhost:8080/api/certificates"
        );
        assert_eq!(
            c.url("/certificates").unwrap().as_str(),
            "http://localhost:8080/api/certificates"
        );
    }
}
