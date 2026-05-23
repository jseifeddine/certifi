//! DNS challenge providers.
//!
//! Multiple integrations can be configured; their zones are unioned and the
//! first one whose zone covers a requested domain wins. The set is read from
//! the `integrations` table at issuance time, so adding/removing an
//! integration takes effect on the next request — no restart required.

use anyhow::Result;
use sqlx::SqlitePool;
use std::collections::BTreeMap;

pub mod cloudflare;
pub mod digitalocean;
pub mod gandi;
pub mod hetzner;
pub mod pdns;

/// Trait for DNS challenge providers (dns-01 ACME hook).
/// Add new providers by implementing this + a build branch below.
#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    /// Place a TXT record: `_acme-challenge.<domain>` = `<token_value>`
    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()>;

    /// Remove the TXT record for `_acme-challenge.<domain>`
    async fn clean_challenge(&self, domain: &str) -> Result<()>;

    /// List all DNS zones managed by this provider (for domain autocomplete +
    /// pre-flight validation).
    async fn list_zones(&self) -> Result<Vec<String>>;

    /// Seconds to wait after deploying the record before notifying ACME.
    fn propagation_delay(&self) -> u64;

    /// Human-readable name for display.
    fn name(&self) -> &'static str;
}

/// DB row for an integration.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct IntegrationRow {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub config: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl IntegrationRow {
    /// Decode the per-integration config blob into a flat key/value map.
    pub fn config_map(&self) -> BTreeMap<String, String> {
        serde_json::from_str(&self.config).unwrap_or_default()
    }
}

/// Aggregates many providers. Implements `DnsProvider` so the rest of the
/// code (renewal, pre-flight, autocomplete) talks to "one" provider.
pub struct MultiDnsProvider {
    /// (display_name, provider) pairs in DB insertion order — first-match wins.
    providers: Vec<(String, Box<dyn DnsProvider>)>,
}

impl MultiDnsProvider {
    #[allow(dead_code)] // used by tests; kept as a constructor for callers
    pub fn empty() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    #[allow(dead_code)] // surfaced in tests / diagnostics
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }

    /// Find the first underlying provider whose zones cover `domain`. Used
    /// by deploy/clean_challenge to route the call.
    async fn route(&self, domain: &str) -> Result<&dyn DnsProvider> {
        let d = domain.trim_end_matches('.').to_lowercase();
        for (name, p) in &self.providers {
            let zones = match p.list_zones().await {
                Ok(z) => z,
                Err(e) => {
                    tracing::warn!(
                        "Integration '{}' list_zones failed during routing: {}",
                        name,
                        e
                    );
                    continue;
                }
            };
            for z in zones {
                let zn = z.trim_end_matches('.').to_lowercase();
                if d == zn || d.ends_with(&format!(".{}", zn)) {
                    return Ok(p.as_ref());
                }
            }
        }
        anyhow::bail!(
            "No managed zone covers '{}' across {} configured integration(s)",
            domain,
            self.providers.len()
        )
    }
}

#[async_trait::async_trait]
impl DnsProvider for MultiDnsProvider {
    fn name(&self) -> &'static str {
        "Multi DNS"
    }

    fn propagation_delay(&self) -> u64 {
        // Wait for the slowest. Each provider has its own propagation idea;
        // taking the max avoids the bug where one integration's record isn't
        // visible yet by the time ACME polls.
        self.providers
            .iter()
            .map(|(_, p)| p.propagation_delay())
            .max()
            .unwrap_or(5)
    }

    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()> {
        let p = self.route(domain).await?;
        p.deploy_challenge(domain, token_value).await
    }

    async fn clean_challenge(&self, domain: &str) -> Result<()> {
        // Best-effort cleanup: route to the matching provider; if that fails,
        // don't error — a leftover challenge record will be overwritten on
        // the next issuance anyway.
        match self.route(domain).await {
            Ok(p) => p.clean_challenge(domain).await,
            Err(e) => {
                tracing::warn!("clean_challenge: no provider for {}: {}", domain, e);
                Ok(())
            }
        }
    }

    async fn list_zones(&self) -> Result<Vec<String>> {
        let mut all: Vec<String> = Vec::new();
        for (name, p) in &self.providers {
            match p.list_zones().await {
                Ok(zones) => all.extend(zones),
                Err(e) => {
                    tracing::warn!("Integration '{}' list_zones failed: {}", name, e);
                }
            }
        }
        // Dedupe (case-insensitive, dot-stripped).
        let mut seen: std::collections::HashSet<String> = Default::default();
        let mut out = Vec::with_capacity(all.len());
        for z in all {
            let key = z.trim_end_matches('.').to_lowercase();
            if seen.insert(key) {
                out.push(z);
            }
        }
        Ok(out)
    }
}

/// Build the aggregated provider from every enabled integration in the DB.
pub async fn build_provider(db: &SqlitePool) -> Result<MultiDnsProvider> {
    let rows: Vec<IntegrationRow> = sqlx::query_as::<_, IntegrationRow>(
        "SELECT * FROM integrations WHERE enabled = 1 ORDER BY created_at ASC",
    )
    .fetch_all(db)
    .await?;

    let mut providers: Vec<(String, Box<dyn DnsProvider>)> = Vec::with_capacity(rows.len());
    for row in rows {
        let cfg = row.config_map();
        match build_single_provider(&row.kind, &cfg) {
            Ok(p) => providers.push((row.name, p)),
            Err(e) => {
                // Don't fail the whole build for one bad row — log and skip
                // so other integrations can still serve traffic.
                tracing::warn!(
                    "Integration '{}' ({}): build failed, skipping: {}",
                    row.name,
                    row.kind,
                    e
                );
            }
        }
    }
    Ok(MultiDnsProvider { providers })
}

/// Construct one provider from a `(kind, config map)`. Used both by
/// `build_provider` (aggregating) and by the `/api/integrations/:id/test`
/// handler (testing one in isolation).
pub fn build_single_provider(
    kind: &str,
    cfg: &BTreeMap<String, String>,
) -> Result<Box<dyn DnsProvider>> {
    let get = |k: &str| cfg.get(k).map(|s| s.to_string()).unwrap_or_default();
    let parse_delay = |k: &str, d: u64| cfg.get(k).and_then(|s| s.parse().ok()).unwrap_or(d);

    match kind {
        "pdns" => {
            let url = get("pdns_url");
            let key = get("pdns_key");
            if url.is_empty() || key.is_empty() {
                anyhow::bail!("PowerDNS integration requires pdns_url and pdns_key");
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                anyhow::bail!("pdns_url must start with http:// or https://");
            }
            let delay = parse_delay("pdns_wait", 5);
            let server = cfg.get("pdns_server").filter(|s| !s.is_empty()).cloned();
            Ok(Box::new(pdns::PdnsProvider::new(url, key, delay, server)))
        }
        "cloudflare" => {
            let token = get("cf_api_token");
            if token.is_empty() {
                anyhow::bail!("Cloudflare integration requires cf_api_token");
            }
            Ok(Box::new(cloudflare::CloudflareProvider::new(
                token,
                parse_delay("cf_wait", 10),
            )))
        }
        "digitalocean" => {
            let token = get("do_api_token");
            if token.is_empty() {
                anyhow::bail!("DigitalOcean integration requires do_api_token");
            }
            Ok(Box::new(digitalocean::DigitalOceanProvider::new(
                token,
                parse_delay("do_wait", 30),
            )))
        }
        "hetzner" => {
            let token = get("hetzner_api_token");
            if token.is_empty() {
                anyhow::bail!("Hetzner DNS integration requires hetzner_api_token");
            }
            Ok(Box::new(hetzner::HetznerProvider::new(
                token,
                parse_delay("hetzner_wait", 10),
            )))
        }
        "gandi" => {
            let pat = get("gandi_pat");
            if pat.is_empty() {
                anyhow::bail!(
                    "Gandi LiveDNS integration requires gandi_pat (Personal Access Token)"
                );
            }
            Ok(Box::new(gandi::GandiProvider::new(
                pat,
                parse_delay("gandi_wait", 10),
            )))
        }
        other => anyhow::bail!(
            "Unknown integration kind '{}'. Supported: pdns, cloudflare, digitalocean, hetzner, gandi",
            other
        ),
    }
}

/// Metadata about each available integration kind, for the web admin's
/// "Add Integration" modal.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct IntegrationMeta {
    pub id: &'static str,
    pub name: &'static str,
    pub fields: Vec<IntegrationField>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct IntegrationField {
    pub key: &'static str,
    pub label: &'static str,
    pub field_type: &'static str, // "text", "password", "number"
    pub required: bool,
    pub default: &'static str,
    pub placeholder: &'static str,
    pub hint: &'static str,
}

pub fn available_integrations() -> Vec<IntegrationMeta> {
    vec![
        IntegrationMeta {
            id: "pdns",
            name: "PowerDNS",
            fields: vec![
                IntegrationField { key: "pdns_url", label: "API URL", field_type: "text", required: true, default: "", placeholder: "https://pdns-api.example.com or http://10.0.0.1:8081", hint: "Full URL including scheme (http:// or https://) and, if non-default, port" },
                IntegrationField { key: "pdns_key", label: "API Key", field_type: "password", required: true, default: "", placeholder: "", hint: "" },
                IntegrationField { key: "pdns_wait", label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "5", placeholder: "5", hint: "Seconds to wait after DNS record is deployed before notifying ACME" },
                IntegrationField { key: "pdns_server", label: "Server ID (optional)", field_type: "text", required: false, default: "", placeholder: "localhost", hint: "Leave blank to auto-detect" },
            ],
        },
        IntegrationMeta {
            id: "cloudflare",
            name: "Cloudflare",
            fields: vec![
                IntegrationField { key: "cf_api_token", label: "API Token", field_type: "password", required: true, default: "", placeholder: "", hint: "Scoped token with Zone:DNS:Edit + Zone:Zone:Read. Create at dash.cloudflare.com → My Profile → API Tokens." },
                IntegrationField { key: "cf_wait", label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "10", placeholder: "10", hint: "Cloudflare propagates very fast; 10s is usually enough." },
            ],
        },
        IntegrationMeta {
            id: "digitalocean",
            name: "DigitalOcean",
            fields: vec![
                IntegrationField { key: "do_api_token", label: "API Token", field_type: "password", required: true, default: "", placeholder: "", hint: "Personal access token with read+write on Domain Records (cloud.digitalocean.com → API → Tokens)." },
                IntegrationField { key: "do_wait", label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "30", placeholder: "30", hint: "DO can take ~30s to propagate to all nameservers." },
            ],
        },
        IntegrationMeta {
            id: "hetzner",
            name: "Hetzner DNS",
            fields: vec![
                IntegrationField { key: "hetzner_api_token", label: "API Token", field_type: "password", required: true, default: "", placeholder: "", hint: "Token from dns.hetzner.com → API tokens. (Different product from Hetzner Cloud — don't use a cloud token here.)" },
                IntegrationField { key: "hetzner_wait", label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "10", placeholder: "10", hint: "" },
            ],
        },
        IntegrationMeta {
            id: "gandi",
            name: "Gandi LiveDNS",
            fields: vec![
                IntegrationField { key: "gandi_pat", label: "Personal Access Token", field_type: "password", required: true, default: "", placeholder: "", hint: "Generate at account.gandi.net → Authentication → Personal Access Token (scoped to the right organization)." },
                IntegrationField { key: "gandi_wait", label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "10", placeholder: "10", hint: "" },
            ],
        },
    ]
}

/// Sentinel returned by GET endpoints in place of secret config values. We
/// never send the real value back over the wire; the operator has to re-paste
/// it if they want to change it.
pub const SECRET_MASK: &str = "***";

/// Fields whose values are secret (password type). Used to mask outgoing
/// responses and to detect "no change" on update (incoming `***` means
/// "preserve the existing value", not "store the literal asterisks").
pub fn is_secret_key(kind: &str, key: &str) -> bool {
    for meta in available_integrations() {
        if meta.id == kind {
            return meta
                .fields
                .iter()
                .any(|f| f.key == key && f.field_type == "password");
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory provider for exercising the routing/aggregation logic without
    /// touching the network. `name` is returned by `name()` so tests can assert
    /// which underlying provider a request was routed to.
    struct FakeProvider {
        name: &'static str,
        zones: Vec<String>,
        delay: u64,
    }

    #[async_trait::async_trait]
    impl DnsProvider for FakeProvider {
        async fn deploy_challenge(&self, _domain: &str, _token_value: &str) -> Result<()> {
            Ok(())
        }
        async fn clean_challenge(&self, _domain: &str) -> Result<()> {
            Ok(())
        }
        async fn list_zones(&self) -> Result<Vec<String>> {
            Ok(self.zones.clone())
        }
        fn propagation_delay(&self) -> u64 {
            self.delay
        }
        fn name(&self) -> &'static str {
            self.name
        }
    }

    fn multi(providers: Vec<(&'static str, Box<dyn DnsProvider>)>) -> MultiDnsProvider {
        MultiDnsProvider {
            providers: providers
                .into_iter()
                .map(|(n, p)| (n.to_string(), p))
                .collect(),
        }
    }

    fn fake(name: &'static str, zones: &[&str], delay: u64) -> Box<dyn DnsProvider> {
        Box::new(FakeProvider {
            name,
            zones: zones.iter().map(|s| s.to_string()).collect(),
            delay,
        })
    }

    // ── Routing ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn route_matches_exact_zone() {
        let m = multi(vec![("a", fake("alpha", &["example.com"], 5))]);
        let p = m.route("example.com").await.unwrap();
        assert_eq!(p.name(), "alpha");
    }

    #[tokio::test]
    async fn route_matches_subdomain() {
        let m = multi(vec![("a", fake("alpha", &["example.com"], 5))]);
        let p = m.route("a.b.example.com").await.unwrap();
        assert_eq!(p.name(), "alpha");
    }

    #[tokio::test]
    async fn route_is_case_and_trailing_dot_insensitive() {
        let m = multi(vec![("a", fake("alpha", &["Example.COM."], 5))]);
        assert!(m.route("WWW.example.com").await.is_ok());
    }

    #[tokio::test]
    async fn route_does_not_match_sibling_suffix() {
        // "notexample.com" must NOT be considered covered by zone "example.com"
        // — the boundary is a label dot, not a raw string suffix.
        let m = multi(vec![("a", fake("alpha", &["example.com"], 5))]);
        assert!(m.route("notexample.com").await.is_err());
    }

    #[tokio::test]
    async fn route_first_match_wins() {
        // Both providers serve the zone; insertion order decides the winner.
        let m = multi(vec![
            ("a", fake("alpha", &["example.com"], 5)),
            ("b", fake("beta", &["example.com"], 5)),
        ]);
        assert_eq!(m.route("example.com").await.unwrap().name(), "alpha");
    }

    #[tokio::test]
    async fn route_falls_through_to_provider_that_owns_the_zone() {
        let m = multi(vec![
            ("a", fake("alpha", &["alpha.net"], 5)),
            ("b", fake("beta", &["beta.org"], 5)),
        ]);
        assert_eq!(m.route("host.beta.org").await.unwrap().name(), "beta");
    }

    #[tokio::test]
    async fn route_errors_when_no_zone_covers_domain() {
        let m = multi(vec![("a", fake("alpha", &["example.com"], 5))]);
        // `&dyn DnsProvider` isn't Debug, so unwrap_err() won't compile here —
        // pull the error out of the Result by hand instead.
        let res = m.route("other.tld").await;
        assert!(res.is_err());
        let err = res.err().unwrap().to_string();
        assert!(
            err.contains("other.tld"),
            "error should name the domain: {err}"
        );
    }

    // ── Aggregation ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_zones_dedupes_case_insensitively_keeping_first_spelling() {
        let m = multi(vec![
            ("a", fake("alpha", &["Example.com", "shared.net"], 5)),
            ("b", fake("beta", &["example.com.", "other.org"], 5)),
        ]);
        let zones = m.list_zones().await.unwrap();
        assert_eq!(zones.len(), 3, "example.com collision should be deduped");
        // First spelling wins for the kept entry.
        assert!(zones.contains(&"Example.com".to_string()));
        let lowered: Vec<String> = zones
            .iter()
            .map(|z| z.trim_end_matches('.').to_lowercase())
            .collect();
        assert!(lowered.contains(&"example.com".to_string()));
        assert!(lowered.contains(&"shared.net".to_string()));
        assert!(lowered.contains(&"other.org".to_string()));
    }

    #[test]
    fn propagation_delay_is_the_slowest_provider() {
        let m = multi(vec![
            ("a", fake("alpha", &[], 5)),
            ("b", fake("beta", &[], 30)),
            ("c", fake("gamma", &[], 10)),
        ]);
        assert_eq!(m.propagation_delay(), 30);
    }

    #[test]
    fn empty_provider_reports_empty_and_default_delay() {
        let m = MultiDnsProvider::empty();
        assert!(m.is_empty());
        assert_eq!(m.provider_count(), 0);
        assert_eq!(m.propagation_delay(), 5); // documented fallback
    }

    // ── build_single_provider validation ──────────────────────────────────

    fn cfg(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn build_rejects_unknown_kind() {
        assert!(build_single_provider("route53", &cfg(&[])).is_err());
    }

    #[test]
    fn build_pdns_requires_url_and_key() {
        assert!(build_single_provider("pdns", &cfg(&[("pdns_url", "http://x")])).is_err());
        assert!(build_single_provider("pdns", &cfg(&[("pdns_key", "secret")])).is_err());
    }

    #[test]
    fn build_pdns_rejects_url_without_scheme() {
        let c = cfg(&[("pdns_url", "pdns.example.com"), ("pdns_key", "secret")]);
        assert!(build_single_provider("pdns", &c).is_err());
    }

    #[test]
    fn build_pdns_accepts_valid_config() {
        let c = cfg(&[
            ("pdns_url", "https://pdns.example.com"),
            ("pdns_key", "secret"),
        ]);
        assert!(build_single_provider("pdns", &c).is_ok());
    }

    #[test]
    fn build_cloudflare_requires_token_and_parses_delay() {
        assert!(build_single_provider("cloudflare", &cfg(&[])).is_err());
        let p = build_single_provider(
            "cloudflare",
            &cfg(&[("cf_api_token", "t"), ("cf_wait", "15")]),
        )
        .unwrap();
        assert_eq!(p.propagation_delay(), 15);
        // Falls back to the documented default when the field is absent.
        let d = build_single_provider("cloudflare", &cfg(&[("cf_api_token", "t")])).unwrap();
        assert_eq!(d.propagation_delay(), 10);
    }

    #[test]
    fn every_advertised_kind_builds_with_its_required_fields() {
        for meta in available_integrations() {
            let mut c = BTreeMap::new();
            for f in &meta.fields {
                if f.required {
                    c.insert(f.key.to_string(), "placeholder-value".to_string());
                }
            }
            // pdns_url needs a scheme to pass validation.
            if meta.id == "pdns" {
                c.insert("pdns_url".into(), "https://pdns.example.com".into());
            }
            assert!(
                build_single_provider(meta.id, &c).is_ok(),
                "kind '{}' should build from its required fields",
                meta.id
            );
        }
    }

    // ── Catalogue + secret-field metadata ─────────────────────────────────

    #[test]
    fn integration_kinds_have_unique_ids() {
        let mut seen = std::collections::HashSet::new();
        for meta in available_integrations() {
            assert!(
                seen.insert(meta.id),
                "duplicate integration id: {}",
                meta.id
            );
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn is_secret_key_flags_only_password_fields() {
        assert!(is_secret_key("cloudflare", "cf_api_token"));
        assert!(!is_secret_key("cloudflare", "cf_wait"));
        assert!(is_secret_key("pdns", "pdns_key"));
        assert!(!is_secret_key("pdns", "pdns_url"));
        assert!(!is_secret_key("nonexistent", "whatever"));
    }

    #[test]
    fn every_required_password_field_is_a_secret_key() {
        for meta in available_integrations() {
            for f in &meta.fields {
                if f.field_type == "password" {
                    assert!(
                        is_secret_key(meta.id, f.key),
                        "{}.{} is a password field but not flagged secret",
                        meta.id,
                        f.key
                    );
                }
            }
        }
    }

    // ── IntegrationRow::config_map ─────────────────────────────────────────

    fn row(config: &str) -> IntegrationRow {
        IntegrationRow {
            id: "id".into(),
            kind: "cloudflare".into(),
            name: "n".into(),
            config: config.into(),
            enabled: true,
            created_at: "now".into(),
            updated_at: "now".into(),
        }
    }

    #[test]
    fn config_map_parses_json_object() {
        let m = row(r#"{"cf_api_token":"abc","cf_wait":"10"}"#).config_map();
        assert_eq!(m.get("cf_api_token").map(String::as_str), Some("abc"));
        assert_eq!(m.get("cf_wait").map(String::as_str), Some("10"));
    }

    #[test]
    fn config_map_is_empty_on_malformed_json() {
        assert!(row("not json").config_map().is_empty());
        assert!(row("").config_map().is_empty());
    }
}
