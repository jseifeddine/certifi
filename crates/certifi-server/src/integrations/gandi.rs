//! Gandi LiveDNS provider.
//!
//! Auth: Personal Access Token via `Authorization: Bearer <token>`. The
//! older `Apikey` scheme still works but Gandi has deprecated it — generate
//! a PAT at https://account.gandi.net → Authentication → Personal Access Token.
//!
//! Records here are grouped by (name, type) tuples (`rrsets`), not individual
//! IDs. Cleaning a challenge is therefore a single DELETE on the rrset URL —
//! simpler than per-record cleanup on most other providers.

use super::DnsProvider;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const API_BASE: &str = "https://api.gandi.net/v5/livedns";

pub struct GandiProvider {
    pat: String,
    delay: u64,
    http: reqwest::Client,
}

impl GandiProvider {
    pub fn new(pat: String, delay: u64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self { pat, delay, http }
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.pat)
    }

    /// `GET /domains` (paginated by `page` query param). Each entry has `fqdn`.
    async fn list_all_domains(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{}/domains?per_page=100&page={}", API_BASE, page);
            let resp = self
                .http
                .get(&url)
                .header("Authorization", self.bearer())
                .send()
                .await
                .with_context(|| format!("Gandi: GET {}", url))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Gandi: GET {} returned HTTP {}: {}", url, status, body);
            }
            let body: Value = resp.json().await.context("Gandi: parsing domains")?;
            let arr = body.as_array().cloned().unwrap_or_default();
            if arr.is_empty() {
                break;
            }
            for d in &arr {
                if let Some(n) = d.get("fqdn").and_then(|v| v.as_str()) {
                    out.push(n.trim_end_matches('.').to_string());
                }
            }
            // Gandi returns the page's worth of items; pagination stops when
            // the page is short of `per_page`.
            if arr.len() < 100 {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn find_zone(&self, domain: &str) -> Result<String> {
        let mut zones = self.list_all_domains().await?;
        zones.sort_by_key(|z| std::cmp::Reverse(z.len()));

        let challenge = format!("_acme-challenge.{}", domain);
        for z in &zones {
            if challenge == *z || challenge.ends_with(&format!(".{}", z)) {
                return Ok(z.clone());
            }
        }
        anyhow::bail!("Gandi: no domain on this account matches '{}'", domain)
    }

    fn record_subname(domain: &str, zone: &str) -> String {
        let full = format!("_acme-challenge.{}", domain);
        if full == zone {
            return "@".to_string();
        }
        let suffix = format!(".{}", zone);
        full.strip_suffix(&suffix)
            .map(|s| s.to_string())
            .unwrap_or(full)
    }
}

#[async_trait::async_trait]
impl DnsProvider for GandiProvider {
    fn name(&self) -> &'static str {
        "Gandi LiveDNS"
    }
    fn propagation_delay(&self) -> u64 {
        self.delay
    }

    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()> {
        let zone = self.find_zone(domain).await?;
        let name = Self::record_subname(domain, &zone);
        tracing::info!(
            "Gandi: deploying TXT _acme-challenge.{} → \"{}\" in domain {}",
            domain,
            token_value,
            zone
        );

        // PUT replaces the entire rrset for (name, TXT) — atomic and idempotent.
        // Wrap the value in literal quotes per Gandi's expected TXT format.
        let url = format!("{}/domains/{}/records/{}/TXT", API_BASE, zone, name);
        let body = json!({
            "rrset_ttl": 300,
            "rrset_values": [format!("\"{}\"", token_value)],
        });
        let resp = self
            .http
            .put(&url)
            .header("Authorization", self.bearer())
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Gandi: PUT {}", url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Gandi: create record failed (HTTP {}): {}", status, body);
        }
        Ok(())
    }

    async fn clean_challenge(&self, domain: &str) -> Result<()> {
        let zone = self.find_zone(domain).await?;
        let name = Self::record_subname(domain, &zone);
        let url = format!("{}/domains/{}/records/{}/TXT", API_BASE, zone, name);
        // Best effort — a 404 here means "already gone", which is the goal.
        let r = self
            .http
            .delete(&url)
            .header("Authorization", self.bearer())
            .send()
            .await;
        if let Ok(resp) = r {
            if !resp.status().is_success() && resp.status().as_u16() != 404 {
                tracing::warn!(
                    "Gandi: delete record returned HTTP {} for {}",
                    resp.status(),
                    url
                );
            }
        }
        Ok(())
    }

    async fn list_zones(&self) -> Result<Vec<String>> {
        self.list_all_domains().await
    }
}
