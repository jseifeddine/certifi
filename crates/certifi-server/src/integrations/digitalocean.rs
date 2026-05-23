//! DigitalOcean DNS provider.
//!
//! Auth: Personal Access Token via `Authorization: Bearer ...` (DO calls
//! these "API tokens"). The token needs read+write on the Domain Records
//! resource — there are no finer-grained scopes for DNS.
//!
//! Caveat: DO doesn't have a "zone lookup by name" endpoint — `GET /v2/domains`
//! lists every domain on the account, and we suffix-match in Rust like the
//! other providers. Pagination defaults to 20/page; we ask for 200.

use super::DnsProvider;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const API_BASE: &str = "https://api.digitalocean.com/v2";

pub struct DigitalOceanProvider {
    api_token: String,
    delay: u64,
    http: reqwest::Client,
}

impl DigitalOceanProvider {
    pub fn new(api_token: String, delay: u64) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_default();
        Self {
            api_token,
            delay,
            http,
        }
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.api_token)
    }

    /// Walk paginated `GET /v2/domains`. DO returns up to 200 per page.
    async fn list_all_domains(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        let mut url = format!("{}/domains?per_page=200", API_BASE);
        loop {
            let resp = self
                .http
                .get(&url)
                .header("Authorization", self.bearer())
                .send()
                .await
                .with_context(|| format!("DigitalOcean: GET {}", url))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!(
                    "DigitalOcean: GET {} returned HTTP {}: {}",
                    url,
                    status,
                    body
                );
            }
            let body: Value = resp.json().await.context("DigitalOcean: parsing domains")?;
            for d in body
                .get("domains")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
            {
                if let Some(n) = d.get("name").and_then(|v| v.as_str()) {
                    out.push(n.trim_end_matches('.').to_string());
                }
            }
            // DO's pagination uses links.pages.next as a fully-qualified URL.
            let next = body
                .pointer("/links/pages/next")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(out)
    }

    /// Longest-suffix match for the challenge domain. Returns the matched
    /// zone name (DO addresses records by zone name, not id).
    async fn find_zone(&self, domain: &str) -> Result<String> {
        let mut zones = self.list_all_domains().await?;
        zones.sort_by_key(|z| std::cmp::Reverse(z.len()));

        let challenge = format!("_acme-challenge.{}", domain);
        for z in &zones {
            if challenge == *z || challenge.ends_with(&format!(".{}", z)) {
                return Ok(z.clone());
            }
        }
        anyhow::bail!(
            "DigitalOcean: no domain on this account matches '{}'",
            domain
        )
    }

    /// DO stores records with `name` as the subdomain portion only (e.g.
    /// `_acme-challenge` rather than `_acme-challenge.example.com`). Convert.
    fn record_subname(domain: &str, zone: &str) -> String {
        let full = format!("_acme-challenge.{}", domain);
        // If full == zone, the record sits at the apex → "@" (DO convention).
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
impl DnsProvider for DigitalOceanProvider {
    fn name(&self) -> &'static str {
        "DigitalOcean"
    }
    fn propagation_delay(&self) -> u64 {
        self.delay
    }

    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()> {
        let zone = self.find_zone(domain).await?;
        let name = Self::record_subname(domain, &zone);
        tracing::info!(
            "DigitalOcean: deploying TXT _acme-challenge.{} → \"{}\" in domain {}",
            domain,
            token_value,
            zone
        );

        // Clean any stale record first so we don't accumulate duplicates.
        self.clean_challenge(domain).await.ok();

        let url = format!("{}/domains/{}/records", API_BASE, zone);
        let body = json!({
            "type": "TXT",
            "name": name,
            "data": token_value,
            "ttl": 30,
        });
        let resp = self
            .http
            .post(&url)
            .header("Authorization", self.bearer())
            .json(&body)
            .send()
            .await
            .with_context(|| format!("DigitalOcean: POST {}", url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "DigitalOcean: create record failed (HTTP {}): {}",
                status,
                body
            );
        }
        Ok(())
    }

    async fn clean_challenge(&self, domain: &str) -> Result<()> {
        let zone = self.find_zone(domain).await?;
        let want_name = Self::record_subname(domain, &zone);

        // DO doesn't support filtering by name/type — list all and match locally.
        let mut url = format!("{}/domains/{}/records?per_page=200", API_BASE, zone);
        loop {
            let resp = self
                .http
                .get(&url)
                .header("Authorization", self.bearer())
                .send()
                .await
                .with_context(|| format!("DigitalOcean: GET {}", url))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!(
                    "DigitalOcean: list records failed (HTTP {}): {}",
                    status,
                    body
                );
            }
            let body: Value = resp.json().await.context("DigitalOcean: parsing records")?;

            for rec in body
                .get("domain_records")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
                let rname = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
                let rid = rec.get("id").and_then(|v| v.as_i64()).unwrap_or(0);
                if rtype == "TXT" && rname == want_name && rid != 0 {
                    let del_url = format!("{}/domains/{}/records/{}", API_BASE, zone, rid);
                    let r = self
                        .http
                        .delete(&del_url)
                        .header("Authorization", self.bearer())
                        .send()
                        .await;
                    match r {
                        Ok(resp) if !resp.status().is_success() => {
                            tracing::warn!(
                                "DigitalOcean: delete record {} failed: HTTP {}",
                                rid,
                                resp.status()
                            );
                        }
                        Err(e) => {
                            tracing::warn!("DigitalOcean: delete record {} failed: {}", rid, e);
                        }
                        _ => {}
                    }
                }
            }

            let next = body
                .pointer("/links/pages/next")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            match next {
                Some(n) => url = n,
                None => break,
            }
        }
        Ok(())
    }

    async fn list_zones(&self) -> Result<Vec<String>> {
        self.list_all_domains().await
    }
}
