//! Hetzner DNS Console provider.
//!
//! Auth: API token via the `Auth-API-Token` header (not Bearer). Generate
//! one at https://dns.hetzner.com → API tokens. Unlike Hetzner Cloud (which
//! uses Bearer), Hetzner DNS Console is its own product with its own token
//! header — easy to mix up.

use super::DnsProvider;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const API_BASE: &str = "https://dns.hetzner.com/api/v1";

pub struct HetznerProvider {
    api_token: String,
    delay: u64,
    http: reqwest::Client,
}

impl HetznerProvider {
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

    fn auth(&self) -> (&'static str, String) {
        ("Auth-API-Token", self.api_token.clone())
    }

    async fn list_all_zones(&self) -> Result<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{}/zones?per_page=100&page={}", API_BASE, page);
            let (k, v) = self.auth();
            let resp = self
                .http
                .get(&url)
                .header(k, v)
                .send()
                .await
                .with_context(|| format!("Hetzner: GET {}", url))?;
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("Hetzner: GET {} returned HTTP {}: {}", url, status, body);
            }
            let body: Value = resp.json().await.context("Hetzner: parsing zones")?;
            let zones = body
                .get("zones")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if zones.is_empty() {
                break;
            }
            for z in &zones {
                let (Some(id), Some(name)) = (
                    z.get("id").and_then(|v| v.as_str()),
                    z.get("name").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                out.push((name.trim_end_matches('.').to_string(), id.to_string()));
            }
            let last_page = body
                .pointer("/meta/pagination/last_page")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;
            if page >= last_page {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    async fn find_zone(&self, domain: &str) -> Result<(String, String)> {
        let mut zones = self.list_all_zones().await?;
        zones.sort_by_key(|z| std::cmp::Reverse(z.0.len()));

        let challenge = format!("_acme-challenge.{}", domain);
        for (name, id) in &zones {
            if challenge == *name || challenge.ends_with(&format!(".{}", name)) {
                return Ok((name.clone(), id.clone()));
            }
        }
        anyhow::bail!("Hetzner: no zone on this account matches '{}'", domain)
    }

    /// Hetzner stores record name without the zone suffix (e.g. "_acme-challenge").
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
impl DnsProvider for HetznerProvider {
    fn name(&self) -> &'static str {
        "Hetzner DNS"
    }
    fn propagation_delay(&self) -> u64 {
        self.delay
    }

    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()> {
        let (zone_name, zone_id) = self.find_zone(domain).await?;
        let name = Self::record_subname(domain, &zone_name);
        tracing::info!(
            "Hetzner: deploying TXT _acme-challenge.{} → \"{}\" in zone {}",
            domain,
            token_value,
            zone_name
        );

        self.clean_challenge(domain).await.ok();

        let url = format!("{}/records", API_BASE);
        let body = json!({
            "value": token_value,
            "ttl": 60,
            "type": "TXT",
            "name": name,
            "zone_id": zone_id,
        });
        let (k, v) = self.auth();
        let resp = self
            .http
            .post(&url)
            .header(k, v)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Hetzner: POST {}", url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Hetzner: create record failed (HTTP {}): {}", status, body);
        }
        Ok(())
    }

    async fn clean_challenge(&self, domain: &str) -> Result<()> {
        let (zone_name, zone_id) = self.find_zone(domain).await?;
        let want_name = Self::record_subname(domain, &zone_name);

        // GET /records?zone_id=... lists records for the zone (no name filter).
        let url = format!("{}/records?zone_id={}&per_page=200", API_BASE, zone_id);
        let (k, v) = self.auth();
        let resp = self
            .http
            .get(&url)
            .header(k, v)
            .send()
            .await
            .with_context(|| format!("Hetzner: GET {}", url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Hetzner: list records failed (HTTP {}): {}", status, body);
        }
        let body: Value = resp.json().await.context("Hetzner: parsing records")?;
        let records = body
            .get("records")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        for rec in records {
            let rtype = rec.get("type").and_then(|v| v.as_str()).unwrap_or("");
            let rname = rec.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let rid = rec.get("id").and_then(|v| v.as_str()).unwrap_or("");
            if rtype == "TXT" && rname == want_name && !rid.is_empty() {
                let del_url = format!("{}/records/{}", API_BASE, rid);
                let (k, v) = self.auth();
                let r = self.http.delete(&del_url).header(k, v).send().await;
                match r {
                    Ok(resp) if !resp.status().is_success() => {
                        tracing::warn!(
                            "Hetzner: delete record {} failed: HTTP {}",
                            rid,
                            resp.status()
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Hetzner: delete record {} failed: {}", rid, e);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    async fn list_zones(&self) -> Result<Vec<String>> {
        let zones = self.list_all_zones().await?;
        Ok(zones.into_iter().map(|(n, _)| n).collect())
    }
}
