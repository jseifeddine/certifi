//! Cloudflare DNS provider.
//!
//! Auth: API Token (preferred) via `Authorization: Bearer ...`. The token
//! needs `Zone:DNS:Edit` + `Zone:Zone:Read` scoped to whichever zones the
//! user wants Certifi to manage. The legacy Global API Key flow (X-Auth-Email
//! and X-Auth-Key) is intentionally not supported — Cloudflare's own docs
//! recommend scoped tokens and the old key has no scoping.
//!
//! Modeled on the cfhookbash reference (https://github.com/sineverba/cfhookbash)
//! but extended with auto zone-id discovery so users don't have to wire each
//! zone manually — Certifi already lists zones for the domains autocompleter.

use super::DnsProvider;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::time::Duration;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

pub struct CloudflareProvider {
    api_token: String,
    delay: u64,
    http: reqwest::Client,
}

impl CloudflareProvider {
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

    fn auth_header(&self) -> (&'static str, String) {
        ("Authorization", format!("Bearer {}", self.api_token))
    }

    /// GET helper that surfaces the Cloudflare-style error envelope.
    async fn get_json(&self, url: &str) -> Result<Value> {
        let (k, v) = self.auth_header();
        let resp = self
            .http
            .get(url)
            .header(k, v)
            .send()
            .await
            .with_context(|| format!("Cloudflare: GET {}", url))?;
        parse_cf_response(resp, "GET", url).await
    }

    /// Walk Cloudflare's paginated `GET /zones` and collect every zone we can
    /// see with the current token. Tokens are typically scoped to a subset of
    /// the account's zones, which is fine — we only see what we can use.
    async fn list_all_zones(&self) -> Result<Vec<(String, String)>> {
        let mut out: Vec<(String, String)> = Vec::new();
        let mut page = 1u32;
        loop {
            let url = format!("{}/zones?per_page=50&page={}", API_BASE, page);
            let body = self.get_json(&url).await?;
            let result = body
                .get("result")
                .and_then(|r| r.as_array())
                .cloned()
                .unwrap_or_default();
            if result.is_empty() {
                break;
            }
            for z in &result {
                let (Some(id), Some(name)) = (
                    z.get("id").and_then(|v| v.as_str()),
                    z.get("name").and_then(|v| v.as_str()),
                ) else {
                    continue;
                };
                out.push((name.trim_end_matches('.').to_string(), id.to_string()));
            }

            // Stop once we've seen all pages — `total_pages` is in result_info.
            let total = body
                .pointer("/result_info/total_pages")
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u32;
            if page >= total {
                break;
            }
            page += 1;
        }
        Ok(out)
    }

    /// Pick the longest-matching zone for `_acme-challenge.<domain>`. Returns
    /// (zone_name, zone_id).
    async fn find_zone(&self, domain: &str) -> Result<(String, String)> {
        let mut zones = self.list_all_zones().await?;
        // Longest first → most specific match wins (api.example.com beats example.com).
        zones.sort_by_key(|z| std::cmp::Reverse(z.0.len()));

        let challenge = format!("_acme-challenge.{}", domain);
        for (name, id) in &zones {
            if challenge == *name || challenge.ends_with(&format!(".{}", name)) {
                return Ok((name.clone(), id.clone()));
            }
        }
        anyhow::bail!(
            "Cloudflare: no zone visible to this token matches '{}' \
             (token needs Zone:Zone:Read + Zone:DNS:Edit on the parent zone)",
            domain
        );
    }
}

/// Convert a Cloudflare API response into a parsed JSON body, or surface the
/// `errors` array verbatim. CF returns 200 even for some failures, so we have
/// to inspect both the HTTP status AND the `success` flag.
async fn parse_cf_response(resp: reqwest::Response, method: &str, url: &str) -> Result<Value> {
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let json: Value = serde_json::from_str(&body).unwrap_or(json!({}));

    let success = json
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if status.is_success() && success {
        return Ok(json);
    }

    // Cloudflare error shape: { "errors": [{"code": N, "message": "..."}] }
    let errs = json
        .get("errors")
        .and_then(|e| e.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("message").and_then(|m| m.as_str()))
                .collect::<Vec<_>>()
                .join("; ")
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("HTTP {} {}", status.as_u16(), body));

    anyhow::bail!("Cloudflare {} {} failed: {}", method, url, errs)
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareProvider {
    fn name(&self) -> &'static str {
        "Cloudflare"
    }

    fn propagation_delay(&self) -> u64 {
        self.delay
    }

    async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()> {
        let (zone_name, zone_id) = self.find_zone(domain).await?;
        let record_name = format!("_acme-challenge.{}", domain);
        tracing::info!(
            "Cloudflare: deploying TXT {} → \"{}\" in zone {}",
            record_name,
            token_value,
            zone_name
        );

        // Idempotency: if a stale challenge record from a previous failed run
        // is still there, drop it first so we don't end up with two TXTs and
        // confuse the ACME server.
        self.clean_challenge(domain).await.ok();

        let url = format!("{}/zones/{}/dns_records", API_BASE, zone_id);
        let body = json!({
            "type": "TXT",
            "name": record_name,
            "content": token_value,
            "ttl": 60,
            "proxied": false,
        });
        let (k, v) = self.auth_header();
        let resp = self
            .http
            .post(&url)
            .header(k, v)
            .json(&body)
            .send()
            .await
            .with_context(|| format!("Cloudflare: POST {}", url))?;
        parse_cf_response(resp, "POST", &url).await?;
        Ok(())
    }

    async fn clean_challenge(&self, domain: &str) -> Result<()> {
        let (_zone_name, zone_id) = self.find_zone(domain).await?;
        let record_name = format!("_acme-challenge.{}", domain);

        // List matching TXT records (there should be at most one but we handle
        // duplicates from earlier failed runs).
        let list_url = format!(
            "{}/zones/{}/dns_records?type=TXT&name={}&per_page=100",
            API_BASE, zone_id, record_name
        );
        let body = self.get_json(&list_url).await?;
        let records = body
            .get("result")
            .and_then(|r| r.as_array())
            .cloned()
            .unwrap_or_default();

        for rec in records {
            let Some(id) = rec.get("id").and_then(|v| v.as_str()) else {
                continue;
            };
            let url = format!("{}/zones/{}/dns_records/{}", API_BASE, zone_id, id);
            let (k, v) = self.auth_header();
            let resp = self
                .http
                .delete(&url)
                .header(k, v)
                .send()
                .await
                .with_context(|| format!("Cloudflare: DELETE {}", url))?;
            // Best effort — log but don't fail the renewal if cleanup hits an error.
            if let Err(e) = parse_cf_response(resp, "DELETE", &url).await {
                tracing::warn!("Cloudflare: failed to delete record {}: {}", id, e);
            }
        }
        Ok(())
    }

    async fn list_zones(&self) -> Result<Vec<String>> {
        let zones = self.list_all_zones().await?;
        Ok(zones.into_iter().map(|(n, _)| n).collect())
    }
}
