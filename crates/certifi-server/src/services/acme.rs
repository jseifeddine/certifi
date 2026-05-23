use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ring::{
    rand::SystemRandom,
    signature::{EcdsaKeyPair, KeyPair, ECDSA_P384_SHA384_FIXED_SIGNING},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

use crate::integrations::DnsProvider;

// ── Wire types ───────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct AcmeOrder {
    status: String,
    authorizations: Vec<String>,
    finalize: String,
    certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AcmeAuth {
    identifier: AcmeIdentifier,
    status: String,
    challenges: Vec<AcmeChallenge>,
}

#[derive(Debug, Deserialize)]
struct AcmeIdentifier {
    value: String,
}

#[derive(Debug, Deserialize)]
struct AcmeChallenge {
    #[serde(rename = "type")]
    kind: String,
    url: String,
    token: String,
}

// ── Public types ─────────────────────────────────────────────────────────────

/// Stored account credentials (serialised to/from DB settings).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountCredentials {
    pub key_pkcs8_b64: String, // base64(PKCS8 DER of account key)
    pub account_url: String,
}

pub struct IssuedCert {
    pub fullchain_pem: String,
    pub cert_pem: String,
    pub chain_pem: String,
    pub privkey_pem: String,
    // Populated from the issued leaf; callers currently re-derive expiry from
    // the PEM, but the field is part of the issuance result contract.
    #[allow(dead_code)]
    pub expires_at: Option<String>,
}

// ── ACME client ──────────────────────────────────────────────────────────────

pub struct AcmeClient {
    http: reqwest::Client,
    directory: Directory,
    key: EcdsaKeyPair,
    rng: SystemRandom,
    jwk: Value,
    thumbprint: String,
    account_url: String,
    key_pkcs8: Vec<u8>,
}

impl AcmeClient {
    /// Load existing account from stored credentials.
    pub async fn from_credentials(ca_url: &str, creds: &AccountCredentials) -> Result<Self> {
        let http = build_http_client();
        let directory = fetch_directory(&http, ca_url).await?;

        let pkcs8 = STANDARD.decode(&creds.key_pkcs8_b64)?;
        let rng = SystemRandom::new();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &pkcs8, &rng)
            .map_err(|e| anyhow::anyhow!("Invalid account key: {:?}", e))?;

        let (jwk, thumbprint) = ec_jwk_and_thumbprint(key.public_key().as_ref())?;

        Ok(Self {
            http,
            directory,
            key,
            rng,
            jwk,
            thumbprint,
            account_url: creds.account_url.clone(),
            key_pkcs8: pkcs8,
        })
    }

    /// Register a new ACME account (first-time use).
    pub async fn register(ca_url: &str) -> Result<(Self, AccountCredentials)> {
        let http = build_http_client();
        let directory = fetch_directory(&http, ca_url).await?;

        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, &rng)
            .map_err(|e| anyhow::anyhow!("Key generation failed: {:?}", e))?;
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .map_err(|e| anyhow::anyhow!("Key load failed: {:?}", e))?;
        let (jwk, thumbprint) = ec_jwk_and_thumbprint(key.public_key().as_ref())?;

        let mut client = Self {
            http,
            directory,
            key,
            rng,
            jwk,
            thumbprint,
            account_url: String::new(),
            key_pkcs8: pkcs8.as_ref().to_vec(),
        };

        let nonce = client.new_nonce().await?;
        // Use JWK (not KID) for new account
        let body = client.sign_with_jwk(
            &client.directory.new_account.clone(),
            &nonce,
            Some(&json!({"termsOfServiceAgreed": true, "contact": []})),
        )?;

        let resp = client
            .http
            .post(&client.directory.new_account)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .context("ACME newAccount request")?;

        let account_url = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        if account_url.is_empty() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("ACME account registration failed ({}): {}", status, body);
        }

        tracing::info!("ACME account registered: {}", account_url);
        client.account_url = account_url.clone();

        let creds = AccountCredentials {
            key_pkcs8_b64: STANDARD.encode(&client.key_pkcs8),
            account_url,
        };

        Ok((client, creds))
    }

    /// Serialize the account key + URL for persistence. Retained as part of the
    /// client's public surface even where the current flow re-loads creds.
    #[allow(dead_code)]
    pub fn credentials(&self) -> AccountCredentials {
        AccountCredentials {
            key_pkcs8_b64: STANDARD.encode(&self.key_pkcs8),
            account_url: self.account_url.clone(),
        }
    }

    // ── Core issuance flow ───────────────────────────────────────────────────

    pub async fn issue_certificate(
        &self,
        cn: &str,
        sans: &[String],
        key_algo: &str,
        dns: &dyn DnsProvider,
    ) -> Result<IssuedCert> {
        // Deduplicate domains (CN + SANs)
        let mut domains = vec![cn.to_string()];
        for s in sans {
            if !domains.contains(s) {
                domains.push(s.clone());
            }
        }

        // ── 1. Create order ──────────────────────────────────────────────────
        let identifiers: Vec<Value> = domains
            .iter()
            .map(|d| json!({"type": "dns", "value": d}))
            .collect();

        let order_resp = self
            .post(
                &self.directory.new_order.clone(),
                Some(&json!({"identifiers": identifiers})),
            )
            .await?;

        let order_url = order_resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_default();

        ensure_success(&order_resp.status(), "newOrder")?;
        let order: AcmeOrder = order_resp.json().await.context("parse order")?;
        tracing::info!("ACME order created: {}", order_url);

        // ── 2. Deploy all DNS challenges first ───────────────────────────────
        let mut deployed: Vec<String> = Vec::new();
        let mut pending_challenge_urls: Vec<String> = Vec::new();

        for auth_url in &order.authorizations {
            let auth_resp = self.post_as_get(auth_url).await?;
            let auth: AcmeAuth = auth_resp.json().await.context("parse auth")?;

            tracing::info!(
                "ACME auth {} status: {}",
                auth.identifier.value,
                auth.status
            );

            if auth.status == "valid" {
                continue;
            }

            let challenge = auth
                .challenges
                .iter()
                .find(|c| c.kind == "dns-01")
                .ok_or_else(|| {
                    anyhow::anyhow!("No dns-01 challenge for {}", auth.identifier.value)
                })?;

            let key_auth = format!("{}.{}", challenge.token, self.thumbprint);
            let dns_value = b64url(&sha256(key_auth.as_bytes()));

            let domain = &auth.identifier.value;
            tracing::info!("Deploying DNS challenge for {}", domain);

            if let Err(e) = dns.deploy_challenge(domain, &dns_value).await {
                self.cleanup(&deployed, dns).await;
                return Err(e.context(format!("DNS challenge deploy for {}", domain)));
            }
            deployed.push(domain.clone());
            pending_challenge_urls.push(challenge.url.clone());
        }

        // ── 3. Wait for DNS propagation (before notifying ACME) ──────────────
        if !pending_challenge_urls.is_empty() {
            let delay = dns.propagation_delay();
            if delay > 0 {
                tracing::info!("Waiting {}s for DNS propagation...", delay);
                sleep(Duration::from_secs(delay)).await;
            }

            // ── 4. Now notify ACME that all challenges are ready ──────────────
            for challenge_url in &pending_challenge_urls {
                let resp = self.post(challenge_url, Some(&json!({}))).await?;
                if !resp.status().is_success() {
                    let body = resp.text().await.unwrap_or_default();
                    self.cleanup(&deployed, dns).await;
                    anyhow::bail!("ACME challenge notify failed: {}", body);
                }
            }
        }

        // ── 5. Poll until order is ready ─────────────────────────────────────
        tracing::info!("Polling for authorization...");
        let ready_result = self.poll_order_ready(&order_url, 120).await;

        if let Err(e) = ready_result {
            self.cleanup(&deployed, dns).await;
            return Err(e);
        }

        // ── 6. Clean up DNS records ───────────────────────────────────────────
        self.cleanup(&deployed, dns).await;

        // ── 7. Generate cert key + CSR ────────────────────────────────────────
        let (privkey_pem, csr_der) = generate_csr(cn, &domains, key_algo)?;

        // ── 8. Finalize order ─────────────────────────────────────────────────
        tracing::info!("Finalizing ACME order...");
        let fin_resp = self
            .post(&order.finalize, Some(&json!({"csr": b64url(&csr_der)})))
            .await?;

        if !fin_resp.status().is_success() {
            let body = fin_resp.text().await.unwrap_or_default();
            anyhow::bail!("ACME finalize failed: {}", body);
        }

        // ── 9. Poll until certificate is available ───────────────────────────
        let cert_chain = self.poll_certificate(&order_url, 120).await?;
        tracing::info!("Certificate issued for {}", cn);

        let (cert_pem, chain_pem) = split_pem_chain(&cert_chain);
        let expires_at = cert_expiry_from_pem(&cert_pem);

        Ok(IssuedCert {
            fullchain_pem: cert_chain,
            cert_pem,
            chain_pem,
            privkey_pem,
            expires_at,
        })
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    async fn new_nonce(&self) -> Result<String> {
        let resp = self
            .http
            .head(&self.directory.new_nonce)
            .send()
            .await
            .context("ACME: fetch nonce")?;
        resp.headers()
            .get("replay-nonce")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No Replay-Nonce in response"))
    }

    /// Sign with JWK header (for newAccount only).
    fn sign_with_jwk(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<Value> {
        let protected = json!({
            "alg": "ES384",
            "jwk": self.jwk,
            "nonce": nonce,
            "url": url,
        });
        self.build_jws(protected, url, nonce, payload)
    }

    /// Sign with KID header (all requests after account creation).
    fn sign_with_kid(&self, url: &str, nonce: &str, payload: Option<&Value>) -> Result<Value> {
        let protected = json!({
            "alg": "ES384",
            "kid": self.account_url,
            "nonce": nonce,
            "url": url,
        });
        self.build_jws(protected, url, nonce, payload)
    }

    fn build_jws(
        &self,
        protected: Value,
        _url: &str,
        _nonce: &str,
        payload: Option<&Value>,
    ) -> Result<Value> {
        let payload_b64 = match payload {
            Some(p) => b64url(serde_json::to_string(p)?.as_bytes()),
            None => String::new(), // POST-as-GET
        };

        let protected_b64 = b64url(serde_json::to_string(&protected)?.as_bytes());
        let signing_input = format!("{}.{}", protected_b64, payload_b64);

        let sig = self
            .key
            .sign(&self.rng, signing_input.as_bytes())
            .map_err(|e| anyhow::anyhow!("ECDSA sign failed: {:?}", e))?;

        Ok(json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": b64url(sig.as_ref()),
        }))
    }

    async fn post(&self, url: &str, payload: Option<&Value>) -> Result<reqwest::Response> {
        let nonce = self.new_nonce().await?;
        let body = self.sign_with_kid(url, &nonce, payload)?;
        let resp = self
            .http
            .post(url)
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await
            .with_context(|| format!("ACME POST to {}", url))?;
        Ok(resp)
    }

    async fn post_as_get(&self, url: &str) -> Result<reqwest::Response> {
        self.post(url, None).await
    }

    async fn poll_order_ready(&self, order_url: &str, timeout_secs: u64) -> Result<()> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!(
                    "Timed out waiting for ACME authorization ({}s)",
                    timeout_secs
                );
            }
            sleep(Duration::from_secs(5)).await;

            let resp = self.post_as_get(order_url).await?;
            let order: AcmeOrder = resp.json().await.context("parse order poll")?;

            match order.status.as_str() {
                "ready" => return Ok(()),
                "invalid" | "pending" => {
                    // Fetch each auth to find the actual failure reason
                    for auth_url in &order.authorizations {
                        let ar = self.post_as_get(auth_url).await?;
                        let body: Value = ar.json().await.context("parse auth poll")?;
                        let status = body
                            .get("status")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown");
                        if status == "invalid" {
                            let domain = body
                                .pointer("/identifier/value")
                                .and_then(|v| v.as_str())
                                .unwrap_or("?");
                            let reason = body
                                .get("challenges")
                                .and_then(|cs| cs.as_array())
                                .and_then(|cs| cs.iter().find(|c| c.get("error").is_some()))
                                .and_then(|c| c.get("error"))
                                .and_then(|e| e.get("detail"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown reason");
                            anyhow::bail!("ACME validation failed for {}: {}", domain, reason);
                        }
                    }
                    if order.status == "invalid" {
                        anyhow::bail!("ACME order became invalid");
                    }
                }
                _ => {}
            }
        }
    }

    async fn poll_certificate(&self, order_url: &str, timeout_secs: u64) -> Result<String> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!("Timed out waiting for certificate ({}s)", timeout_secs);
            }
            sleep(Duration::from_secs(5)).await;

            let resp = self.post_as_get(order_url).await?;
            let order: AcmeOrder = resp.json().await.context("parse order cert poll")?;

            match order.status.as_str() {
                "valid" => {
                    if let Some(cert_url) = order.certificate {
                        let cert_resp = self.post_as_get(&cert_url).await?;
                        return cert_resp.text().await.context("download cert");
                    }
                }
                "invalid" => anyhow::bail!("ACME order became invalid after finalize"),
                _ => {}
            }
        }
    }

    async fn cleanup(&self, deployed: &[String], dns: &dyn DnsProvider) {
        for domain in deployed {
            if let Err(e) = dns.clean_challenge(domain).await {
                tracing::warn!("DNS cleanup failed for {}: {}", domain, e);
            }
        }
    }
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use ring::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

/// Build the JWK public key object and compute its thumbprint for ES384 (P-384).
/// `pub_key_bytes` must be the uncompressed EC point: 0x04 || x (48) || y (48)
fn ec_jwk_and_thumbprint(pub_key_bytes: &[u8]) -> Result<(Value, String)> {
    // Uncompressed: 0x04 | x[48] | y[48]
    if pub_key_bytes.len() != 97 || pub_key_bytes[0] != 0x04 {
        anyhow::bail!("Unexpected public key format (len={})", pub_key_bytes.len());
    }
    let x = b64url(&pub_key_bytes[1..49]);
    let y = b64url(&pub_key_bytes[49..97]);

    let jwk = json!({"crv": "P-384", "kty": "EC", "x": x, "y": y});

    // Thumbprint: SHA256 of canonical JSON (sorted keys, no spaces)
    let canonical = format!(
        "{{\"crv\":\"P-384\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
        x, y
    );
    let thumbprint = b64url(&sha256(canonical.as_bytes()));

    Ok((jwk, thumbprint))
}

// ── CSR generation ────────────────────────────────────────────────────────────

/// Dispatch to the correct CSR generator based on `key_algo`.
/// Valid values: "ec-p256", "ec-p384", "rsa-2048", "rsa-4096"
fn generate_csr(cn: &str, domains: &[String], key_algo: &str) -> Result<(String, Vec<u8>)> {
    match key_algo {
        "rsa-2048" => generate_rsa_csr(cn, 2048),
        "rsa-4096" => generate_rsa_csr(cn, 4096),
        _ => generate_ec_csr(cn, domains, key_algo),
    }
}

/// EC CSR via rcgen + ring (P-256 or P-384).
fn generate_ec_csr(cn: &str, domains: &[String], key_algo: &str) -> Result<(String, Vec<u8>)> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    let alg = if key_algo.contains("256") || key_algo.contains("prime256") {
        &rcgen::PKCS_ECDSA_P256_SHA256
    } else {
        &rcgen::PKCS_ECDSA_P384_SHA384
    };

    let key = KeyPair::generate_for(alg)?;
    let privkey_pem = key.serialize_pem();

    let mut params = CertificateParams::new(domains.to_vec())?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);

    let csr_der = params.serialize_request(&key)?.der().to_vec();
    Ok((privkey_pem, csr_der))
}

/// RSA CSR via openssl (2048 or 4096 bits).
///
/// The CSR contains only the CN; SANs are set by the ACME order identifiers,
/// which the CA (e.g. Let's Encrypt) uses to populate the issued certificate
/// regardless of what the CSR itself contains.
fn generate_rsa_csr(cn: &str, bits: u32) -> Result<(String, Vec<u8>)> {
    use anyhow::Context as _;
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509NameBuilder, X509ReqBuilder};

    let rsa = Rsa::generate(bits).context("RSA key generation")?;
    let pkey = PKey::from_rsa(rsa).context("RSA PKey wrapping")?;

    // Emit PKCS#8 PEM (-----BEGIN PRIVATE KEY-----) for consistency with EC output
    let privkey_pem = String::from_utf8(
        pkey.private_key_to_pem_pkcs8()
            .context("RSA PKCS#8 PEM encoding")?,
    )
    .context("RSA PEM is not valid UTF-8")?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_text("CN", cn)?;

    let mut req = X509ReqBuilder::new()?;
    req.set_pubkey(&pkey)?;
    req.set_subject_name(&name.build())?;
    req.sign(&pkey, MessageDigest::sha256())?;

    let csr_der = req.build().to_der()?;
    Ok((privkey_pem, csr_der))
}

// ── PEM / cert utilities ─────────────────────────────────────────────────────

fn split_pem_chain(chain: &str) -> (String, String) {
    const MARKER: &str = "-----BEGIN CERTIFICATE-----";
    let positions: Vec<usize> = chain.match_indices(MARKER).map(|(i, _)| i).collect();

    if positions.len() <= 1 {
        return (chain.to_string(), String::new());
    }

    let leaf = chain[positions[0]..positions[1]].trim_end().to_string();
    let rest = chain[positions[1]..].trim_end().to_string();
    (leaf + "\n", rest + "\n")
}

pub fn cert_expiry_from_pem(cert_pem: &str) -> Option<String> {
    use x509_parser::prelude::*;

    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes()).ok()?;
    let (_, cert) = X509Certificate::from_der(&pem.contents).ok()?;
    let ts = cert.validity().not_after.timestamp();
    chrono::DateTime::from_timestamp(ts, 0).map(|dt| dt.to_rfc3339())
}

pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let b64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    STANDARD.decode(b64.trim()).unwrap_or_default()
}

// ── HTTP client ───────────────────────────────────────────────────────────────

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .user_agent("Certifi/0.1 (ACME client)")
        .build()
        .expect("build http client")
}

async fn fetch_directory(http: &reqwest::Client, ca_url: &str) -> Result<Directory> {
    http.get(ca_url)
        .send()
        .await
        .context("fetch ACME directory")?
        .json()
        .await
        .context("parse ACME directory")
}

fn ensure_success(status: &reqwest::StatusCode, context: &str) -> Result<()> {
    if !status.is_success() {
        anyhow::bail!("ACME {} returned HTTP {}", context, status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_is_unpadded_and_url_safe() {
        assert_eq!(b64url(b"hello"), "aGVsbG8");
        // 0xfb,0xff encodes to "+/8=" in standard base64; the URL-safe,
        // unpadded form swaps +/ for -_ and drops the trailing '='.
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url(b""), "");
    }

    #[test]
    fn split_pem_chain_single_cert_has_empty_remainder() {
        let leaf = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let (got_leaf, rest) = split_pem_chain(leaf);
        assert_eq!(got_leaf, leaf);
        assert!(rest.is_empty());
    }

    #[test]
    fn split_pem_chain_separates_leaf_from_intermediates() {
        let leaf = "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n";
        let inter = "-----BEGIN CERTIFICATE-----\nINTER\n-----END CERTIFICATE-----\n";
        let chain = format!("{leaf}{inter}");
        let (got_leaf, rest) = split_pem_chain(&chain);
        assert!(got_leaf.contains("LEAF") && !got_leaf.contains("INTER"));
        assert!(rest.contains("INTER") && !rest.contains("LEAF"));
    }

    #[test]
    fn pem_to_der_strips_armor_and_decodes_body() {
        // "AQIDBAU=" is the base64 of the bytes 1..=5.
        let pem = "-----BEGIN CERTIFICATE-----\nAQIDBAU=\n-----END CERTIFICATE-----\n";
        assert_eq!(pem_to_der(pem), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn pem_to_der_returns_empty_on_garbage() {
        assert!(pem_to_der("not a pem").is_empty());
    }
}
