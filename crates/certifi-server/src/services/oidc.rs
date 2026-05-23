//! OIDC client wiring.
//!
//! Phase 3 supports a single configured IdP — Authentik, Keycloak, Google,
//! Azure AD, Okta, anyone speaking OIDC discovery. The flow is the standard
//! authorization-code + PKCE: `/api/auth/oidc/start` returns an IdP URL plus
//! a state UUID; the IdP redirects back to `/api/oidc/callback` (registered
//! as the redirect_uri), which exchanges the code, verifies the id_token
//! (issuer, audience, signature, nonce), JIT-provisions the user if
//! `oidc_create_users` is on, and syncs role assignments from the configured
//! group mappings.
//!
//! The openidconnect crate's generic surface for additional claims is heavy
//! enough that we deliberately keep it as `CoreClient`/`EmptyAdditionalClaims`
//! and do a second pass on the id_token JWT payload to pull out whichever
//! group / username / email claim the operator configured. The signature has
//! already been verified by the time we re-parse the payload, so this is
//! purely a deserialisation convenience — no security implications.

use crate::config::Config;
use crate::handlers::settings::load_all_settings;
use crate::models::*;
use crate::services::secret;
use crate::AppState;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope,
};
use std::collections::HashMap;

type ConfiguredCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Snapshot of the OIDC settings that's safe to pass around — secrets are
/// decrypted only at the call site that needs to exchange a code.
#[derive(Debug, Clone)]
pub struct OidcSettings {
    #[allow(dead_code)] // gating is done before this snapshot is built
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub group_claim: String,
    pub username_claim: String,
    pub email_claim: String,
    pub create_users: bool,
    /// When true, the /login page auto-redirects to the IdP instead of
    /// rendering the local form. Surface-only — the API still accepts local
    /// credentials for callers that bypass the SPA (curl, automation).
    pub force_login: bool,
}

impl OidcSettings {
    /// Load and validate the settings from the DB + env-var overrides. Returns
    /// `Ok(None)` if OIDC is disabled or under-configured (caller may still
    /// want to show local-login-only UI without erroring).
    pub async fn load(state: &AppState) -> Result<Option<Self>> {
        let map = load_all_settings(state)
            .await
            .map_err(|e| anyhow!("loading settings: {:?}", e))?;

        let enabled = parse_bool(map.get(S_OIDC_ENABLED));
        if !enabled {
            return Ok(None);
        }
        let issuer = get_or_empty(&map, S_OIDC_ISSUER);
        let client_id = get_or_empty(&map, S_OIDC_CLIENT_ID);
        let secret_value = get_or_empty(&map, S_OIDC_CLIENT_SECRET);
        let redirect_uri = get_or_empty(&map, S_OIDC_REDIRECT_URI);
        if issuer.is_empty() || client_id.is_empty() || redirect_uri.is_empty() {
            return Ok(None);
        }

        // Decrypt the client_secret if it looks encrypted (created via the
        // admin UI). When supplied via env var or set directly, accept plaintext.
        let client_secret = match secret::decrypt(&secret_value, &state.config.cookie_key) {
            Ok(plain) => plain,
            Err(_) => secret_value,
        };
        if client_secret.is_empty() {
            return Ok(None);
        }

        let scopes = parse_scopes(map.get(S_OIDC_SCOPES));
        let group_claim = map
            .get(S_OIDC_GROUP_CLAIM)
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OIDC_DEFAULT_GROUP_CLAIM.to_string());
        let username_claim = map
            .get(S_OIDC_USERNAME_CLAIM)
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OIDC_DEFAULT_USERNAME_CLAIM.to_string());
        let email_claim = map
            .get(S_OIDC_EMAIL_CLAIM)
            .cloned()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| OIDC_DEFAULT_EMAIL_CLAIM.to_string());
        let create_users = parse_bool(map.get(S_OIDC_CREATE_USERS));
        let force_login = parse_bool(map.get(S_OIDC_FORCE_LOGIN));

        Ok(Some(OidcSettings {
            enabled,
            issuer,
            client_id,
            client_secret,
            redirect_uri,
            scopes,
            group_claim,
            username_claim,
            email_claim,
            create_users,
            force_login,
        }))
    }
}

fn parse_bool(v: Option<&String>) -> bool {
    matches!(
        v.map(|s| s.to_ascii_lowercase()).as_deref(),
        Some("true" | "1" | "yes")
    )
}
fn get_or_empty(map: &HashMap<String, String>, key: &str) -> String {
    map.get(key).cloned().unwrap_or_default()
}
fn parse_scopes(v: Option<&String>) -> Vec<String> {
    let raw = v
        .cloned()
        .unwrap_or_else(|| OIDC_DEFAULT_SCOPES.to_string());
    raw.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Build a fresh `reqwest::Client` for OIDC traffic. `redirect = none` is
/// required by the openidconnect crate so it can observe 3xx responses
/// during token exchange.
fn http_client() -> Result<reqwest::Client> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| anyhow!("oidc http client: {}", e))
}

/// Discover the IdP and return a configured client plus the
/// `end_session_endpoint` advertised by the discovery doc (if any). The
/// callback handler caches the URL on the session row so the logout
/// handler can build an RP-initiated-logout redirect later.
pub async fn build_client(
    _config: &Config,
    settings: &OidcSettings,
) -> Result<(ConfiguredCoreClient, Option<String>)> {
    let http = http_client()?;
    let issuer = IssuerUrl::new(settings.issuer.clone()).context("invalid OIDC issuer URL")?;
    // Discovery hits `<issuer>/.well-known/openid-configuration` and then
    // `jwks_uri` from the returned metadata. We log only the first URL —
    // the crate constructs both itself, we mirror the convention.
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        settings.issuer.trim_end_matches('/'),
    );
    tracing::info!("OIDC: discovering {}", discovery_url);
    let provider_metadata = CoreProviderMetadata::discover_async(issuer, &http)
        .await
        .map_err(|e| {
            // openidconnect's discovery error keeps the underlying reqwest /
            // parse / signature error in its source chain. Log the whole
            // chain on the server side so an operator looking at the log
            // sees more than "discovery failed".
            let mut parts: Vec<String> = vec![e.to_string()];
            let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
            while let Some(s) = src { parts.push(s.to_string()); src = s.source(); }
            let chain = parts.join(" -> ");
            tracing::warn!("OIDC discovery failed for {}: {}", discovery_url, chain);

            // Friendly hint for the most common cause we see — "missing
            // field `keys`" means the IdP returned a JWKs document without
            // a `keys` array, which on Authentik almost always means the
            // OIDC provider has no Signing Key configured. Append a hint
            // so the operator doesn't have to guess.
            let hint = if chain.contains("missing field `keys`") {
                "\n\nHint: the IdP's JWKs document has no `keys`. On Authentik, open the OIDC provider and set the Signing Key (e.g. \"authentik Self-signed Certificate\")."
            } else {
                ""
            };
            anyhow!("{}{}", parts.join(": "), hint)
        })
        .context("OIDC discovery failed")?;
    // Snapshot the end_session_endpoint advertised by discovery. It's part
    // of the OpenID Session Management spec and not exposed as a typed
    // field on CoreProviderMetadata, so we re-fetch + parse just the one
    // value. Cheap (a single GET) and keeps the rest of the openidconnect
    // wiring untouched. None is fine — older IdPs don't advertise this,
    // and logout silently falls back to local-only.
    let end_session_url = fetch_end_session_endpoint(&http, &discovery_url).await;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(settings.client_id.clone()),
        Some(ClientSecret::new(settings.client_secret.clone())),
    )
    .set_redirect_uri(
        RedirectUrl::new(settings.redirect_uri.clone()).context("invalid OIDC redirect URI")?,
    );
    Ok((client, end_session_url))
}

/// Best-effort pluck of the `end_session_endpoint` field from the IdP's
/// discovery document. Logged-and-ignored on failure — RP-initiated
/// logout is optional, missing/broken just means we fall back to a plain
/// local cookie clear.
async fn fetch_end_session_endpoint(http: &reqwest::Client, url: &str) -> Option<String> {
    let resp = match http.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("OIDC: end_session_endpoint discovery skip ({})", e);
            return None;
        }
    };
    let doc: serde_json::Value = match resp.json().await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("OIDC: end_session_endpoint parse skip ({})", e);
            return None;
        }
    };
    doc.get("end_session_endpoint")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Build the IdP authorize URL. Returns the URL the browser should be
/// redirected to plus the `(state, nonce, pkce_verifier)` triple the caller
/// must persist for callback verification.
pub fn authorize_url(
    client: &ConfiguredCoreClient,
    scopes: &[String],
) -> (String, CsrfToken, Nonce, PkceCodeVerifier) {
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let mut builder = client.authorize_url(
        AuthenticationFlow::<openidconnect::core::CoreResponseType>::AuthorizationCode,
        CsrfToken::new_random,
        Nonce::new_random,
    );
    for s in scopes {
        builder = builder.add_scope(Scope::new(s.clone()));
    }
    let (url, csrf, nonce) = builder.set_pkce_challenge(pkce_challenge).url();
    (url.to_string(), csrf, nonce, pkce_verifier)
}

/// Subset of an id_token's claims we care about. Standard fields are pulled
/// from the openidconnect crate's verified view; custom-name fields
/// (`group_claim`, `username_claim`, `email_claim`) are pulled from a second
/// JSON parse of the JWT payload AFTER verification.
pub struct OidcLoginResult {
    pub subject: String,
    pub issuer: String,
    pub email: Option<String>,
    pub username: Option<String>,
    pub groups: Vec<String>,
    /// Raw id_token (the compact JWS string), stashed on the session row
    /// so logout can pass it as `id_token_hint` to the IdP.
    pub id_token: String,
    /// IdP `end_session_endpoint` from discovery, if it advertised one.
    /// `None` means RP-initiated logout isn't supported by this provider —
    /// the logout handler falls back to clearing the local cookie only.
    pub end_session_url: Option<String>,
}

/// Coerce a JSON claim into a string list. Accepts a JSON array of strings,
/// a single string with comma/space separators, or null/missing.
fn coerce_groups(v: Option<&serde_json::Value>) -> Vec<String> {
    let Some(v) = v else { return Vec::new() };
    match v {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect(),
        serde_json::Value::String(s) => s
            .split(|c: char| c == ',' || c.is_whitespace())
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

/// Decode the JWT payload segment (already signature-verified by openidconnect)
/// to a free-form JSON value. We use this only to read additional claims by
/// the operator-configured names.
fn decode_payload(jwt: &str) -> Result<serde_json::Value> {
    let mut parts = jwt.split('.');
    let _header = parts.next();
    let payload = parts
        .next()
        .ok_or_else(|| anyhow!("malformed id_token: missing payload segment"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .context("id_token payload is not valid base64url")?;
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).context("id_token payload is not valid JSON")?;
    Ok(value)
}

pub async fn exchange_code(
    client: &ConfiguredCoreClient,
    settings: &OidcSettings,
    code: String,
    pkce_verifier: PkceCodeVerifier,
    expected_nonce: &Nonce,
    end_session_url: Option<String>,
) -> Result<OidcLoginResult> {
    let http = http_client()?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http)
        .await
        .context("OIDC token exchange failed")?;

    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or_else(|| anyhow!("IdP did not return an id_token"))?;

    // Verify signature + audience + issuer + expiry + nonce. We don't read
    // the returned claims directly because we want operator-named custom
    // fields, which the typed view doesn't expose.
    let verifier = client.id_token_verifier();
    let _verified = id_token
        .claims(&verifier, expected_nonce)
        .context("id_token claim verification failed")?;

    // Re-parse the JWT payload for the operator-configured claim names.
    let raw = id_token.to_string();
    let payload = decode_payload(&raw)?;

    let subject = payload
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("id_token has no 'sub' claim"))?
        .to_string();
    let issuer = payload
        .get("iss")
        .and_then(|v| v.as_str())
        .unwrap_or(&settings.issuer)
        .to_string();
    let email = payload
        .get(&settings.email_claim)
        .or_else(|| payload.get("email"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let username = payload
        .get(&settings.username_claim)
        .or_else(|| payload.get("preferred_username"))
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let groups = coerce_groups(payload.get(&settings.group_claim));

    Ok(OidcLoginResult {
        subject,
        issuer,
        email,
        username,
        groups,
        id_token: raw,
        end_session_url,
    })
}
