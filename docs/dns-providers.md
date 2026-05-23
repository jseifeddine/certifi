# DNS providers

Certifi uses DNS-01 challenges, so it needs API access to your authoritative DNS provider to create/delete `_acme-challenge.<domain>` TXT records during issuance.

You can configure **multiple integrations**. Their zones are unioned for autocomplete and pre-flight validation; when a challenge needs to be deployed, Certifi picks the first integration whose zones cover the requested domain (creation-order tie-break). Disabling an integration takes effect immediately on the next request.

## Adding an integration

Sign in to the web admin → **Settings → DNS Integrations → Add Integration**. Pick a provider, fill in its config, save. Use **Test** on the card to confirm credentials by listing zones.

Programmatic alternative: `POST /api/integrations` — see [api.md](api.md#dns-integrations).

## Multiple integrations of the same kind

Allowed. For example: two Cloudflare accounts, one for production zones and one for staging. The cards UI shows a warning banner when multiple of the same kind are enabled, since their zones can overlap and routing becomes load-bearing.

The first integration (by creation timestamp) wins for any domain its zones cover. Subsequent integrations only handle domains the earlier ones don't.

## Plugin model

Each provider implements the `DnsProvider` trait in `crates/certifi-server/src/integrations/mod.rs`:

```rust
async fn deploy_challenge(&self, domain: &str, token_value: &str) -> Result<()>;
async fn clean_challenge(&self, domain: &str) -> Result<()>;
async fn list_zones(&self) -> Result<Vec<String>>;
fn propagation_delay(&self) -> u64;
fn name(&self) -> &'static str;
```

`available_integrations()` returns metadata (id, name, fields) that drives the web admin's "Add Integration" form. Adding a new kind requires no UI changes for new field types. See [development.md](development.md#adding-a-dns-provider) for the step-by-step.

The five providers shipped today:

| Kind | Auth | Notes |
|---|---|---|
| [`pdns`](#powerdns) | `X-API-Key` header | API URL is configurable — useful for self-hosted setups |
| [`cloudflare`](#cloudflare) | `Authorization: Bearer` | Scoped API tokens, fast propagation |
| [`digitalocean`](#digitalocean) | `Authorization: Bearer` | Lists all domains and suffix-matches in Rust |
| [`hetzner`](#hetzner-dns) | `Auth-API-Token` header | Different from Hetzner Cloud — easy to mix up |
| [`gandi`](#gandi-livedns) | `Authorization: Bearer` (PAT) | rrset-based — DELETE is one call |

---

## PowerDNS

Self-hosted, suitable when you run your own authoritative DNS.

| Field (config key) | Description |
|---|---|
| API URL (`pdns_url`) | Full URL incl. scheme — e.g. `https://pdns-api.example.com` (TLS) or `http://10.0.0.1:8081` (plain). Self-signed certs are accepted. |
| API Key (`pdns_key`) | The `api-key` value from your `pdns.conf` |
| Propagation Delay (`pdns_wait`) | Seconds to wait after creating the TXT before notifying the CA. Increase (e.g. `30`) if you have secondaries that need time to sync. |
| Server ID (`pdns_server`) | Leave blank for auto-detect. Set explicitly if auto-detect fails (usually `localhost`). |

Certifi sends a PDNS `NOTIFY` after each record change to trigger immediate zone transfer to secondaries.

## Cloudflare

The recommended setup for most users — scoped API tokens, very fast propagation.

| Field (config key) | Description |
|---|---|
| API Token (`cf_api_token`) | Create at [Cloudflare → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens). Use a **Custom token** with the minimum scopes below. |
| Propagation Delay (`cf_wait`) | `10` is usually enough. |

**Required token permissions:**

- **Zone → Zone → Read** (across all zones, or scoped to specific zones)
- **Zone → DNS → Edit** (across all zones, or scoped to specific zones)

The legacy Global API Key flow is **not** supported — it has no scoping.

## DigitalOcean

| Field (config key) | Description |
|---|---|
| API Token (`do_api_token`) | Create at [DigitalOcean → API → Tokens](https://cloud.digitalocean.com/account/api/tokens). Needs **read + write** scope on the Domain Records resource. |
| Propagation Delay (`do_wait`) | `30` — DO can take ~30s to propagate to all nameservers. |

DigitalOcean has no zone-lookup-by-name endpoint, so Certifi lists every domain on the account and suffix-matches in Rust. The token therefore needs visibility into every domain you want to issue for.

## Hetzner DNS

> **Different product from Hetzner Cloud.** They use different APIs and different tokens. Generate yours at **dns.hetzner.com → API tokens**, NOT in the Hetzner Cloud console.

| Field (config key) | Description |
|---|---|
| API Token (`hetzner_api_token`) | From [dns.hetzner.com](https://dns.hetzner.com) → API tokens |
| Propagation Delay (`hetzner_wait`) | `10` |

## Gandi LiveDNS

Popular for many European users since Gandi is also a registrar.

| Field (config key) | Description |
|---|---|
| Personal Access Token (`gandi_pat`) | Create at [account.gandi.net → Authentication → Personal Access Token](https://account.gandi.net). Scope to the right organization and grant DNS management on the domains you'll issue for. |
| Propagation Delay (`gandi_wait`) | `10` |

Gandi groups TXT records by `(name, type)` rrsets. Certifi's `deploy_challenge` uses `PUT` to replace the rrset atomically — clearing any leftover challenge from a previous failed run in the same call.

---

## Testing an integration

Each card in the web admin has a **Test** button → calls `POST /api/integrations/:id/test` and shows the zone count + first few zones. Quick way to confirm credentials are right before you try to issue a real cert.

## Domain autocomplete

`GET /api/domains` returns the union of all enabled integrations' zones. The web admin uses this for autocomplete in the New Certificate dialog. If you have a lot of zones and the dropdown feels sluggish, that's where to look.

## Why aren't AWS Route 53, GCP, Azure here yet?

Those need significant additional auth infrastructure — SigV4 request signing for Route 53, OAuth2 service-account JWTs for GCP DNS, Azure AD token exchange for Azure DNS. Each is a half-day's work on its own, with non-trivial dep additions. See the open issues / development notes if you want to contribute one.
