# Certificates

## ACME setup

Settings → **ACME Account** controls which CA issues your certificates.

| Field | Description |
|---|---|
| ACME CA Directory URL | The CA's directory endpoint. Let's Encrypt production: `https://acme-v02.api.letsencrypt.org/directory`; staging: `https://acme-staging-v02.api.letsencrypt.org/directory`. |
| Key Algorithm | `ECDSA P-384` (recommended) or `ECDSA P-256`. |

Click **Register** to generate a key pair and register with the CA. The account credentials are persisted in the database. Re-registering creates a new account; existing certificates continue to work with the old account info recorded against them.

> Use Let's Encrypt **staging** while you set things up — it has higher rate limits. Switch to production once issuance and DNS propagation are working end-to-end.

## Issuing

### Via web admin

1. **Certificates → New Certificate**
2. Enter the **Common Name** — the primary domain.
3. Optionally add **SANs** — additional domains covered by the same certificate.
4. Optionally add a **Description** — free-text label for your own bookkeeping.
5. Toggle **Auto-renew**.
6. **Issue Certificate**.

Issuance runs asynchronously on the server. The detail page subscribes to live events, so status transitions (`pending → issuing → active`) appear instantly — no polling, no manual refresh.

### Via API

```bash
curl -X POST https://certifi.example.com/api/certificates \
  -H "Authorization: Bearer dapi_..." \
  -H "Content-Type: application/json" \
  -d '{
    "common_name": "app.example.com",
    "sans": ["www.example.com", "api.example.com"],
    "auto_renew": true,
    "description": "production web tier"
  }'
```

Poll until `status` is `active`:

```bash
curl -H "Authorization: Bearer dapi_..." \
  https://certifi.example.com/api/certificates/<id>
```

Or subscribe to the SSE event stream and react instead of polling — see [api.md](api.md#events-sse).

### Via CLI

```bash
certifi-cli request -d app.example.com -d www.example.com \
  --description "production web tier" \
  --fullchain /etc/nginx/certs/app.fullchain.pem \
  --privkey   /etc/nginx/certs/app.privkey.pem \
  --reload-cmd "systemctl reload nginx"
```

See [cli.md](cli.md) for the full CLI reference including exit codes and cron patterns.

## Pre-flight validation

`POST /api/certificates` queries `list_zones()` across all enabled DNS integrations before queueing issuance. Every requested domain (CN + each SAN) must be covered by some managed zone — otherwise the server rejects with `400` and a clear error listing the zones it can see. This catches typos and missing integrations up-front instead of letting the ACME flow run for a minute before failing at the DNS-deploy step.

If you have zero integrations configured, every cert request gets a clear `400`: "No DNS integrations configured. Add one in Settings → DNS Integrations."

## Idempotent creation

`POST /api/certificates` is idempotent on the normalized `(common_name, sorted SAN set)`:

- If a `status='active'` cert with the same combination already exists, the server returns that cert and sets `deduplicated: true` on the response. Status code is `200 OK` rather than `202 Accepted`.
- If a `pending`/`issuing` cert with the same combination is in flight, the server folds the new request onto it (also `deduplicated: true`) instead of returning `409`. Two concurrent POSTs therefore never double-issue.
- Otherwise the server creates a new row and starts issuance asynchronously.

Normalization: trim, lowercase, strip trailing dots, dedupe SANs, drop the CN if it's repeated in the SAN list. So `Example.COM` + `[example.com., www.example.com]` is treated as `example.com` + `[www.example.com]`.

The daily renewal scheduler keeps deduplicated certs fresh, so the caller can rely on the returned cert being valid even when close to expiry — there's no per-request renewal logic on the create path.

## Renewal

The renewal scheduler runs **30 seconds after startup**, then every **24 hours**:

- Certificates with `auto_renew: true` and `< 30 days` to expiry are renewed automatically.
- Certificates with `auto_renew: false` and `< 30 days` to expiry trigger a **warning email** (if SMTP is configured) but are not renewed.
- Renewal failures are recorded in the certificate's `error` field and trigger a failure email.

Force an immediate renewal via the web admin, `POST /api/certificates/:id/renew`, or `certifi-cli renew <id-or-cn>`.

Renewal events flow through the same SSE channel as initial issuance — open web admin tabs see the status transitions live.

## Description

Each cert has an optional free-text `description` field — useful for tagging the owning service, environment, or whatever else helps operators find what they're looking for.

- Set on creation: form field on the New Certificate page, or `description` field in the API/CLI request.
- Edit later: inline editor on the detail page, or `PUT /api/certificates/:id/description`.
- Ignored on dedup hits: an existing cert's description is preserved when a new POST matches it.

## Downloads

Each certificate exposes:

| Endpoint | What it returns |
|---|---|
| `GET /api/certificates/:id/download/fullchain.pem` | Leaf + chain in one PEM blob |
| `GET /api/certificates/:id/download/cert.pem` | Leaf only |
| `GET /api/certificates/:id/download/chain.pem` | Intermediate chain only |
| `GET /api/certificates/:id/download/privkey.pem` | Private key in PEM format |
| `POST /api/certificates/:id/download/pfx` | PKCS#12 archive with generated password |

Treat the private-key endpoint with care — restrict access via your reverse proxy if you can.

The PFX password is generated on first call and persisted encrypted (AES-256-GCM with the `COOKIE_KEY`) — so re-downloading later returns the same password the user already saved. Rotating `COOKIE_KEY` invalidates stored PFX passwords; the next download generates a fresh password.

## Email notifications

Configure SMTP via the environment variables in [installation.md](installation.md#smtp-optional). Users with an email set (Users page → edit user) receive:

| Event | Trigger |
|---|---|
| Renewal success | A certificate was auto-renewed |
| Renewal failure | Auto-renewal failed |
| Expiry warning | A certificate with `auto_renew: false` is within 30 days of expiry |

Leave `SMTP_HOST` unset to disable email entirely.

## Status values

The status pipeline:

```
pending → issuing → active
                  \─→ failed
```

| Status | Meaning |
|---|---|
| `pending` | Row inserted, issuance task not yet started |
| `issuing` | ACME flow is running (DNS-01 challenge in progress) |
| `active` | Cert issued, PEM blobs stored, expiry recorded |
| `failed` | Issuance failed; the `error` field has the underlying message |
