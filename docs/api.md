# REST API reference

Base URL: whatever you've put the web admin behind, plus `/api`. Example: `https://certifi.example.com/api/...`. Pointing the client at the backend directly (`http://localhost:8080/api/...`) is equivalent — see [architecture.md](architecture.md#url-symmetry).

All endpoints except `POST /api/auth/login` and `GET /api/health` require authentication.

## Authentication

Two methods, both via the `Authorization` header:

**JWT session token** (returned by `/api/auth/login`):
```
Authorization: Bearer <jwt>
```

**API token** (created via the Tokens page or `POST /api/tokens`):
```
Authorization: Bearer dapi_<token>
```

A session cookie (`session=<jwt>`) set by the login endpoint is also accepted — used by the web admin and the SSE event stream (the browser's `EventSource` API can't set custom headers).

---

## Certificates

### `GET /api/certificates`

List all certificates.

**Response `200`:**
```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "common_name": "app.example.com",
    "sans": ["www.example.com"],
    "status": "active",
    "auto_renew": true,
    "key_algo": "ec-p384",
    "description": "production web tier",
    "created_at": "2026-03-01T10:00:00Z",
    "updated_at": "2026-06-01T10:00:00Z",
    "expires_at": "2026-09-01T10:00:00Z",
    "error": null,
    "has_files": true
  }
]
```

`status` values: `pending` → `issuing` → `active` | `failed`.

### `POST /api/certificates`

Request a certificate. **Idempotent** on the normalized `(common_name, sorted SAN set)`:

- Existing `status='active'` cert with the same combo → returned as-is, `deduplicated: true`, HTTP `200`.
- In-flight `pending`/`issuing` cert with the same combo → returned as-is, `deduplicated: true`, HTTP `200`.
- Otherwise → pre-flight zone validation runs (each domain must be covered by some configured integration's zone). New row inserted, async issuance kicked off, HTTP `202 Accepted`.

**Request:**
```json
{
  "common_name": "app.example.com",
  "sans": ["www.example.com"],
  "auto_renew": true,
  "key_algo": "ec-p384",
  "description": "production web tier"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `common_name` | string | yes | Primary domain (CN) |
| `sans` | string[] | no | Additional domains. Don't repeat `common_name`; if you do it's deduped. |
| `auto_renew` | bool | no | Default `true`. Ignored on dedup hits — existing setting is preserved. |
| `key_algo` | string | no | One of `ec-p256`, `ec-p384`, `rsa-2048`, `rsa-4096`. Defaults to the per-instance setting. Ignored on dedup hits. |
| `description` | string | no | Free-text label. Ignored on dedup hits. |

**Response (new issuance) `202`:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "pending",
  "common_name": "app.example.com",
  "sans": ["www.example.com"],
  "auto_renew": true,
  "key_algo": "ec-p384",
  "description": "production web tier",
  "deduplicated": false
}
```

**Response (dedup hit) `200`:** same shape, with `deduplicated: true` and the existing cert's `status` (typically `active`).

**Errors:**
- `400` — `common_name` empty, `key_algo` invalid, no DNS integrations configured, or one or more domains not covered by any managed zone.

### `GET /api/certificates/:id`

Get a single cert. **Response `200`:** same shape as the list item. **Errors:** `404`.

### `DELETE /api/certificates/:id`

Delete a cert and all key/cert material. **Response `200`:** `{"ok": true}`. **Errors:** `404`.

### `POST /api/certificates/:id/renew`

Force an immediate renewal regardless of expiry. **Response `202`:** same shape as the create response with `deduplicated: false`. **Errors:** `404`, `409` (already in flight).

### `PUT /api/certificates/:id/auto-renew`

Enable / disable auto-renewal.

**Request:** `{ "auto_renew": false }`. **Response `200`:** `{"ok": true}`.

### `PUT /api/certificates/:id/description`

Set or clear the operator-set description label.

**Request:** `{ "description": "new label" }` or `{ "description": null }`. **Response `200`:** `{"ok": true}`. Empty string is treated as null.

### Download endpoints

All return `Content-Disposition: attachment` and the appropriate content-type:

| Path | Returns |
|---|---|
| `GET /api/certificates/:id/download/fullchain.pem` | Leaf + chain (PEM) |
| `GET /api/certificates/:id/download/cert.pem` | Leaf only (PEM) |
| `GET /api/certificates/:id/download/chain.pem` | Intermediate chain only (PEM) |
| `GET /api/certificates/:id/download/privkey.pem` | Private key (PEM) |

### `POST /api/certificates/:id/download/pfx`

Generate / return a PKCS#12 archive.

**Response `200`:**
```json
{
  "pfx_b64": "<base64-encoded PFX>",
  "password": "...",
  "filename": "app.example.com.pfx"
}
```

The password is generated on the first call and persisted encrypted (AES-256-GCM with `COOKIE_KEY`). Subsequent calls return the same password until `COOKIE_KEY` rotates.

### `GET /api/certificates/:id/pem`

Returns all PEM blobs + the stored PFX password (if known) in one call. Used by the web admin's cert detail page.

---

## DNS integrations

DNS integrations are multi-record: you can configure as many as you need, and Certifi unions their zones for ACME routing. See [dns-providers.md](dns-providers.md) for per-provider config keys.

### `GET /api/integrations`

List all configured integrations plus the available kinds metadata (used by the web admin's "Add Integration" form).

**Response `200`:**
```json
{
  "integrations": [
    {
      "id": "...",
      "kind": "cloudflare",
      "name": "Production Cloudflare",
      "config": { "cf_api_token": "***", "cf_wait": "10" },
      "enabled": true,
      "created_at": "2026-05-15T10:00:00Z",
      "updated_at": "2026-05-15T10:00:00Z"
    }
  ],
  "available_kinds": [
    { "id": "cloudflare", "name": "Cloudflare", "fields": [/* ... */] }
  ]
}
```

Secret config values (token, key, PAT) are masked as `***` — the raw value never leaves the server after creation.

### `POST /api/integrations`

Create one.

**Request:**
```json
{
  "kind": "cloudflare",
  "name": "Production Cloudflare",
  "config": {
    "cf_api_token": "<real-token>",
    "cf_wait": "10"
  },
  "enabled": true
}
```

The server validates the config by constructing the provider (catches missing required fields, malformed URLs etc.) before persisting.

**Response `200`:** the created integration with secrets masked.

### `GET /api/integrations/:id`

**Response `200`:** the integration with secrets masked. **Errors:** `404`.

### `PUT /api/integrations/:id`

Update name, enabled, and/or config.

**Request:** any subset of `{ "name": ..., "config": {...}, "enabled": bool }`. **Response `200`:** the updated integration.

When updating `config`, a value of `***` is treated as **preserve** — pass it back for any secret field you don't want to change. To clear a value, send an empty string (allowed only for optional fields).

### `DELETE /api/integrations/:id`

**Response `200`:** `{"ok": true}`. **Errors:** `404`.

### `POST /api/integrations/:id/test`

Confirm the integration's credentials work by listing its zones.

**Response `200`:**
```json
{
  "ok": true,
  "provider": "Cloudflare",
  "zone_count": 3,
  "zones": ["example.com", "internal.example.com", "corp.example.com"]
}
```

**Errors:** `400` (config invalid or upstream call failed — the error chain is surfaced verbatim).

---

## Domains

### `GET /api/domains`

List DNS zones available from all enabled integrations. Used by the web admin for autocomplete.

**Response `200`:** `["example.com", "internal.example.com"]`.

**Errors:** `400` (no integrations configured), `500` (integration backend unreachable).

---

## Events (SSE)

### `GET /api/events`

Server-Sent Events stream of cert state changes. Authenticated via session cookie (browser `EventSource`) or bearer token (header).

Events:

| Event | Data |
|---|---|
| `cert.changed` | `{"id":"<uuid>"}` — emitted on create, renew, delete (already-emitted), and every status transition |
| `cert.deleted` | `{"id":"<uuid>"}` — emitted on delete |

Clients should re-fetch the affected resource on each event rather than relying on the payload to carry the full state. The web admin's `useCertEvents` hook does this automatically.

The server emits keep-alive comment frames every 15s so intermediate proxies don't reap the long-lived response.

---

## API tokens

### `GET /api/tokens`

List API tokens belonging to the authenticated user.

**Response `200`:**
```json
[
  {
    "id": "uuid",
    "user_id": "uuid",
    "name": "deploy-server-01",
    "created_at": "2026-01-01T00:00:00Z",
    "last_used_at": "2026-06-01T12:00:00Z",
    "expires_at": null
  }
]
```

The token hash is never returned.

### `POST /api/tokens`

Create an API token.

**Request:**
```json
{
  "name": "deploy-server-01",
  "expires_at": "2027-01-01T00:00:00Z",
  "permissions": ["certificate.list", "certificate.download"]
}
```

| Field | Type | Required |
|---|---|---|
| `name` | string | yes |
| `expires_at` | ISO 8601 datetime | no — omit for no expiry |
| `permissions` | string[] | no — omit (or `null`) for "inherit my permissions" |

`permissions` lets the issuer restrict the token to a subset of their own permission set. Every key must be one the issuing user currently holds — there's no privilege-escalation path through tokens. The check runs on every request, so revoking the user's role propagates instantly to any token they minted.

**Response `200`:**
```json
{
  "id": "uuid",
  "token": "dapi_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "permissions": ["certificate.list", "certificate.download"]
}
```

The token is returned **only once**. Store it immediately — only its SHA-256 hash is persisted.

### `DELETE /api/tokens/:id`

Revoke a token immediately. **Response `200`:** `{"ok": true}`.

---

## Users (admin only)

### `GET /api/users`

**Response `200`:**
```json
[
  {
    "id": "uuid",
    "username": "alice",
    "is_admin": false,
    "email": "alice@example.com",
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-01T00:00:00Z"
  }
]
```

Password hash is never returned.

### `POST /api/users`

**Request:**
```json
{
  "username": "alice",
  "password": "minimum8chars",
  "email": "alice@example.com",
  "is_admin": false
}
```

**Response `200`:** the created user.

### `PUT /api/users/:id`

**Request:** `{ "email": "new@example.com", "is_admin": true }` (any subset). **Response `200`:** `{"ok": true}`.

Cannot update your own admin status.

### `PUT /api/users/:id/password`

**Request:** `{ "new_password": "minimum8chars" }`. **Response `200`:** `{"ok": true}`.

Admins can change anyone's password; non-admins can only change their own.

### `DELETE /api/users/:id`

**Response `200`:** `{"ok": true}`. Cannot delete yourself.

---

## Settings (admin only)

### `GET /api/settings`

**Response `200`:**
```json
{
  "acme_ca": "https://acme-v02.api.letsencrypt.org/directory",
  "acme_registered": true,
  "acme_account_url": "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
  "key_algo": "ec-p384",
  "locked": ["acme_ca"]
}
```

`locked` lists settings whose values are fixed by environment variables and cannot be changed via the API. DNS-integration config lives in `/api/integrations` and is not part of this response.

### `PUT /api/settings`

Update one or more settings. Any field can be omitted. **Response `200`:** `{"ok": true}`. **Errors:** `400` if you try to update a locked setting.

### `POST /api/settings/acme/register`

Register / re-register the ACME account.

**Response `200`:**
```json
{ "ok": true, "account_url": "https://acme-v02.api.letsencrypt.org/acme/acct/12345" }
```

---

## Roles & permissions

Every API endpoint is gated on a permission key. A user's effective permissions are the union across all of their role assignments. The login response and `GET /api/auth/me` include the flat permission list so clients can hide affordances they can't use.

### System roles (seeded on startup)

| Role | Holds |
|---|---|
| `system:super_admin` | Every permission. Cannot be deleted. |
| `system:operator` | Full read/write on certificates, integrations, tokens; read on settings, domains. No user / role / settings administration. |
| `system:viewer` | Read-only across certificates, integrations, domains, settings. |

Legacy `users.is_admin = 1` users are migrated to SuperAdmin on first boot; legacy non-admins get Operator. The `is_admin` field on the user JSON is now derived from holding the SuperAdmin role.

### `GET /api/permissions`

List every permission key the server knows about (`{key, description}[]`). Requires `role.list`.

### `GET /api/roles`

List every role (system + custom) with its permission set. Requires `role.list`.

### `POST /api/roles`

Create a custom role. Requires `role.create`. The caller can only grant permissions they themselves hold — there's no privilege escalation path through "I make a role with `user.delete` and assign it to myself".

**Request:** `{ "name": "DeploymentBot", "description": "...", "permissions": ["certificate.list", "certificate.download"] }`

### `DELETE /api/roles/:id`

Remove a custom role. System roles cannot be deleted. Requires `role.delete`.

### `GET /api/users/:id/roles`

List the role assignments held by a user. Requires `role.list`.

### `POST /api/users/:id/roles`

Grant a role. Requires `role.assign`. Idempotent on `(user_id, role_id, scope)`.

**Request:** `{ "role_id": "system:operator", "scope": "global" }`

`scope` is one of:
- `"global"` — the role applies to every operation
- `"zone:<fqdn>"` — the role applies only to certificate operations whose CN and every SAN fall under `<fqdn>` (the zone, or any subdomain of it)

A user with `zone:example.com` Operator can issue/renew/download/delete certs for `example.com`, `app.example.com`, `a.b.example.com`, etc. They cannot act on `example.org` or on a multi-zone cert like `[example.com, other.com]` (every domain must be covered — the check is conservative on purpose).

Non-cert operations (user, settings, integration, role management) ignore zone scopes — they only consider global grants.

### `DELETE /api/users/:user_id/roles/:assignment_id`

Revoke an assignment. Requires `role.assign`. The server refuses to revoke:
- the last remaining `system:super_admin` assignment across the whole instance, or
- the caller's own `system:super_admin` assignment.

Both rules close the "lock yourself out" footgun.

---

## Audit log

Every state-changing request emits one row into the append-only `audit_log` table. Each row carries: actor (user id + username, plus token id when authenticated via an API token), action key, resource type + id, `before` and `after` JSON snapshots, and request metadata (IP, user agent, request id from `X-Request-Id` if set).

Secret values are stripped at write time: any JSON object key matching `password`, `secret`, `token`, `key`, `auth`, `credential`, `cookie`, `private`, `_enc` etc. has its value replaced with `[REDACTED]` before the row is committed.

There is no UPDATE / DELETE code path for the table — append-only by construction.

### `GET /api/audit`

Requires `audit.read`. Query parameters (all optional):

| Param | Notes |
|---|---|
| `actor_user_id` | Filter by user. |
| `action` | Exact match — e.g. `certificate.create`. |
| `resource_type` | e.g. `certificate`, `user`, `oidc`. |
| `resource_id` | Exact resource UUID. |
| `before` | Pagination cursor — pass the `created_at` from the last row of the previous page. |
| `limit` | Page size, default 100, max 500. |

Rows are returned newest-first. `before_json` and `after_json` are strings (JSON-encoded) so a client can roundtrip them.

---

## OIDC SSO

Single-IdP OIDC is supported alongside local login. The flow is authorization-code + PKCE; tokens are verified for issuer / audience / signature / nonce / expiry before any local action.

### Configuration

Settings live in the `settings` table (administered via `GET/PUT /api/oidc/config` or the `/sso` admin page) and are env-var overridable:

| Setting key | Env var | Notes |
|---|---|---|
| `oidc_enabled` | `OIDC_ENABLED` | `true` / `false` |
| `oidc_issuer` | `OIDC_ISSUER` | Discovery base URL |
| `oidc_client_id` | `OIDC_CLIENT_ID` | |
| `oidc_client_secret` | `OIDC_CLIENT_SECRET` | Stored encrypted with `COOKIE_KEY` when set via the admin UI |
| `oidc_redirect_uri` | `OIDC_REDIRECT_URI` | Must match what the IdP has registered (typically `https://<host>/api/oidc/callback`) |
| `oidc_scopes` | `OIDC_SCOPES` | Comma-separated, defaults to `openid,email,profile,groups` |
| `oidc_group_claim` | `OIDC_GROUP_CLAIM` | Default `groups` |
| `oidc_username_claim` | `OIDC_USERNAME_CLAIM` | Default `preferred_username` |
| `oidc_email_claim` | `OIDC_EMAIL_CLAIM` | Default `email` |
| `oidc_create_users` | `OIDC_CREATE_USERS` | If `true`, first-time logins auto-provision a local user (JIT) |
| `oidc_force_login` | `OIDC_FORCE_LOGIN` | If `true`, `/login` auto-redirects to the IdP. `/login?local=1` is a per-visit override for break-glass access. The API still accepts local password POSTs. |

Whenever an env var is set, its setting key shows as locked in the admin UI and `PUT /api/oidc/config` refuses to change it.

### Flow

1. `GET /api/auth/oidc` — public; returns `{ enabled, provider_name, force_login }`. The login page uses this to decide whether to show the SSO button (or auto-redirect, when `force_login` is on).
2. `GET /api/auth/oidc/start?return_to=<path>` — server stores fresh `(state, nonce, pkce_verifier, return_to)` in `oidc_states`, returns `{ authorize_url, state }`. Browser navigates to `authorize_url`.
3. IdP redirects to `oidc_redirect_uri?code=...&state=...`. Register that as `https://<host>/api/oidc/callback` so the IdP lands directly on the backend — no SPA round-trip.
4. `GET /api/oidc/callback?code=...&state=...` — server looks up + deletes the state row, exchanges the code, verifies the id_token, JIT-provisions the user (if enabled), reconciles role assignments from group mappings, mints a session, sets the `session=` cookie, and `303`-redirects the browser to the captured `return_to` (or `/certificates`). On any failure (state expired, IdP rejection, JIT off and user unknown) it `303`s to `/login?error=<message>` instead.

State rows older than 10 minutes are swept at lookup time so an abandoned sign-in can't pile up rows.

### `GET /api/oidc/group-mappings`, `POST`, `DELETE /api/oidc/group-mappings/:id`

CRUD on the `oidc_group_mappings` table — claims-group-name → (role_id, scope). On every OIDC sign-in:

- For each mapping whose `group_name` appears in the user's group claim, the user receives the corresponding role assignment with `source = 'oidc'`.
- OIDC-sourced assignments the user no longer qualifies for are revoked.
- Manually-administered assignments (`source = 'manual'`) are left untouched.

`scope` accepts `"global"` or `"zone:<fqdn>"`, same as the regular role assignment.

---

## Auth

Browsers authenticate via a `session=<id>` HttpOnly cookie that maps to a row in the `sessions` table. The cookie is `SameSite=Strict`, so browsers refuse to send it on cross-site state-changing requests — adequate CSRF protection for the present flows.

CLI clients (`certifi-cli`) and other non-browser callers continue to use `Authorization: Bearer dapi_<token>`. API tokens are unchanged by the session work.

A bearer header carrying a non-`dapi_` value is also treated as a session id, so test tools can paste the same `token` the login response returns into a Postman/curl `Authorization: Bearer …` header.

### `POST /api/auth/login`

**Request:** `{ "username": "alice", "password": "..." }`

Two possible response shapes:

**Direct sign-in (no TOTP) `200`:**
```json
{ "token": "<opaque session id>", "user": { "id": ..., "username": ..., "is_admin": ..., "permissions": [...] } }
```

The same value is set as the `session=` cookie. The `token` field exists for clients that prefer to send it in `Authorization: Bearer …` instead of relying on the cookie.

**TOTP required `200`:**
```json
{ "stage": "totp_required", "challenge_id": "<uuid>" }
```

The caller must complete sign-in via `POST /api/auth/login/totp` within 5 minutes.

**Errors:** `400` on missing or mismatched credentials.

### `POST /api/auth/login/totp`

Completes a TOTP-gated sign-in.

**Request:** `{ "challenge_id": "...", "code": "123456" }`. **Response `200`:** the same `LoginResponse` shape as the direct path. **Errors:** `400` on bad / expired challenge or wrong code (the challenge is consumed regardless — replays fail).

### `POST /api/auth/logout`

Destroys the session row and clears the cookie. Idempotent.

### `GET /api/auth/me`

Returns the authenticated user.

### TOTP self-service

Identity-checked: every authenticated user manages their own factor. No permission key is consumed.

- `GET /api/auth/totp` — `{ enrolled, verified }` status.
- `POST /api/auth/totp/enroll` — generates a fresh secret and returns `{ secret_b32, provisioning_uri, qr_png_b64 }`. The factor is **not** active until the user confirms a code.
- `POST /api/auth/totp/confirm` `{ code }` — validates a current OTP against the pending secret and flips the factor to verified.
- `DELETE /api/auth/totp` — disables the factor. Subsequent sign-ins skip the OTP step.

---

## Health

### `GET /api/health`

Unauthenticated.

**Response `200`:**
```json
{ "status": "ok", "app": "Certifi", "version": "0.1.0" }
```

---

## Self-documentation

All three of these endpoints are unauthenticated and serve the same content the web admin renders under `/docs` and the CLI exposes via `certifi-cli docs`.

### `GET /api/openapi`

The OpenAPI 3.1 spec (`Content-Type: application/json`), generated from the live Rust handler annotations at build time. Cannot drift from the actual wire — change a response status or rename a field, and the spec moves with it. The web admin's `/docs/openapi` route renders this with Swagger UI; you can feed it to any other OpenAPI tooling (Postman, openapi-generator, schemathesis) too.

> The path deliberately has no `.json` extension — some reverse proxies and hardened nginx builds route by file extension, which would intercept the spec before it reaches the backend.

### `GET /api/docs`

Table of contents for the markdown docs baked into the server binary.

**Response `200`:**
```json
[
  { "slug": "readme",       "title": "Overview" },
  { "slug": "api",          "title": "REST API" },
  { "slug": "cli",          "title": "CLI" }
]
```

### `GET /api/docs/:slug`

Raw markdown body. Content-Type: `text/markdown; charset=utf-8`. Returns `404` for unknown slugs.
