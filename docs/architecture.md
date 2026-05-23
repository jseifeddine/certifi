# Architecture

## Service topology

```
┌──────────────────┐         ┌──────────────────────┐
│  React (Vite)    │         │  nginx (web service) │
│  Tailwind        │ ──────► │  ─ /        → static │
│  static bundle   │         │  ─ /api/*   → :8080  │
└──────────────────┘         └──────────┬───────────┘
                                        │
                              ┌─────────▼──────────┐
                              │  certifi (Rust)    │
                              │  Axum API + daemon │
                              │  → SQLite (/data)  │
                              └────────────────────┘
```

Two run modes:

| Mode | Services | Use case |
|---|---|---|
| Headless | `certifi` only | API + renewal daemon, driven by API tokens from CI/CD, the CLI, or your own UI |
| With web admin | `certifi` + `web` (nginx + React) | Browser UI on port `80` |

The two services share no process — only the SQLite volume — so the web admin can be added, removed, or replaced without restarting the API/daemon.

## URL symmetry

The server always mounts under `/api/...`. The nginx config proxies `/api/` straight through. Therefore the same base URL works whether the caller points at the backend directly or at the web admin's proxy:

- `http://localhost:8080` → backend serves `/api/foo` directly
- `https://certifi.example.com` → nginx proxies `/api/foo` to the backend

`certifi-cli` and `certifi-client` both rely on this — set `CERTIFI_URL` to either form.

## Repository layout

The repo is a Cargo workspace with three crates plus the web admin:

```
Cargo.toml                        — workspace manifest
crates/
├── certifi-server/               — Rust binary: API, ACME client, renewal daemon
│   └── src/
│       ├── main.rs               — startup, router, seeding, admin bootstrap
│       ├── config.rs             — env-var loading, settings overrides
│       ├── auth.rs               — JWT, API token hashing, extractors
│       ├── db.rs                 — SQLite pool, schema migrations
│       ├── error.rs              — AppError → HTTP responses
│       ├── events.rs             — broadcast channel + CertEvent type
│       ├── models.rs             — DB row types, setting key constants
│       ├── handlers/             — one module per resource
│       │     auth, certificates, domains, events (SSE),
│       │     integrations (DNS), settings, tokens, users
│       ├── integrations/         — DNS provider plugins
│       │     mod (trait + MultiDnsProvider + build_provider),
│       │     pdns, cloudflare, digitalocean, hetzner, gandi
│       └── services/             — acme, renewal scheduler, email, pfx, secret
├── certifi-types/                — Wire types shared between server and client
│   └── src/lib.rs                — IssueCertRequest / Response, CertificateView,
│                                   Integration types, normalizers
└── certifi-client/               — Rust client library + `certifi-cli` binary
    └── src/
        ├── lib.rs                — Client struct + endpoint methods + wait_until_ready
        └── bin/cli.rs            — clap-based CLI
web/                              — React + Vite + Tailwind admin UI (optional)
├── package.json
├── vite.config.ts                — dev server, proxies /api/* to :8080
├── Dockerfile                    — multi-stage node build → nginx:alpine
└── src/                          — pages, components, typed API modules
deploy/
└── nginx.conf                    — SPA fallback + /api/ proxy + SSE-friendly /api/events
Dockerfile                        — multi-stage Rust build → debian:slim
docker-compose.yml                — certifi + web services
scripts/build-cli.sh              — Build certifi-cli for a Linux target via Docker
data/                             — runtime SQLite + cert state (mounted volume)
docs/                             — this folder
```

## Crate responsibilities

**`certifi-types`** is the contract between server and client. Any type that crosses the HTTP boundary lives here — moving a field, adding a flag, renaming an enum variant requires editing exactly one file. The server and client both depend on this crate, so a mismatch fails to compile rather than silently misbehaving at runtime.

Server-internal types (DB row structs derived with `sqlx::FromRow`, setting-key constants, internal error enums) stay in `certifi-server` — they don't cross the wire.

**`certifi-server`** is the only crate that talks to the database. It owns the ACME client, the renewal scheduler, the integration plugins, and exposes everything through the Axum router defined in `main.rs`.

**`certifi-client`** is a thin async wrapper around the REST API. The library is the contract; `certifi-cli` is a clap-based binary that uses it. See [cli.md](cli.md) for the user-facing surface.

## Multi-DNS routing

Many DNS integrations can coexist. They're persisted as rows in the `integrations` table (each row has `kind`, `name`, JSON `config`, `enabled`). At issuance time, `integrations::build_provider(&db)` reads every enabled row and constructs a `MultiDnsProvider`:

- `list_zones()` queries every underlying provider and unions the results.
- `deploy_challenge(domain, value)` walks providers in DB-insertion order and dispatches to the first one whose zones suffix-match the domain — **first-match wins** when zones overlap.
- `clean_challenge(domain)` does the same routing on the way out.
- `propagation_delay()` returns the max across configured providers, so the slowest one gets enough time.

Adding/removing/disabling an integration takes effect on the next request — no restart needed.

## Live updates (SSE)

The server holds a `tokio::sync::broadcast::Sender<CertEvent>` in `AppState`. Every mutation of cert state — create, renew, delete, every status transition inside the issuance task, plus updates from the daily renewal scheduler — emits an event.

The `GET /api/events` handler subscribes to the channel and streams events as Server-Sent Events. The web admin's `useCertEvents` hook (`web/src/api/events.ts`) opens an `EventSource` and refetches affected data on each event — no polling, no manual refresh. Authentication uses the same session cookie as every other endpoint (EventSource can't set custom headers).

The nginx config has a dedicated `location /api/events` block with `proxy_buffering off` and a 24h read timeout so the long-lived response isn't reaped. The server sends keep-alive comment frames every 15s as defense against intermediate proxies.

## Data flow — issuance

1. `POST /api/certificates` lands at `handlers::certificates::create`.
2. The handler normalizes `(common_name, sans)` and looks for a matching `status='active'` row — if found, returns it as a dedup hit (`deduplicated: true`).
3. Same dedup check against `status IN ('pending','issuing')` so concurrent identical POSTs fold onto one issuance.
4. Pre-flight: build the `MultiDnsProvider` and verify every requested domain is covered by some managed zone. Fail with `400` if not — better than queueing a doomed ACME run.
5. Insert a new row with `status='pending'`, emit `cert.changed`, spawn the issuance task.
6. The task runs `services::renewal::run_issuance` which flips status to `issuing` (emits event), drives ACME via `services::acme`, and writes `status='active'` + PEM blobs + expiry on success (emits event).
7. Callers poll `GET /api/certificates/:id` until status flips — or just subscribe to `/api/events` and react. `certifi-client`'s `wait_until_ready` automates the polling path.

## Where state lives

- **SQLite** (`$DATA_DIR/certifi.db`) — users, API tokens (hashed), certificates (incl. PEM blobs and description), integrations (config JSON), settings, ACME account key. WAL mode is enabled for concurrent reads. Schema migrations are additive — existing DBs upgrade on startup.
- **ACME account private key** — stored as base64 PKCS#8 DER in the `settings` table under `acme_account_key`.
- **PFX passwords** — encrypted with the `COOKIE_KEY` (AES-256-GCM) before being persisted on the certificate row. Decrypted on demand when the user re-downloads. Rotating `COOKIE_KEY` invalidates stored PFX passwords; the next PFX download generates fresh.
- **Integration config** — stored as a JSON blob per row. Secret fields (`*_token`, `*_key`, `*_pat`) are masked as `***` in API responses; the raw value never leaves the server after creation.
- **Session tokens / API tokens** — JWTs are issued by the server, signed with `JWT_SECRET`. API tokens (`dapi_...`) are stored as SHA-256 hashes only; the plaintext is shown exactly once at creation.
