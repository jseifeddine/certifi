# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.0] — 2026-09-21

### Added

- **Optional OpenBao backend for secret storage** (`BAO_ADDR`). Certificate private keys and
  chains, the ACME account key and DNS provider credentials are written to an OpenBao KV mount
  under a configurable path (default `certifi`) instead of the SQLite file, which keeps only
  non-secret metadata — id, common name, SANs, status, expiry. Listing, RBAC, the renewal
  scheduler and the web admin are unchanged. Off unless `BAO_ADDR` is set; every `BAO_*`
  variable is also read as `VAULT_*`, so a Vault-shaped environment needs no new variables.
  Full setup, policy and migration guide in [`docs/secret-backend.md`](docs/secret-backend.md).
  - Authenticates by token (`BAO_TOKEN` / `BAO_TOKEN_FILE`, renewed while renewable) or AppRole
    (`BAO_ROLE_ID` + `BAO_SECRET_ID`, re-logging in before the lease expires). KV v1 and v2,
    namespaces, a custom CA bundle and a skip-verify escape hatch are all supported.
  - Existing secrets migrate at the next startup: write, read back, verify every field, then
    clear the column. Idempotent and interruption-safe — a row already carrying a reference is
    skipped, and a failed run just leaves work for the next boot. **Back up `DATA_DIR` first;
    the migration is one-way.**
  - Each row records where its own material lives (`certificates.secret_ref`, and a reference in
    place of the value for the ACME key and integration config), so a half-migrated database
    stays coherent and a cert issued before the switch keeps working until its next renewal.
  - If `BAO_ADDR` is set and OpenBao is unreachable or rejects the credentials, the server exits
    instead of quietly falling back to writing private keys to disk.
  - Deleting a certificate or DNS integration now destroys its material in OpenBao (a KV v2
    *destroy*, all versions), not just the row pointing at it.

### Security

- **A completed migration no longer leaves the old plaintext recoverable in the database file.**
  `UPDATE … SET col = NULL` only unlinks the payload — the bytes survive in free pages and WAL
  frames. After a migration that moved something, Certifi now checkpoints the WAL, runs `VACUUM`
  to rebuild the file from live rows only, and truncates the WAL again.
- **SQLite `secure_delete` is now on**, so freed pages are zeroed rather than merely unlinked.
  Applies to the database backend too: a deleted certificate's private key no longer sits
  legible in the free list waiting for those pages to be reused.

## [1.1.4] — 2026-09-09

### Fixed

- **DNS propagation checks no longer consult a recursive resolver — least of all the host's
  own.** The check that waits for the challenge TXT to appear on the zone's authoritative
  nameservers discovered that delegation through the host's configured resolver
  (`/etc/resolv.conf`). On a certifi host inside a split-horizon network that resolver is an
  internal recursor, which hands back internal-only NS records and an internal-only copy of the
  zone — so a record correctly published to the public authoritative backend looked "missing"
  on every pass and issuance stalled until the 5-minute timeout. The check now does its own
  iterative walk from the IANA root hints (`. → TLD → the zone's nameservers`), every query with
  recursion disabled and every answer taken only from the server authoritative for that step —
  the same path Let's Encrypt validates from, and one an internal recursor or a poisoned cache
  can't influence. The final TXT read already queried each authoritative server directly; only
  the discovery of *which* servers those are was going through the host resolver.

## [1.1.3] — 2026-09-03

### Added

- **The web admin is now published as its own image**, `ghcr.io/<owner>/certifi-web` — the React
  build served by nginx, which also reverse-proxies `/api` to the server. Previously only the
  server image was published, so anyone following the `docker pull` path had to build the
  frontend themselves. Same multi-arch (amd64/arm64) manifests, same tag scheme
  (`X.Y.Z` / `X.Y` / `latest` / `edge`), built natively per architecture.

### Changed

- **`docker compose` no longer compiles anything by default.** Both services name their published
  image alongside the existing `build:` stanza, so `docker compose pull && docker compose up -d`
  runs the stack with no Rust or Node toolchain. Set `CERTIFI_VERSION` to pin both images to a
  release; `docker compose build` still builds from source and tags the result under the same
  names.

## [1.1.2] — 2026-09-03

### Fixed

- **Wildcard + apex certs no longer fail validation.** A cert covering `example.com` and
  `*.example.com` gets two ACME authorizations whose challenge records share the FQDN
  `_acme-challenge.example.com` but carry different values. Every provider deployed one value
  at a time (PowerDNS `REPLACE`, Gandi `PUT`, and a clean-then-create in Cloudflare,
  DigitalOcean and Hetzner), so the second wiped the first and the CA rejected the order with
  `Incorrect TXT record ... found`. `DnsProvider::deploy_challenge` now takes the whole value
  set for a name and providers publish the complete RRset in one call.
- **Requesting a cert that already exists but failed no longer creates a duplicate row.**
  `POST /api/certificates` deduplicated against `active` and `pending`/`issuing` certs only,
  so re-requesting after a failure left two rows for the same domains — the new one without
  the original's description, and the old one still holding the previously issued material.
  A matching `failed` cert is now retried in place (same id, `202` + `deduplicated: true`).
- **A failed renewal no longer strands a certificate forever.** The daily scheduler only looked
  at `status='active'` rows, so one bad run (provider outage, expired credentials) parked the
  cert in `failed` and auto-renew never fired again. Failed certs with `auto_renew` on are now
  retried on the same daily pass. The failure email is sent on the transition into `failed`
  only, so a persistently broken cert doesn't mail every day.
- Issuance no longer strands a cert in `pending` when loading settings for the background task
  fails — the row is marked `failed` with the error, which also makes it eligible for retry.

### Changed

- **DNS propagation is now verified, not guessed.** After publishing the challenge records,
  issuance resolves the zone's authoritative nameservers and queries each of them directly,
  once a second, until they all serve every expected TXT value (up to 5 minutes) — then tells
  the CA to validate. This fixes intermittent failures on hidden-primary setups where the API
  write lands on the primary but ns1/ns2 haven't received the NOTIFY/AXFR yet. The
  per-integration **Propagation Delay** is now only a fallback for when the check can't run
  (no outbound DNS, unresolvable NS records).

## [1.1.1] — 2026-06-30

### Fixed

- Build Linux `amd64` release binaries on Ubuntu 22.04 so `certifi` and `certifi-cli`
  remain compatible with older glibc versions than binaries built on `ubuntu-latest`.

## [1.1.0] — 2026-05-23

### Added

- Pre-built **release binaries** for both `certifi` (server) and `certifi-cli`, attached to
  every release across four targets: **linux** and **macOS (darwin)**, each in **`amd64`** and
  **`arm64`**, with per-target `SHA256SUMS`.
- macOS binaries statically link a **vendored OpenSSL** (new `vendored-openssl` cargo feature on
  `certifi-server`), so they run on a clean Mac with no Homebrew OpenSSL install.
- A `release` GitHub Actions workflow that builds and publishes those binaries on every `vX.Y.Z`
  tag (each architecture built natively on its own runner).

## [1.0.0] — 2026-05-23

First production release.

### Added

- **ACME v2 certificate issuance & renewal** over the **DNS-01** challenge — no inbound HTTP
  required, so it works for internal and private domains. Pure-Rust ACME client (`ring` /
  `rcgen` / `x509-parser`), no external shell hooks.
- **Five in-tree DNS providers** — PowerDNS, Cloudflare, DigitalOcean, Hetzner DNS, and Gandi
  LiveDNS, behind a single `DnsProvider` trait. Configure several at once: each DNS-01
  challenge is routed to whichever configured integration owns the zone (first-match,
  most-specific wins).
- **`certifi-server`** — REST API + daily renewal scheduler, runnable fully headless as a cert
  backplane.
- **`certifi-cli`** — cross-platform Rust CLI for cron-driven automation. Idempotent: safe to
  run hourly, only writes files on change, and exits with codes a shell wrapper can branch on.
- **Web admin** (React + Vite, served by nginx) that updates **live over SSE** — no refresh as a
  cert moves `pending → issuing → active` or is renewed by the scheduler.
- **RBAC** — a code-owned permission registry, three system roles (SuperAdmin / Operator /
  Viewer) plus custom roles, with global and per-zone scoped grants.
- **Authentication** — local accounts (Argon2id), generic **OIDC SSO** (PKCE + group→role
  mapping), **TOTP MFA**, and scoped API tokens for automation.
- **Append-only audit log** with before/after snapshots and write-time redaction of
  secret-looking fields.
- **Encrypted storage** of integration credentials and the ACME account key; secret fields are
  masked (`***`) on the wire and never echoed back.
- **Key algorithms** — EC P-256 / P-384 and RSA 2048 / 4096; download as PEM, full chain, key,
  or PFX/PKCS#12 bundle.
- **Transactional email** (SMTP) for verification and password reset.
- **First-boot provisioning** — optional YAML (`CERTIFI_PROVISIONING_FILE`) that seeds settings,
  roles, users, and DNS integrations on first start. See
  [`provisioning.example.yaml`](./provisioning.example.yaml).
- **OpenAPI** spec generated from the wire types (`utoipa`) with Swagger UI, plus a documentation
  set served straight from the binary at `/docs`.
- **Storage** — SQLite with migrations applied on boot. **Distribution** — single Docker image
  plus a one-command `docker compose` stack.
- **Engineering baseline** — a unit-test suite over the security- and correctness-critical logic
  (hostname dedup, provider routing, RBAC scope checks, audit redaction, config precedence, ACME
  crypto helpers); `rustfmt` + `clippy -D warnings` enforced in CI; and a sidebar footer showing
  the running version linked to its GitHub release alongside a version-pinned Docs link.

[Unreleased]: https://github.com/jseifeddine/certifi/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/jseifeddine/certifi/compare/v1.1.4...v1.2.0
[1.1.4]: https://github.com/jseifeddine/certifi/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/jseifeddine/certifi/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/jseifeddine/certifi/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/jseifeddine/certifi/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/jseifeddine/certifi/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/jseifeddine/certifi/releases/tag/v1.0.0
