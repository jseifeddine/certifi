# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/jseifeddine/certifi/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/jseifeddine/certifi/releases/tag/v1.0.0
