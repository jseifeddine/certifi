# 🦎 Certifi

[![CI](https://github.com/jseifeddine/certifi/actions/workflows/ci.yml/badge.svg)](https://github.com/jseifeddine/certifi/actions/workflows/ci.yml) [![Release](https://img.shields.io/github/v/release/jseifeddine/certifi)](https://github.com/jseifeddine/certifi/releases/latest) [![License: MIT](https://img.shields.io/github/license/jseifeddine/certifi)](./LICENSE) [![GHCR version](https://ghcr-badge.egpl.dev/jseifeddine/certifi/latest_tag?ignore=latest,edge&label=ghcr.io&color=%232ea44f)](https://github.com/jseifeddine/certifi/pkgs/container/certifi) [![GHCR size](https://ghcr-badge.egpl.dev/jseifeddine/certifi/size?tag=latest&label=image%20size&color=%232ea44f)](https://github.com/jseifeddine/certifi/pkgs/container/certifi) [![Rust 2021](https://img.shields.io/badge/Rust-2021-000000?logo=rust&logoColor=white)](https://www.rust-lang.org) [![Axum](https://img.shields.io/badge/Axum-0.7-1a1a1a)](https://github.com/tokio-rs/axum) [![React 18](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)](https://react.dev) [![ACME DNS-01](https://img.shields.io/badge/ACME-DNS--01-2ea44f)](https://datatracker.ietf.org/doc/html/rfc8555)

Self-hosted ACME v2 certificate manager. Issues and renews TLS certificates using DNS-01 challenges — no inbound HTTP required, so it works for internal and private domains. Pure-Rust ACME client, no external scripts.

## What's in the box

- **`certifi-server`** — REST API + renewal daemon. Runs headless as your cert backplane.
- **`certifi-cli`** — cross-platform Rust CLI for cron-driven cert automation. Idempotent: safe to invoke from cron every hour, only writes files on change, exits with codes a shell wrapper can branch on.
- **`web/`** — optional React + Vite admin UI, served by nginx, reverse-proxying `/api/*` to the server.

Five authoritative-DNS providers ship in-tree — **PowerDNS**, **Cloudflare**, **DigitalOcean**, **Hetzner DNS**, **Gandi LiveDNS**. Mix and match: configure multiple integrations and Certifi routes each ACME DNS-01 challenge to whichever provider owns the zone.

The web admin updates live over SSE — no page refresh required when a cert is issued from the CLI, transitions through `pending → issuing → active`, or is renewed by the daily scheduler.

## 30-second start

```bash
git clone https://github.com/jseifeddine/certifi.git
cd certifi
docker compose up -d --build
docker compose logs -f certifi   # watch for the initial admin password
```

Open `http://localhost` and sign in. Configure one or more DNS integrations (Settings → DNS Integrations → Add Integration), register an ACME account (Settings → ACME Account), then issue your first cert.

For headless / API-only deployments: `docker compose up -d --build certifi` and uncomment the `ports:` block in `docker-compose.yml`.

Prefer a prebuilt multi-arch (amd64/arm64) image instead of building locally:

```bash
docker pull ghcr.io/jseifeddine/certifi:latest   # or a pinned :vX.Y.Z
```

## Documentation

Full docs live in [`docs/`](docs/README.md):

| | |
|---|---|
| **[Installation](docs/installation.md)** | Docker, env vars, secrets, first-time setup |
| **[Architecture](docs/architecture.md)** | Workspace layout, how the pieces fit |
| **[DNS providers](docs/dns-providers.md)** | Configuring each integration; adding new ones |
| **[Certificates](docs/certificates.md)** | Issuing, renewing, downloading, the idempotent model |
| **[CLI](docs/cli.md)** | `certifi-cli` for cron-driven automation |
| **[API reference](docs/api.md)** | REST endpoints and the SSE event stream |
| **[Security](docs/security.md)** | Credential storage, production checklist |
| **[Development](docs/development.md)** | Building from source, adding a DNS provider |

## License

[MIT](LICENSE)
