# Certifi documentation

Pick a starting point based on what you're trying to do.

## Get started

- **[Installation](installation.md)** — Docker compose, environment variables, secrets, the first-run admin password, initial DNS + ACME setup.
- **[Architecture](architecture.md)** — How the workspace is laid out (`certifi-server`, `certifi-types`, `certifi-client`, `web/`), how the services fit together, and how live updates flow.

## Operate

- **[DNS providers](dns-providers.md)** — Per-provider setup for PowerDNS, Cloudflare, DigitalOcean, Hetzner DNS, Gandi LiveDNS. Multiple integrations can coexist; routing is first-match-wins by creation order.
- **[Certificates](certificates.md)** — Issuing, renewing, downloading. How the idempotent `POST /api/certificates` behaves. The daily renewal scheduler. Pre-flight zone validation. The description field. Email notifications.
- **[CLI](cli.md)** — `certifi-cli` for cron automation. Exit codes, `--reload-cmd`, `--poll-interval`, cross-platform install (including a Docker build path for hosts without Rust).

## Reference

- **[REST API](api.md)** — Every endpoint, request/response shapes, error codes, the SSE event stream.
- **[Security](security.md)** — Credential storage, production checklist, TLS termination, CORS, what's not yet implemented.

## Develop

- **[Development](development.md)** — Building from source with the Cargo workspace, web admin dev loop, adding a new DNS provider, conventions.

---

**Quick orientation:**

- Want to issue a cert from a cron job on a remote host? Start with [CLI](cli.md).
- Want to add a new DNS provider? Start with the "Adding a DNS provider" section of [Development](development.md).
- Confused about the workspace layout? Start with [Architecture](architecture.md).
- Need to know exactly what a particular endpoint returns? [REST API](api.md).
