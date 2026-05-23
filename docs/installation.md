# Installation

## Docker compose (with web admin)

```bash
git clone https://github.com/jseifeddine/certifi.git
cd certifi
docker compose up -d --build
docker compose logs -f certifi   # watch for the initial admin password
```

Open `http://localhost` and sign in with the printed credentials. Change the admin password immediately (Settings → Change Password).

## Headless / API-only

Skip the web admin and run only the Rust server:

```bash
docker compose up -d --build certifi
# Then either:
#   a) uncomment the `ports:` block in docker-compose.yml to bind 8080:8080
#   b) put your own reverse proxy in front of it
```

The server listens on `:8080` inside the container, runs the renewal daemon, and accepts both JWT session tokens and API tokens (`dapi_...`).

## docker run (single container, headless)

```bash
docker run -d \
  --name certifi \
  -p 8080:8080 \
  -v certifi-data:/data \
  -e JWT_SECRET="$(openssl rand -hex 32)" \
  -e COOKIE_KEY="$(openssl rand -hex 32)" \
  your-registry/certifi:latest
```

DNS provider credentials are configured through the API / web admin after first boot — not as environment variables. See [docs/dns-providers.md](dns-providers.md).

If you also want the web admin, build it with `docker build -f web/Dockerfile -t certifi-web .` from the repo root and run it pointed at the server, or just use `docker compose`.

## First-time setup

On a fresh database the admin user is created automatically. Look for this in the logs:

```
╔══════════════════════════════════════════╗
║     CERTIFI — INITIAL ADMIN CREDENTIALS  ║
║  Username: admin                         ║
║  Password: <random-16-chars>             ║
╚══════════════════════════════════════════╝
```

Then:

1. Sign in and change the admin password (Settings → Change Password).
2. Configure one or more DNS integrations (Settings → DNS Integrations → Add Integration) — see [dns-providers.md](dns-providers.md) for each provider's setup.
3. Register your ACME account (Settings → ACME Account → Register).
4. Issue your first cert (Certificates → New Certificate) or use [the CLI](cli.md).

If the original startup password has scrolled out of your logs, restart with `RESET_ADMIN_PASSWORD=1` set for one launch — a new password will be generated and logged. Unset the variable immediately afterwards.

## Environment variables

### Core

| Variable | Default | Description |
|---|---|---|
| `DATA_DIR` | `./data` | Directory for the SQLite database |
| `LISTEN_ADDR` | `0.0.0.0:8080` | TCP address and port |
| `RUST_LOG` | `certifi=info` | Log filter — see [tracing-subscriber docs](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html) |

### Security — required in production

| Variable | Description |
|---|---|
| `JWT_SECRET` | Secret for signing JWT session tokens. **Must be set** to persist sessions across restarts. Generate: `openssl rand -hex 32` |
| `COOKIE_KEY` | Key used to encrypt at-rest secrets (PFX passwords). **Must be set** to persist them across restarts. Rotating it invalidates stored PFX passwords; new ones are generated on next download. Generate: `openssl rand -hex 32` |

If either is unset they're randomly generated at startup — every restart invalidates all sessions and stored PFX passwords. Don't ship without them.

### Recovery

| Variable | Description |
|---|---|
| `RESET_ADMIN_PASSWORD` | Set to `1` for one startup to regenerate the `admin` user's password and print it to logs. Unset immediately after, or every restart rotates the password. |

### Settings overrides (optional)

These env vars override the matching setting in the database AND lock the field as read-only in the web UI. Intended for infrastructure-as-code deployments where the value shouldn't drift.

| Variable | Setting key | Description |
|---|---|---|
| `ACME_CA_URL` | `acme_ca` | ACME directory URL |

DNS-integration credentials are configured per integration in the database (see [dns-providers.md](dns-providers.md)). Locking those via env vars is not yet implemented — open an issue if you need it.

### SMTP (optional)

Leave `SMTP_HOST` unset to disable all email notifications.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | *(disabled)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_FROM` | `certifi@localhost` | From address |
| `SMTP_USERNAME` | *(none)* | SMTP auth username |
| `SMTP_PASSWORD` | *(none)* | SMTP auth password |
