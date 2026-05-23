# Security

## Credential storage

- **User passwords** — hashed with Argon2id. The plaintext never touches disk.
- **API tokens** — stored as SHA-256 hashes only. The full token (`dapi_...`) is returned exactly once at creation and never again. Lose it and you have to issue a new one.
- **Certificate private keys** — stored in the SQLite DB in PEM format. Restrict filesystem access to the `DATA_DIR` accordingly (`chmod 700` is reasonable).
- **ACME account private key** — stored in the `settings` table as base64-encoded PKCS#8 DER under `acme_account_key`.
- **PFX passwords** — encrypted with AES-256-GCM keyed off `COOKIE_KEY` before being persisted on the certificate row. Decrypted on demand when the user re-downloads. Rotating `COOKIE_KEY` invalidates stored PFX passwords; the next PFX download generates fresh.
- **DNS integration credentials** — stored as JSON in the `integrations` table. **Not encrypted at rest** — they're protected by filesystem permissions on `DATA_DIR`, the same as cert private keys. Secret values (`*_token`, `*_key`, `*_pat`) are masked as `***` in API responses; the raw value never leaves the server after creation. Set strict permissions on `DATA_DIR` and treat the volume the same way you'd treat any other secret-bearing data store.
- **JWT session tokens** — signed (HS256) with `JWT_SECRET`. 8-hour expiry.

## Production checklist

- [ ] Set `JWT_SECRET` and `COOKIE_KEY` to long random values: `openssl rand -hex 32`.
- [ ] Terminate TLS in front of the `web` service — Certifi itself does not serve HTTPS (see [TLS termination](#tls-termination)).
- [ ] Keep the `certifi` (backend) service unexposed; route all traffic through the `web` service or your own proxy.
- [ ] Mount `DATA_DIR` on a volume with restricted permissions (`chmod 700`).
- [ ] Create named users rather than sharing the `admin` account. Set `email` so each user gets renewal-failure notifications.
- [ ] Set reasonable expiry dates on API tokens used by automation.
- [ ] Use Let's Encrypt **production** only after you've tested with staging.
- [ ] If integrating with a strict reverse proxy: confirm the `/api/events` SSE stream isn't being buffered (the bundled nginx config handles this; custom proxies may need `proxy_buffering off` for that path).

## CORS

The Rust API allows CORS from any origin (`*`) by default so the React dev server, headless API clients, and self-hosted GUIs can all reach it. If you only ever serve the web admin behind the bundled nginx (same-origin), tighten the policy in `crates/certifi-server/src/main.rs` where the `CorsLayer` is constructed.

## TLS termination

The bundled `web` service serves plain HTTP. Two common ways to get TLS:

**1. Replace `deploy/nginx.conf` with a TLS-enabled config** and mount certificates into the `web` container. Suitable when you want everything in the same compose stack.

**2. Sit a TLS-terminating reverse proxy (Caddy / Traefik / HAProxy / external nginx) in front of `web`.** Minimal nginx example:

```nginx
server {
    listen 443 ssl;
    server_name certifi.example.com;
    ssl_certificate     /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # SSE: don't buffer the live event stream
    location /api/events {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 24h;
    }
}
```

Bootstrap question: how do you get the cert for Certifi itself? Either issue it via Certifi (after first setup) and reload your proxy, or use Caddy / Traefik with their own ACME clients.

## Network exposure

The default `docker-compose.yml` does NOT expose the Rust backend's port. It's only reachable from the `web` container on the internal Docker network. If you want direct backend access (for the CLI from outside the host, or for your own UI), uncomment the `ports:` block in `docker-compose.yml`. Keep it firewalled to trusted IPs — there's no IP-allowlist feature in Certifi itself yet.

## What's not implemented yet

- **At-rest encryption** for DNS integration credentials and ACME account key (currently filesystem-permission-protected only).
- **2FA / TOTP** on user accounts.
- **WebAuthn / passkey** logins.
- **OIDC / SSO** federation.
- **Audit log** of admin actions.
- **Rate limiting** on login.
- **Env-var lockdown** for non-PowerDNS integration credentials.

If any of these are blocking for you, open an issue describing the use case.
