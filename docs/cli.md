# certifi-cli

A cross-platform Rust client for the Certifi API. Designed for cron use: the `request` subcommand is idempotent on the server side, writes output files atomically, and uses exit codes that a shell wrapper can branch on.

Runs on Linux, macOS (arm64 / x86_64), and Windows. No system OpenSSL needed (rustls). HTTP/2 negotiated via ALPN with HTTP/1.1 fallback.

## Install

### With a local Rust toolchain (any platform)

```bash
cargo install --path crates/certifi-client
```

Works on Linux, macOS (arm64 / x86_64), and Windows. Installs to `~/.cargo/bin/certifi-cli` (or `%USERPROFILE%\.cargo\bin\certifi-cli.exe`).

If you don't have Rust installed: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh` (or grab an installer from <https://rustup.rs>).

### Without Rust — Docker build (Linux targets only)

For environments where installing Rust isn't an option, build a Linux binary in a container:

```bash
# Default: linux-amd64
./scripts/build-cli.sh
# Or:
./scripts/build-cli.sh linux-arm64
```

Output lands in `dist/cli/<target>/certifi-cli`. Copy it to your deploy target's `$PATH`. The script uses Docker's `--platform` flag so it works from any host — but cross-architecture builds use qemu emulation under the hood and are ~5–10x slower than native.

> **macOS users:** the Docker path produces a **Linux** binary, not a macOS binary. That's useful if you're building on your Mac to deploy to a Linux server. For a native macOS binary, install rustup and use `cargo install` above — Docker on macOS can't produce Mac-native binaries.

### Binary releases

Not yet published. The script + `cargo install` cover most workflows.

## Configure

Two equivalent ways — pick one:

### Interactive

```
$ certifi-cli init
Certifi CLI setup
─────────────────
The URL can point to either the web admin (e.g. https://certifi.example.com)
or the backend API directly (e.g. http://localhost:8080). Both work.

Server URL [http://localhost:8080]: https://certifi.example.com
API token: ****

Saved /home/you/.config/certifi.json
```

The CLI validates connectivity (unauthenticated `/api/health`) and auth (`/api/certificates`) before writing the file.

### Environment variables

```bash
export CERTIFI_URL="https://certifi.example.com"
export CERTIFI_TOKEN="dapi_..."
```

Env vars take precedence over the config file. Useful for CI / cron where you'd rather not write secrets to disk.

### Config file path

| Platform | Default |
|---|---|
| Linux / macOS | `~/.config/certifi.json` |
| Windows | `%APPDATA%\certifi.json` |

Override with `--config /custom/path` or `CERTIFI_CONFIG=/custom/path`. The file is written with mode `0600` on Unix.

```json
{
  "url": "https://certifi.example.com",
  "token": "dapi_..."
}
```

## Subcommands

| Command | Description |
|---|---|
| `init` | Interactive setup (see above) |
| `list` | List all certificates |
| `get <id-or-cn>` | Show one certificate as JSON |
| `request -d cn [-d san …]` | Idempotently request a cert; optionally write files; the cron-friendly command |
| `renew <id-or-cn>` | Force-renew a cert (queues issuance on the server) |
| `delete <id-or-cn>` | Delete a cert |
| `docs [slug]` | Fetch documentation from the connected server (e.g. `certifi-cli docs cli`). With no `slug`, prints the table of contents. Output is rendered as styled terminal text via [termimad](https://github.com/Canop/termimad); pipe to a file or pager (`certifi-cli docs api > api.md`) to get raw markdown. |
| `integrations <sub>` | Manage DNS integrations from the terminal — indispensable for headless deployments without the web admin. See below for the sub-commands. |

## `integrations` — DNS providers from the CLI

| Sub-command | Description |
|---|---|
| `integrations list` (alias `ls`) | List configured integrations (id, kind, name, enabled). |
| `integrations kinds [--kind X]` | Without `--kind`, list available kinds (PowerDNS, Cloudflare, …). With `--kind`, print the full field catalogue for that kind. |
| `integrations show <id>` | Print one integration as JSON (secrets masked). |
| `integrations add [...]` | Create. Fully non-interactive when every flag is supplied; otherwise prompts for missing pieces. See examples below. |
| `integrations update <id> [...]` | Patch name / config keys / enabled flag. |
| `integrations delete <id>` (alias `rm`) | Delete. |
| `integrations test <id>` | Probe by listing zones — the same button the web admin's "Test" exposes. |

### Add — interactive

```
$ certifi-cli integrations add
Kind (pdns / cloudflare / digitalocean / hetzner / gandi): pdns
Name: Main PowerDNS
API URL (pdns_url): https://pdns-api.example.com
API Key (pdns_key): ****
Propagation Delay (seconds) (pdns_wait) [5]: 10
Server ID (pdns_server, optional):
Created integration 4f2a… (Main PowerDNS)
```

### Add — fully scripted

```
$ certifi-cli integrations add \
    --kind pdns \
    --name "Main PowerDNS" \
    --config pdns_url=https://pdns-api.example.com \
    --config pdns_key="$PDNS_KEY" \
    --config pdns_wait=10
Created integration 4f2a… (Main PowerDNS)
```

Set `CERTIFI_NONINTERACTIVE=1` to skip prompts for *optional* fields not given on the command line — required fields without a value still error out.

### Update

```
$ certifi-cli integrations update 4f2a… --disable
$ certifi-cli integrations update 4f2a… --config pdns_key="$NEW_KEY"
$ certifi-cli integrations update 4f2a… --name "Main PowerDNS (legacy)"
```

`***` is the "preserve current value" sentinel: omitting a secret entirely leaves it untouched.

Anywhere a command takes `<id-or-cn>`, you can pass either the UUID or the common name — the CLI resolves CNs case-insensitively and ignores trailing dots.

## `request` — the main command

```
certifi-cli request -d <cn> [-d <san1> -d <san2> …]
                    [--fullchain PATH] [--cert PATH]
                    [--chain PATH]     [--privkey PATH]
                    [--description TEXT]
                    [--timeout SECONDS] [--poll-interval SECONDS]
                    [--reload-cmd CMD]
                    [--auto-renew {true|false}]
                    [--key-algo ALGO]
```

The first `-d` is the Subject CN; subsequent `-d` values are SANs. Repeated form (`-d a -d b`) and space-separated form (`-d a b`) both work.

The flow:

1. POSTs to `/api/certificates`. If a cert with the same `(CN, SAN set)` already exists, the server returns it with `deduplicated: true`. Otherwise it queues issuance and returns the new id.
2. If the cert isn't already `active`, the CLI polls `GET /api/certificates/:id` every `--poll-interval` seconds (default `1`) until the status flips — or until `--timeout` (default `300`).
3. For each `--fullchain` / `--cert` / `--chain` / `--privkey` path given, downloads the contents and writes atomically (`tempfile-in-same-dir` + `rename`) **only if** the bytes differ from what's already on disk. Skipping unchanged writes is what makes the cron pattern work.
4. If anything was written and `--reload-cmd` is set, runs the command via `sh -c` (or `cmd /C` on Windows).

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success, files on disk are already up to date (or no `--*` paths given) — cron should do nothing. |
| `2` | Success, one or more files were written/updated — caller should reload services. |
| `1` | Error (auth, validation, network, etc.). |
| `3` | Timed out waiting for issuance. The cert is still being issued on the server; try again. |

The exit codes are chosen to play nicely with shell `&&` / `||`:

```sh
certifi-cli request -d app.example.com --fullchain fc.pem --privkey pk.pem
case $? in
  0)  ;;                              # nothing to do
  2)  systemctl reload nginx ;;       # files updated
  3)  logger -t certifi "still issuing, will retry next cron run" ;;
  *)  logger -t certifi "ERROR" >&2; exit 1 ;;
esac
```

`--reload-cmd` collapses the common case:

```sh
certifi-cli request -d app.example.com \
  --fullchain /etc/nginx/certs/app.fullchain.pem \
  --privkey   /etc/nginx/certs/app.privkey.pem \
  --reload-cmd "systemctl reload nginx"
```

## Cron recipes

### Daily refresh, reload nginx on change

```cron
17 4 * * *  /usr/local/bin/certifi-cli request \
              -d app.example.com -d www.example.com \
              --fullchain /etc/nginx/certs/app.fullchain.pem \
              --privkey   /etc/nginx/certs/app.privkey.pem \
              --reload-cmd "systemctl reload nginx" \
              >> /var/log/certifi-cli.log 2>&1
```

The first invocation issues the cert. Subsequent runs find an existing valid cert on the server (idempotent POST), match the on-disk files byte-for-byte, exit `0`, and reload nothing. When the server-side renewal scheduler swaps in a fresh cert, the next cron run sees a diff, writes the new files, and triggers the reload.

### Multiple certs, single host

Run one `certifi-cli request` per cert. Each call is independent — the server handles concurrency safely.

### Windows scheduled task

```powershell
certifi-cli.exe request -d app.example.com `
  --fullchain "C:\IIS\certs\app.fullchain.pem" `
  --privkey   "C:\IIS\certs\app.privkey.pem" `
  --reload-cmd "iisreset /noforce"
```

The CLI writes the privkey with restrictive permissions on Unix (`0600`); on Windows it relies on parent-directory ACLs. Place it under `C:\ProgramData\...` or another path with appropriate ACLs.

## URL handling

The `--url` you pass (or `CERTIFI_URL`) can be either the backend directly or the web admin — the CLI always appends `/api/...` itself:

- `http://localhost:8080` → backend serves `/api/foo` directly
- `https://certifi.example.com` → nginx proxies `/api/foo` to the backend

The CLI rejects URLs that already include `/api` to avoid `/api/api/...` mistakes.

The HTTP client negotiates HTTP/2 via ALPN with HTTP/1.1 fallback — the same shape as curl. If you're behind a strict reverse proxy and want to debug protocol negotiation, set `RUST_LOG=hyper=trace,rustls=debug` and re-run.
