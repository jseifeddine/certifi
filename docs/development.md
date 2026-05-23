# Development

## Prerequisites

- Rust **1.75+** (workspace edition 2021).
- `pkg-config`, `libssl-dev` (Linux) — required by the `lettre` SMTP crate.
- Node **20+** (only if you're working on the web admin).
- Docker (optional, but the only sanity-check route on a host without a local Rust toolchain).

## Build

```bash
# Workspace check — fastest sanity check.
cargo check --workspace

# Build everything in release mode.
cargo build --release

# Just the server.
cargo build --release -p certifi-server
# Binary: target/release/certifi

# Just the CLI.
cargo build --release -p certifi-client --bin certifi-cli
# Binary: target/release/certifi-cli
```

## Dev loop

### Backend

```bash
RUST_LOG=certifi=debug cargo run -p certifi-server
# Listens on http://localhost:8080 — only /api/* is served, there are no static assets.
# Try http://localhost:8080/api/health to confirm it's up.
```

On the first run a fresh DB is created at `./data/certifi.db` and admin credentials are printed to the console.

### Web admin

```bash
cd web
npm install
npm run dev          # http://localhost:5173 — proxies /api/* → :8080
npm run build        # static bundle in web/dist/
```

The Vite dev server reads `vite.config.ts` and forwards every `/api/*` request to a `cargo run -p certifi-server` instance on `:8080`. Authenticate against the local backend just like in production.

### CLI

```bash
cargo run -p certifi-client --bin certifi-cli -- list
cargo run -p certifi-client --bin certifi-cli -- request -d test.local --fullchain /tmp/fc.pem --privkey /tmp/pk.pem
```

## Docker-only build sanity check

If you don't have a local Rust toolchain, you can `cargo check` via the build image used by `Dockerfile`:

```bash
docker run --rm \
  -v "$(pwd):/build" \
  -v cargo-cache:/usr/local/cargo/registry \
  -w /build \
  rust:1.95.0-slim-bookworm \
  sh -c "apt-get update >/dev/null && apt-get install -y --no-install-recommends pkg-config libssl-dev >/dev/null && cargo check --workspace"
```

The `cargo-cache` volume avoids re-downloading the index between runs.

## Database

SQLite at `$DATA_DIR/certifi.db`. WAL mode is enabled for concurrent reads. Schema migrations are additive (`ALTER TABLE ... ADD COLUMN` wrapped in `IF NOT EXISTS` logic, plus `CREATE TABLE IF NOT EXISTS`) so existing databases upgrade automatically on startup.

There are no down migrations. If you need to nuke state in dev: `rm -rf data/`.

## Adding a DNS provider

1. **Implement the trait.** Create `crates/certifi-server/src/integrations/<provider>.rs`:

   ```rust
   pub struct MyProvider { /* http client, token, … */ }

   impl MyProvider {
       pub fn new(token: String, delay: u64) -> Self { /* ... */ }
   }

   #[async_trait::async_trait]
   impl super::DnsProvider for MyProvider {
       fn name(&self) -> &'static str { "My Provider" }
       fn propagation_delay(&self) -> u64 { 10 }
       async fn deploy_challenge(&self, domain: &str, value: &str) -> anyhow::Result<()> { … }
       async fn clean_challenge(&self, domain: &str) -> anyhow::Result<()> { … }
       async fn list_zones(&self) -> anyhow::Result<Vec<String>> { … }
   }
   ```

   The `cloudflare.rs` / `digitalocean.rs` / `hetzner.rs` / `gandi.rs` files in the same folder are good templates depending on your provider's auth style.

2. **Register it** in `crates/certifi-server/src/integrations/mod.rs`:

   ```rust
   pub mod my_provider;

   // In build_single_provider:
   "my-provider" => {
       let token = get("my_provider_token");
       if token.is_empty() { anyhow::bail!("My Provider requires my_provider_token"); }
       Ok(Box::new(my_provider::MyProvider::new(token, parse_delay("my_provider_wait", 10))))
   }
   ```

3. **Add metadata** in `available_integrations()` so the web admin's "Add Integration" form renders the right fields:

   ```rust
   IntegrationMeta {
       id: "my-provider",
       name: "My Provider",
       fields: vec![
           IntegrationField { key: "my_provider_token", label: "API Token", field_type: "password", required: true, default: "", placeholder: "", hint: "Generate at …" },
           IntegrationField { key: "my_provider_wait",  label: "Propagation Delay (seconds)", field_type: "number", required: false, default: "10", placeholder: "10", hint: "" },
       ],
   }
   ```

   No web changes are needed — the cards UI is driven entirely off `available_integrations`. Secret fields (`field_type: "password"`) are automatically masked in responses and treated as preserve-on-empty by the edit modal.

4. **Update [docs/dns-providers.md](dns-providers.md)** with a per-provider section so users know what scopes / tokens to set up.

## Adding an endpoint

1. Define request/response types in `crates/certifi-types/src/lib.rs` if they cross the wire.
2. Add a handler function in `crates/certifi-server/src/handlers/<resource>.rs`.
3. Wire the route in `crates/certifi-server/src/main.rs` (look for the `Router::new()` block).
4. If the endpoint mutates cert state, emit a `CertEvent::changed(&id)` or `CertEvent::deleted(&id)` via the broadcast sender on `state.events` so the web admin sees live updates without polling.
5. Add a method on `Client` in `crates/certifi-client/src/lib.rs` (and a CLI subcommand if it makes sense).
6. Update [docs/api.md](api.md).

## Coding conventions

- **One concept per file.** Handlers split by resource (`handlers/certificates.rs`, `handlers/integrations.rs`); providers split by vendor (`integrations/cloudflare.rs`).
- **Wire types live in `certifi-types`.** Server-internal types (DB row structs, setting key constants) stay in `certifi-server`.
- **Comments explain *why*, not *what*.** Most code is self-evident; a comment is worth its space only when it captures an invariant, a subtle ordering constraint, or a workaround for a specific upstream quirk.
- **Errors surface upward via `anyhow::Result`** in services and `Result<T, AppError>` at the HTTP boundary. `AppError` maps cleanly to HTTP status + body.

## Testing

There's no test harness wired up yet. Quick verification flow when changing the issuance path:

1. Start a local server with Let's Encrypt **staging** configured (higher rate limits, free retries).
2. Configure a DNS integration against a real zone you control.
3. `cargo run -p certifi-client --bin certifi-cli -- request -d test.<your-zone>` and watch the logs.

Adding proper integration tests against an in-process fake CA + in-process fake DNS provider is on the to-do list.
