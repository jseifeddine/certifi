# Contributing to Certifi

> **Why this document exists.** Certifi issues and stores TLS private keys and talks to
> production DNS. A "small" change in the wrong place can leak a key, mis-route an ACME
> challenge, or bypass an authorization check. The rules below are short on purpose — read
> them before opening a PR so review is about the idea, not the conventions.

---

## Ground rules

1. **Every change is reviewed.** No direct pushes to `main`. PR + at least one approval.
   Security-sensitive areas (ACME, the DNS provider clients, auth, RBAC, secret storage)
   warrant an extra-careful read.
2. **Every PR ships its own tests and docs.** A bug fix ships a regression test that fails
   before the fix. A feature ships docs under [`docs/`](./docs).
3. **Trunk-based.** Short-lived branches, squash-merge to `main`, no long-running forks.
4. **Conventional Commits** for PR titles: `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`,
   `test:`, `perf:`, `build:`, `ci:`. The PR body is the changelog entry — write it for humans
   and add a line to [`CHANGELOG.md`](./CHANGELOG.md) under `## [Unreleased]`.
5. **CI must be green.** `cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
   and `cargo test --workspace` all pass before merge. Run them locally first (see
   [Local checks](#local-checks)).

---

## Code standards (Rust)

- **Edition 2021, `rustfmt` is law.** Run `cargo fmt --all` before committing. The config is
  [`rustfmt.toml`](./rustfmt.toml) (100-column lines). CI fails on any unformatted file.
- **Clippy is denied at warning level.** `unsafe_code` is `forbid`-den workspace-wide
  (see `[workspace.lints]` in [`Cargo.toml`](./Cargo.toml)); `unused_must_use` is a hard error.
  If you must keep a deliberately-unused item, annotate it with a one-line `#[allow(dead_code)]`
  that says *why*, don't widen the lint.
- **Errors are typed, not stringly.** Library/`?`-propagating code returns `anyhow::Result`;
  public crate error enums use `thiserror`. The HTTP layer maps errors to status codes in one
  place ([`crates/certifi-server/src/error.rs`](./crates/certifi-server/src/error.rs)).
- **No `.unwrap()` / `.expect()` / `panic!` on runtime paths.** They're fine in tests and in
  truly-infallible startup wiring with a comment. Everywhere else, propagate with `?`.
- **No abbreviations** in identifiers beyond universally-understood acronyms (`url`, `id`,
  `dns`, `api`, `csr`, `acme`, `tls`). `propagation_delay`, not `prop_delay`.
- **Name the magic.** `const RENEW_WINDOW_DAYS: i64 = 30;` beats a bare `30` in a comparison.

### Boundaries (the hard rules)

- **Every DNS-01 provider goes through the `DnsProvider` trait.**
  ([`crates/certifi-server/src/integrations/`](./crates/certifi-server/src/integrations)).
  No ad-hoc `reqwest` calls to a registrar API anywhere else. Adding a provider means
  implementing the trait and adding one arm to `build_single_provider` — nothing in the
  renewal loop, handlers, or web admin should know which provider a zone belongs to. Zone
  ownership is resolved by the aggregator's first-match routing.
- **Secrets never travel in clear.** Integration credentials and ACME account keys are stored
  encrypted ([`services/secret.rs`](./crates/certifi-server/src/services/secret.rs)); secret
  fields are masked with `***` on the wire and only re-accepted as a new value, never echoed.
  Read process secrets once at boot through [`config.rs`](./crates/certifi-server/src/config.rs),
  not via scattered `std::env::var` calls.
- **Authorization is checked in the handler, before the work.** Cross-user / cross-resource
  operations gate on a permission key via the RBAC layer
  ([`rbac.rs`](./crates/certifi-server/src/rbac.rs)). Operations on *your own* resources are
  identity-checked, not permission-checked. Don't push authz down into the service layer.
- **Audit every state-changing operation.** Issuing, renewing, deleting a cert; creating or
  editing a user, role, integration, or setting — each writes an append-only audit row through
  [`audit.rs`](./crates/certifi-server/src/audit.rs). The audit writer redacts secret-looking
  keys at write time; keep that redaction list current when you add a secret field.
- **Wire types live in `certifi-types`.** Anything that crosses the HTTP boundary belongs in
  the shared crate so the server and the CLI client can't drift. Server-internal types (DB
  rows, settings keys) stay in `certifi-server`.

### Project layout

```
crates/
  certifi-server/   REST API + renewal daemon (the binary, `certifi`).
    src/
      handlers/     Axum route handlers — thin, orchestration + authz only.
      services/     Domain logic: acme, renewal, oidc, totp, sessions, pfx, secret, email.
      integrations/ DnsProvider trait + one module per provider (pdns, cloudflare, …).
      rbac.rs       Permission registry, system roles, scope checks.
      audit.rs      Append-only audit log + secret redaction.
      config.rs     Single boot-time env parse.
      error.rs      AppError → HTTP status mapping.
  certifi-types/    Wire types shared by server + client. No server-only deps.
  certifi-client/   Client library + `certifi-cli` for cron-driven automation.
web/                Optional React + Vite admin UI (served by nginx, proxies /api/*).
docs/               Long-form docs; `include_str!`'d into the binary and served at /docs.
```

---

## Testing

- **Unit tests live next to the code** in a `#[cfg(test)] mod tests` block in the same file.
  Prefer pure, hermetic tests with no network or filesystem. The things that *must* stay
  covered: hostname normalization/dedup, provider zone-routing, RBAC scope checks, audit
  redaction, config env-override precedence, and the ACME crypto/PEM helpers.
- **Every bug fix ships a test that fails before the fix.** No exceptions.
- **Coverage is not a goal.** Cover what matters — anything that touches a private key, a
  credential, an authorization decision, or the audit trail. Don't write tests to move a
  percentage.

### Local checks

The project builds with the toolchain pinned in the [`Dockerfile`](./Dockerfile)
(`rust:1.95.0`). If you have a matching local toolchain:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

No local Rust? Run the exact CI checks in a container:

```sh
docker run --rm -v "$PWD":/build -w /build rust:1.95.0-slim-bookworm bash -c '
  apt-get update -qq && apt-get install -y -qq --no-install-recommends pkg-config libssl-dev >/dev/null
  rustup component add rustfmt clippy >/dev/null
  cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace'
```

---

## Documentation standards

Docs rot when they aren't part of the change. Keep them in the same PR as the code.

- **Module-level `//!` comment** on every non-trivial file: *what it does and why it exists*,
  not a line-by-line narration.
- **Doc comments on public items.** A one-line summary; note error conditions and any
  surprising behavior. Internal helpers only need a comment when the behavior is non-obvious.
- **Comment the _why_, not the _what_.** `// Trailing dot is canonical at the PDNS API layer`
  is useful; `// strip the dot` is not.
- **User-facing docs go in [`docs/`](./docs).** They're compiled into the binary with
  `include_str!` and served at `/docs`, so a docs change ships with the build that serves it.
  When you add a new page, register it in
  [`handlers/docs.rs`](./crates/certifi-server/src/handlers/docs.rs).

---

## Security practices

- **Authorized testing only.** If you find a vulnerability, follow [`SECURITY.md`](./SECURITY.md);
  do not open a public issue.
- **No secrets in git, logs, or error messages** — especially private keys and provider API
  tokens. Logs and audit snapshots run through redaction; keep it current.
- **Pure-Rust crypto, no surprise system deps.** TLS is `rustls` where possible; the existing
  crates (`ring`, `rcgen`, `x509-parser`) are deliberate. Justify any new crypto dependency.
- **Think about the blast radius** for changes to ACME, the provider clients, auth, RBAC, or
  session handling. A sentence in the PR description — what could go wrong, what prevents it —
  is expected for those areas.

---

## Dependencies

- **The lockfile is the source of truth.** `Cargo.lock` is committed; CI and the Docker build
  use it as-is. Don't hand-edit it.
- **Justify every new dependency** in the PR: what does it buy that a little hand-written code
  wouldn't? Prefer small, single-purpose crates over framework-y ones.

---

## Governance, for now

The project is small: one maintainer with final say. Disagreement is welcome **in writing**,
not in revert wars. As the project grows this will become a written governance model.

Certifi is licensed under the **MIT License**. By contributing you agree your contribution is
licensed under the same terms.
