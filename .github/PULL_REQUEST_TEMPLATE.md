<!--
Thanks for contributing to Certifi! Keep this PR small and focused.
The title must follow Conventional Commits, e.g. `fix: route challenge to most-specific zone`.
-->

## What & why

<!-- What does this change and why? This text becomes the CHANGELOG entry — write it for humans. -->

Closes #

## Type of change

- [ ] `fix` — bug fix (ships a regression test that fails before the fix)
- [ ] `feat` — new feature (ships docs)
- [ ] `docs` / `refactor` / `chore` / `test` / `perf` / `build` / `ci`

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Tests added/updated for the change
- [ ] Docs updated (`docs/`) and `CHANGELOG.md` has an `## [Unreleased]` entry
- [ ] No secrets in code, logs, or error messages

## Security impact

<!--
Required for changes to ACME, the DNS provider clients, auth, RBAC, sessions, or secret
storage. One paragraph: what could go wrong, and what in this PR prevents it? Write "n/a"
if the change doesn't touch those areas.
-->
