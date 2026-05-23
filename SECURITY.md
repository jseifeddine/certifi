# Security Policy

Certifi issues and stores TLS private keys and holds credentials for production DNS providers.
Security reports are taken seriously and handled with priority.

## Supported versions

The latest released `1.x` line receives security fixes. Older minor versions are not
backported — upgrade to the latest release.

| Version | Supported |
| ------- | --------- |
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report privately through GitHub's
[**Report a vulnerability**](https://github.com/jseifeddine/certifi/security/advisories/new)
flow (the **Security** tab → *Report a vulnerability*). This opens a private advisory visible
only to you and the maintainer.

When you report, please include:

- A description of the issue and its impact (key disclosure, authorization bypass, challenge
  mis-routing, credential leak, etc.).
- Steps to reproduce, a proof of concept, or the affected code path.
- The version or commit you tested against.

You can expect an acknowledgement within a few days. Once a fix is ready, a patched release is
cut and the advisory is published with credit to the reporter (unless you prefer to remain
anonymous).

## Scope

In scope: anything that leaks a private key or provider credential, bypasses authentication or
RBAC, forges or mis-routes an ACME DNS-01 challenge, or escalates privileges.

Out of scope: findings that require an already-compromised host or database, missing hardening
on a deliberately insecure demo configuration, and reports generated solely by automated
scanners without a demonstrated impact. See [`docs/security.md`](./docs/security.md) for the
production-hardening checklist.
