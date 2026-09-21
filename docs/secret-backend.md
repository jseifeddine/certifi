# Secret backend (OpenBao)

By default every secret Certifi holds lives in the SQLite database under `DATA_DIR`:

- certificate private keys and chains
- the ACME account key
- DNS provider API tokens

Nothing there is encrypted at rest — the protection is filesystem permissions on the volume. That's fine for a single trusted host and not fine if the volume gets snapshotted, backed up somewhere shared, or mounted by anything else.

Set `BAO_ADDR` and Certifi writes that material to an [OpenBao](https://openbao.org/) KV mount instead. The database keeps only metadata — id, common name, SANs, status, expiry — so listing, RBAC, the renewal scheduler and the web admin all behave identically.

This is entirely opt-in. With `BAO_ADDR` unset nothing changes.

> HashiCorp Vault speaks the same API and works too. Every `BAO_*` variable below is also read as `VAULT_*`, so an environment already set up for Vault needs no new variables.

## What moves

| Secret | Path in the mount | Fields |
|---|---|---|
| Certificate material | `<base>/certificates/<cert-id>` | `fullchain_pem`, `cert_pem`, `chain_pem`, `privkey_pem`, `pfx_password` |
| ACME account key | `<base>/acme/account` | `key_pkcs8_b64` |
| DNS integration credentials | `<base>/integrations/<integration-id>` | the provider's config keys (`cf_api_token`, `pdns_key`, …) |

`<base>` is `BAO_PATH`, default `certifi`. With the default `BAO_MOUNT=secret` and KV v2, a cert's key is at `secret/data/certifi/certificates/<id>`.

TOTP secrets and the OIDC client secret are **not** moved. They stay AES-256-GCM encrypted under `COOKIE_KEY` — they're login-path state, and putting a network round-trip in front of every sign-in buys nothing.

## Quick start

```yaml
services:
  certifi:
    environment:
      - BAO_ADDR=https://openbao.internal:8200
      - BAO_TOKEN=${BAO_TOKEN}
      # Optional — these are the defaults:
      # - BAO_MOUNT=secret
      # - BAO_PATH=certifi
```

On the next start the log tells you which backend is live:

```
INFO certifi::services::secret_store: Secret backend: OpenBao — https://openbao.internal:8200 mount=secret path=certifi kv=v2 auth=token
```

If Certifi can't reach OpenBao or the credentials are rejected, **it refuses to start**. A server that silently fell back to writing private keys to disk would be worse than one that didn't come up.

## Environment variables

### Connection

| Variable | Default | Description |
|---|---|---|
| `BAO_ADDR` | *(unset — backend off)* | Base URL of the OpenBao server. Setting this enables the backend. |
| `BAO_MOUNT` | `secret` | KV mount point. |
| `BAO_PATH` | `certifi` | Path prefix inside the mount. Everything Certifi writes lives under it. |
| `BAO_KV_VERSION` | `2` | `1` or `2`. Must match how the mount was created. |
| `BAO_NAMESPACE` | *(none)* | Sent as `X-Vault-Namespace`. |
| `BAO_CACERT` | *(none)* | Path to a PEM CA bundle for a privately-signed OpenBao certificate. |
| `BAO_SKIP_VERIFY` | `false` | Disables TLS verification. Every secret the instance holds transits this connection — use it for a local test server and nowhere else. |

### Authentication

Pick one. AppRole wins if both are supplied.

**Token:**

| Variable | Description |
|---|---|
| `BAO_TOKEN` | The token itself. |
| `BAO_TOKEN_FILE` | Path to a file containing it — how Docker and Kubernetes secrets normally arrive. |

Certifi renews the token against `auth/token/renew-self` while OpenBao reports it as renewable. A root or non-renewable token is used as-is.

**AppRole:**

| Variable | Default | Description |
|---|---|---|
| `BAO_ROLE_ID` / `BAO_ROLE_ID_FILE` | | The role id. |
| `BAO_SECRET_ID` / `BAO_SECRET_ID_FILE` | | The secret id. |
| `BAO_APPROLE_PATH` | `approle` | Mount path of the AppRole auth method. |

Certifi logs in at startup and re-logs in before the lease expires, so short token TTLs are fine — preferred, in fact.

## Policy

Certifi needs read/write on its own prefix and nothing else:

```hcl
path "secret/data/certifi/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Permanently destroying a deleted cert's key material goes through the
# metadata endpoint on KV v2.
path "secret/metadata/certifi/*" {
  capabilities = ["read", "delete", "list"]
}
```

Adjust `secret/` and `certifi/` if you changed `BAO_MOUNT` or `BAO_PATH`. On KV v1, drop the `data/` and `metadata/` segments.

Setting it up from scratch:

```bash
bao secrets enable -path=secret kv-v2          # if the mount doesn't exist
bao auth enable approle
bao policy write certifi ./certifi.hcl
bao write auth/approle/role/certifi \
    token_policies=certifi token_ttl=20m token_max_ttl=4h

bao read  -field=role_id   auth/approle/role/certifi/role-id
bao write -field=secret_id -f auth/approle/role/certifi/secret-id
```

## Migrating an existing instance

Turning the backend on for a database that already holds secrets migrates them at the next startup. For each one Certifi writes it to OpenBao, reads it back, verifies every field survived the round trip, and only then clears the database column.

```
INFO Migrated secrets into OpenBao: 12 certificate(s), 2 integration(s), acme_account_key=true. The corresponding database columns are now empty.
INFO Database file rewritten — no stale copies of the migrated secrets remain
```

That second line matters. `UPDATE … SET col = NULL` only unlinks the old payload — the bytes stay legible in free pages and WAL frames, where `grep` finds them. So after a migration that moved something, Certifi checkpoints the WAL, runs `VACUUM` to rebuild the file from live rows only, and truncates the WAL again.

The sweep is **idempotent**: a row already carrying a reference is skipped, so later restarts cost one query. An interrupted run loses nothing — it just leaves work for the next boot.

**Take a backup of `DATA_DIR` before the first boot with the backend enabled.** The migration is one-way.

### Going back

There's no automated path back. Each row records where its own material lives, so a database mid-migration is coherent, but unsetting `BAO_ADDR` after a successful migration leaves Certifi unable to read anything already moved — the API returns an error naming the missing backend rather than pretending the cert has no key. Restore the pre-migration backup, or re-issue.

## How a row knows where its secret is

Each row carries its own pointer rather than the instance carrying a mode flag:

- `certificates.secret_ref` — `openbao:certificates/<id>`, with the PEM columns NULL
- `settings.acme_account_key` — the value becomes `openbao:acme/account`
- `integrations.config` — the JSON blob becomes `openbao:integrations/<id>`

A value with no `openbao:` prefix is the secret itself. That's what makes a half-migrated database safe, and what lets a certificate issued before the switch keep working until its next renewal moves it.

## Operational notes

- **Deleting a certificate destroys its key material.** Certifi issues a KV v2 *destroy* (all versions), not a soft delete — "delete this certificate" has to mean the private key is gone. Same for a deleted DNS integration.
- **Renewals keep the PFX password.** Re-issuing overwrites the PEM fields and carries the existing `pfx_password` forward, so an archive already downloaded keeps opening.
- **An unavailable backend degrades where it can.** A DNS integration whose credentials can't be read is logged and skipped so the others still issue certs. A certificate whose material can't be read returns an error on download rather than reporting itself as empty.
- **OpenBao availability becomes issuance availability.** The renewal scheduler needs the ACME account key and the DNS credentials on every run. Certificate metadata still lists fine if OpenBao is down; issuing and downloading do not.
- **`COOKIE_KEY` is still required.** TOTP secrets and the OIDC client secret continue to use it.
