use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

pub async fn create_pool(db_path: &str) -> anyhow::Result<SqlitePool> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite:{}", db_path))?
        .create_if_missing(true)
        .pragma("journal_mode", "WAL")
        .pragma("synchronous", "NORMAL")
        .pragma("foreign_keys", "ON")
        .pragma("temp_store", "MEMORY")
        .pragma("cache_size", "10000");

    let pool = SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(opts)
        .await?;

    run_migrations(&pool).await?;
    Ok(pool)
}

async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            email TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            expires_at TEXT
        );

        CREATE TABLE IF NOT EXISTS certificates (
            id TEXT PRIMARY KEY,
            common_name TEXT NOT NULL,
            sans TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'pending',
            auto_renew INTEGER NOT NULL DEFAULT 1,
            fullchain_pem TEXT,
            privkey_pem TEXT,
            cert_pem TEXT,
            chain_pem TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            expires_at TEXT,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS integrations (
            id TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            name TEXT NOT NULL,
            config TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_certificates_cn ON certificates(common_name);
        CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);
        CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
        CREATE INDEX IF NOT EXISTS idx_integrations_enabled ON integrations(enabled);

        -- ── RBAC ────────────────────────────────────────────────────────────
        -- `permissions` is a registry of every valid permission key (e.g.
        -- 'certificate.create'). The set is owned by the code — see rbac.rs.
        -- We persist them so the admin UI can list and bind to them, and so
        -- a forward-migrated DB still works if a role references a perm the
        -- new binary hasn't seeded yet.
        CREATE TABLE IF NOT EXISTS permissions (
            key TEXT PRIMARY KEY,
            description TEXT
        );

        -- `roles` collects a set of permissions under a human name. System
        -- roles (is_system=1) are seeded at boot and cannot be deleted; user
        -- roles can be created freely once the admin UI lands.
        CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_system INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
            PRIMARY KEY (role_id, permission_key)
        );

        -- A user holds a role with a scope. Scope is 'global' for now;
        -- phase 2 introduces 'zone:<fqdn>' etc. A user can have multiple
        -- assignments — their effective perms are the union.
        CREATE TABLE IF NOT EXISTS role_assignments (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            scope TEXT NOT NULL DEFAULT 'global',
            granted_by TEXT,
            granted_at TEXT NOT NULL,
            UNIQUE (user_id, role_id, scope)
        );

        CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON role_assignments(user_id);

        -- ── OIDC / external identities ─────────────────────────────────────
        -- One row per (provider, issuer, subject). Lets a single Certifi user
        -- be linked to multiple identity sources later (Azure AD + Google
        -- both pointing at the same person). For phase 3 there's only one
        -- provider, but the shape is forward-compatible.
        CREATE TABLE IF NOT EXISTS identities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            provider TEXT NOT NULL,
            issuer TEXT NOT NULL,
            subject TEXT NOT NULL,
            email TEXT,
            last_login_at TEXT,
            created_at TEXT NOT NULL,
            UNIQUE (provider, issuer, subject)
        );

        -- Short-lived state for in-flight OIDC flows. Each /start writes a
        -- row, /callback reads-and-deletes. Rows older than 10 minutes are
        -- swept at lookup time.
        CREATE TABLE IF NOT EXISTS oidc_states (
            state TEXT PRIMARY KEY,
            nonce TEXT NOT NULL,
            pkce_verifier TEXT NOT NULL,
            return_to TEXT,
            created_at TEXT NOT NULL
        );

        -- group claim from the IdP → role assignment. Multiple rows per
        -- group are allowed (one group can confer multiple roles, e.g.
        -- a Viewer + a zone-scoped Operator).
        CREATE TABLE IF NOT EXISTS oidc_group_mappings (
            id TEXT PRIMARY KEY,
            group_name TEXT NOT NULL,
            role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
            scope TEXT NOT NULL DEFAULT 'global',
            created_at TEXT NOT NULL,
            UNIQUE (group_name, role_id, scope)
        );

        -- ── Audit log ───────────────────────────────────────────────────────
        -- Append-only record of every state-changing action. `before_json`
        -- and `after_json` are NULL for create/delete respectively. Sensitive
        -- values are redacted (secrets, password hashes) before write.
        CREATE TABLE IF NOT EXISTS audit_log (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            actor_user_id TEXT,
            actor_username TEXT,
            actor_token_id TEXT,
            action TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            resource_id TEXT,
            before_json TEXT,
            after_json TEXT,
            ip TEXT,
            user_agent TEXT,
            request_id TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource_type, resource_id);

        -- ── Sessions (phase 6) ──────────────────────────────────────────────
        -- Opaque, server-side session rows. The cookie carries only the id;
        -- DB row holds the user link + activity window. Lets us revoke
        -- instantly (DELETE the row) without rotating a JWT secret.
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            last_used_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

        -- Two-step login: a successful password check for a TOTP-enrolled
        -- user issues a short-lived challenge token, which the client
        -- exchanges for a real session via POST /api/auth/login/totp.
        CREATE TABLE IF NOT EXISTS login_challenges (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        -- One TOTP enrollment per user. `secret_enc` is the base32 secret
        -- encrypted with COOKIE_KEY; `verified_at` stays NULL until the
        -- user proves they can type a current code, at which point the
        -- factor becomes a hard requirement on subsequent logins.
        CREATE TABLE IF NOT EXISTS user_totp (
            user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            secret_enc TEXT NOT NULL,
            enrolled_at TEXT NOT NULL,
            verified_at TEXT
        );
        "#,
    )
    .execute(pool)
    .await?;

    // Additive migrations for existing databases
    for stmt in [
        "ALTER TABLE certificates ADD COLUMN auto_renew INTEGER NOT NULL DEFAULT 1",
        "ALTER TABLE users ADD COLUMN email TEXT",
        "ALTER TABLE certificates ADD COLUMN key_algo TEXT",
        // Encrypted PFX password — null until the user generates a PFX, then
        // persisted (AES-256-GCM, base64) and reused on subsequent generations.
        "ALTER TABLE certificates ADD COLUMN pfx_password_enc TEXT",
        // Optional free-text label so operators can annotate a cert (purpose,
        // owning service, etc.) — shown in the web admin and settable via API/CLI.
        "ALTER TABLE certificates ADD COLUMN description TEXT",
        // RBAC phase 3: tracks where an assignment came from so OIDC sync can
        // reconcile its own grants without clobbering hand-administered ones.
        // 'manual' (admin assigned) | 'oidc' (synced from a group claim).
        "ALTER TABLE role_assignments ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'",
        // RBAC phase 4: per-token permission ceiling. NULL means "inherit
        // the issuing user's current permissions" (phase 1/2 behaviour); a
        // JSON string array means "intersect with this set at every request".
        "ALTER TABLE api_tokens ADD COLUMN permissions TEXT",
        // RP-initiated logout: when the session was minted via OIDC, remember
        // the id_token (needed as `id_token_hint`) and the IdP's
        // end_session_endpoint discovered at sign-in time. NULL for local
        // sessions — logout falls back to the plain cookie-clear path.
        "ALTER TABLE sessions ADD COLUMN oidc_id_token TEXT",
        "ALTER TABLE sessions ADD COLUMN oidc_end_session_url TEXT",
    ] {
        let _ = sqlx::query(stmt).execute(pool).await; // ignore "duplicate column" errors
    }

    Ok(())
}
