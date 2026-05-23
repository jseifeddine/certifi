//! Role-based access control.
//!
//! Phase 1 model: a fixed permission registry, a small set of system roles
//! that cover the existing admin/non-admin split, and per-user `role_assignments`.
//! A user's effective permissions are the **union** of permissions across
//! every role assignment, regardless of scope (scope filtering arrives in
//! phase 2 alongside per-domain authorization).
//!
//! Handlers gate on permissions via [`AuthUser::require`], e.g.
//!
//! ```ignore
//! auth.require(perms::CERTIFICATE_CREATE)?;
//! ```
//!
//! Anything callable on **your own resources** (e.g. changing your own
//! password, listing your own API tokens) is identity-checked in the
//! handler itself and does NOT consume a permission. Permissions only
//! gate cross-user operations.

use chrono::Utc;
use sqlx::SqlitePool;
use std::collections::HashSet;
use uuid::Uuid;

/// Permission keys. All grants reference one of these strings. The list is
/// owned by the code — it's seeded into the `permissions` table at boot so
/// the admin UI can render a checklist, but the source of truth is here.
pub mod perms {
    // Certificates
    pub const CERTIFICATE_LIST: &str = "certificate.list";
    pub const CERTIFICATE_READ: &str = "certificate.read";
    pub const CERTIFICATE_CREATE: &str = "certificate.create";
    pub const CERTIFICATE_RENEW: &str = "certificate.renew";
    pub const CERTIFICATE_UPDATE: &str = "certificate.update";
    pub const CERTIFICATE_DELETE: &str = "certificate.delete";
    pub const CERTIFICATE_DOWNLOAD: &str = "certificate.download";

    // API tokens — these gate operations on OTHER users' tokens. A user
    // can always list/create/delete their own tokens (identity check in
    // the handler).
    pub const TOKEN_MANAGE_ALL: &str = "token.manage_all";

    // Users — admin operations on the user table.
    pub const USER_LIST: &str = "user.list";
    pub const USER_CREATE: &str = "user.create";
    pub const USER_UPDATE: &str = "user.update";
    pub const USER_DELETE: &str = "user.delete";
    /// Set someone else's password. The "change my own" path is identity-checked.
    pub const USER_PASSWORD_UPDATE: &str = "user.password.update";

    // DNS integrations
    pub const INTEGRATION_LIST: &str = "integration.list";
    pub const INTEGRATION_READ: &str = "integration.read";
    pub const INTEGRATION_CREATE: &str = "integration.create";
    pub const INTEGRATION_UPDATE: &str = "integration.update";
    pub const INTEGRATION_DELETE: &str = "integration.delete";
    pub const INTEGRATION_TEST: &str = "integration.test";

    // Settings (ACME + key algo)
    pub const SETTINGS_READ: &str = "settings.read";
    pub const SETTINGS_UPDATE: &str = "settings.update";
    pub const SETTINGS_ACME_REGISTER: &str = "settings.acme.register";

    // Misc
    pub const DOMAIN_LIST: &str = "domain.list";

    // Role administration
    pub const ROLE_LIST: &str = "role.list";
    pub const ROLE_CREATE: &str = "role.create";
    pub const ROLE_UPDATE: &str = "role.update";
    pub const ROLE_DELETE: &str = "role.delete";
    pub const ROLE_ASSIGN: &str = "role.assign";

    // Reserved for later phases — listed here so seeding includes them.
    pub const AUDIT_READ: &str = "audit.read"; // phase 5
}

/// Every permission known to this binary, with a short description used by
/// the admin UI. Add entries here when adding a new permission.
pub const ALL: &[(&str, &str)] = &[
    (perms::CERTIFICATE_LIST, "List certificates"),
    (perms::CERTIFICATE_READ, "Read a single certificate"),
    (perms::CERTIFICATE_CREATE, "Issue a new certificate"),
    (perms::CERTIFICATE_RENEW, "Force-renew a certificate"),
    (
        perms::CERTIFICATE_UPDATE,
        "Edit a certificate (auto-renew, description)",
    ),
    (perms::CERTIFICATE_DELETE, "Delete a certificate"),
    (
        perms::CERTIFICATE_DOWNLOAD,
        "Download certificate material (PEM, PFX, key)",
    ),
    (perms::TOKEN_MANAGE_ALL, "Manage other users' API tokens"),
    (perms::USER_LIST, "List users"),
    (perms::USER_CREATE, "Create users"),
    (perms::USER_UPDATE, "Update users (email, role)"),
    (perms::USER_DELETE, "Delete users"),
    (
        perms::USER_PASSWORD_UPDATE,
        "Change another user's password",
    ),
    (perms::INTEGRATION_LIST, "List DNS integrations"),
    (perms::INTEGRATION_READ, "Read a DNS integration"),
    (perms::INTEGRATION_CREATE, "Create a DNS integration"),
    (perms::INTEGRATION_UPDATE, "Update a DNS integration"),
    (perms::INTEGRATION_DELETE, "Delete a DNS integration"),
    (perms::INTEGRATION_TEST, "Test a DNS integration"),
    (perms::SETTINGS_READ, "View instance settings"),
    (perms::SETTINGS_UPDATE, "Update instance settings"),
    (
        perms::SETTINGS_ACME_REGISTER,
        "Register / re-register the ACME account",
    ),
    (perms::DOMAIN_LIST, "List available DNS zones"),
    (perms::ROLE_LIST, "List roles"),
    (perms::ROLE_CREATE, "Create custom roles"),
    (perms::ROLE_UPDATE, "Edit custom roles"),
    (perms::ROLE_DELETE, "Delete custom roles"),
    (perms::ROLE_ASSIGN, "Grant or revoke role assignments"),
    (perms::AUDIT_READ, "Read the audit log"),
];

// ── System roles ─────────────────────────────────────────────────────────────

/// Stable identifiers for the seeded system roles. Used by phase-3 OIDC group
/// mapping, the migration of legacy admin/non-admin users, and the admin UI's
/// "you can't delete this" guard.
pub mod system_roles {
    pub const SUPER_ADMIN: &str = "system:super_admin";
    pub const OPERATOR: &str = "system:operator";
    pub const VIEWER: &str = "system:viewer";
}

/// Permission set for the SuperAdmin role: literally every key. Generated at
/// runtime so adding a new permission auto-grants it to SuperAdmin.
fn super_admin_perms() -> Vec<&'static str> {
    ALL.iter().map(|(k, _)| *k).collect()
}

/// Operator: full read/write on certificates, tokens (own), integrations, and
/// domains. No user / settings / role administration.
fn operator_perms() -> Vec<&'static str> {
    vec![
        perms::CERTIFICATE_LIST,
        perms::CERTIFICATE_READ,
        perms::CERTIFICATE_CREATE,
        perms::CERTIFICATE_RENEW,
        perms::CERTIFICATE_UPDATE,
        perms::CERTIFICATE_DELETE,
        perms::CERTIFICATE_DOWNLOAD,
        perms::INTEGRATION_LIST,
        perms::INTEGRATION_READ,
        perms::INTEGRATION_CREATE,
        perms::INTEGRATION_UPDATE,
        perms::INTEGRATION_DELETE,
        perms::INTEGRATION_TEST,
        perms::DOMAIN_LIST,
        perms::SETTINGS_READ,
    ]
}

/// Viewer: read-only. Useful for service-account tokens that just pull cert
/// material for monitoring or distribution.
fn viewer_perms() -> Vec<&'static str> {
    vec![
        perms::CERTIFICATE_LIST,
        perms::CERTIFICATE_READ,
        perms::CERTIFICATE_DOWNLOAD,
        perms::INTEGRATION_LIST,
        perms::INTEGRATION_READ,
        perms::DOMAIN_LIST,
        perms::SETTINGS_READ,
    ]
}

struct SystemRoleSpec {
    id: &'static str,
    name: &'static str,
    description: &'static str,
    perms: fn() -> Vec<&'static str>,
}

const SYSTEM_ROLES: &[SystemRoleSpec] = &[
    SystemRoleSpec {
        id: system_roles::SUPER_ADMIN,
        name: "SuperAdmin",
        description: "Full control over every resource and every other role.",
        perms: super_admin_perms,
    },
    SystemRoleSpec {
        id: system_roles::OPERATOR,
        name: "Operator",
        description:
            "Manage certificates, DNS integrations, and tokens. No user or settings administration.",
        perms: operator_perms,
    },
    SystemRoleSpec {
        id: system_roles::VIEWER,
        name: "Viewer",
        description: "Read-only access to certificates, integrations, and domains.",
        perms: viewer_perms,
    },
];

// ── Boot-time seeding + migration ────────────────────────────────────────────

/// Seed the permission registry and the system roles. Idempotent — safe to
/// run on every boot. Also synchronises the role_permissions of system roles
/// so adding a new permission to e.g. SuperAdmin in code propagates on the
/// next start.
pub async fn seed(db: &SqlitePool) -> anyhow::Result<()> {
    // 1. Register every known permission.
    for (key, description) in ALL {
        sqlx::query(
            "INSERT INTO permissions (key, description) VALUES (?, ?)
             ON CONFLICT(key) DO UPDATE SET description = excluded.description",
        )
        .bind(key)
        .bind(description)
        .execute(db)
        .await?;
    }

    // 2. Upsert system roles, then re-sync their permission lists.
    let now = Utc::now().to_rfc3339();
    for spec in SYSTEM_ROLES {
        sqlx::query(
            "INSERT INTO roles (id, name, description, is_system, created_at, updated_at)
             VALUES (?, ?, ?, 1, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                 name = excluded.name,
                 description = excluded.description,
                 is_system = 1,
                 updated_at = excluded.updated_at",
        )
        .bind(spec.id)
        .bind(spec.name)
        .bind(spec.description)
        .bind(&now)
        .bind(&now)
        .execute(db)
        .await?;

        // Clear and rewrite the perms — small, fixed sets, simpler than a diff.
        sqlx::query("DELETE FROM role_permissions WHERE role_id = ?")
            .bind(spec.id)
            .execute(db)
            .await?;
        for perm in (spec.perms)() {
            sqlx::query("INSERT INTO role_permissions (role_id, permission_key) VALUES (?, ?)")
                .bind(spec.id)
                .bind(perm)
                .execute(db)
                .await?;
        }
    }

    Ok(())
}

/// Set or clear a user's "admin" status by reconciling their SuperAdmin
/// role assignment. The legacy `users.is_admin` flag becomes a shorthand
/// for "holds the SuperAdmin role at global scope":
///
///   `true`  → grant SuperAdmin if not already present
///   `false` → drop the SuperAdmin assignment; leave the user with at least
///             an Operator grant so they're not silently locked out
///
/// `granted_by` is the actor (usually `auth.user_id`) of the admin making
/// the change, recorded on the row.
pub async fn set_user_admin_status(
    db: &SqlitePool,
    user_id: &str,
    is_admin: bool,
    granted_by: Option<&str>,
) -> Result<(), sqlx::Error> {
    let now = Utc::now().to_rfc3339();
    if is_admin {
        sqlx::query(
            "INSERT INTO role_assignments
                (id, user_id, role_id, scope, granted_by, granted_at, source)
             VALUES (?, ?, ?, 'global', ?, ?, 'manual')
             ON CONFLICT(user_id, role_id, scope) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(system_roles::SUPER_ADMIN)
        .bind(granted_by)
        .bind(&now)
        .execute(db)
        .await?;
    } else {
        sqlx::query(
            "DELETE FROM role_assignments
             WHERE user_id = ? AND role_id = ? AND scope = 'global'",
        )
        .bind(user_id)
        .bind(system_roles::SUPER_ADMIN)
        .execute(db)
        .await?;
        // Ensure the user retains at least Operator so they're not silently
        // locked out when an admin toggles them off.
        sqlx::query(
            "INSERT INTO role_assignments
                (id, user_id, role_id, scope, granted_by, granted_at, source)
             VALUES (?, ?, ?, 'global', ?, ?, 'manual')
             ON CONFLICT(user_id, role_id, scope) DO NOTHING",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(user_id)
        .bind(system_roles::OPERATOR)
        .bind(granted_by)
        .bind(&now)
        .execute(db)
        .await?;
    }
    Ok(())
}

/// Reconcile every user's role assignments against the legacy `is_admin`
/// column at boot. Idempotent — covers three cases:
///
///   1. Pre-RBAC users with no assignments at all → Operator (or SuperAdmin
///      when `is_admin = 1`). Phase-1 migration path.
///   2. Existing `is_admin = 1` users who somehow lost their SuperAdmin
///      assignment → re-granted on boot. Self-healing for the gap where
///      `users::update` flipped `is_admin` without touching role rows.
///   3. Brand new users whose `users::create` path predates the role-on-
///      insert fix → also covered by case 1 on the next restart.
///
/// Users who already hold a non-SuperAdmin role assignment but are
/// `is_admin = 0` are left untouched — the explicit assignment wins.
pub async fn migrate_existing_users(db: &SqlitePool) -> anyhow::Result<()> {
    let users: Vec<(String, bool)> = sqlx::query_as("SELECT id, is_admin FROM users")
        .fetch_all(db)
        .await?;

    for (user_id, is_admin) in users {
        // Skip users who already have an explicit assignment AND aren't
        // legacy admins missing SuperAdmin.
        let assignments: Vec<(String,)> =
            sqlx::query_as("SELECT role_id FROM role_assignments WHERE user_id = ?")
                .bind(&user_id)
                .fetch_all(db)
                .await?;

        let has_super_admin = assignments
            .iter()
            .any(|(r,)| r == system_roles::SUPER_ADMIN);

        if is_admin && !has_super_admin {
            set_user_admin_status(db, &user_id, true, None).await?;
            tracing::info!(
                "RBAC: reconciled SuperAdmin for legacy is_admin=1 user {}",
                user_id
            );
        } else if assignments.is_empty() {
            set_user_admin_status(db, &user_id, false, None).await?;
            tracing::info!("RBAC: granted Operator to unassigned user {}", user_id);
        }
    }
    Ok(())
}

// ── Runtime lookup ───────────────────────────────────────────────────────────

/// A single non-global grant: one scope (e.g. `"zone:example.com"`) bound to
/// the set of permission keys the assigned role grants.
#[derive(Debug, Clone)]
pub struct ScopedGrant {
    pub scope: String,
    pub permissions: HashSet<String>,
}

/// The full RBAC view for a user: their global-scope permissions (the union
/// across every `scope = 'global'` assignment) plus per-scope grants for any
/// other assignments. Constructed once per request by the auth extractor.
#[derive(Debug, Clone, Default)]
pub struct UserGrants {
    pub global: HashSet<String>,
    pub scoped: Vec<ScopedGrant>,
}

/// True iff the supplied scope zone covers `domain` — i.e. they're the same
/// host, or `domain` is a subdomain of `zone`. Matching is case-insensitive
/// and trailing dots are stripped. Used by zone-scoped permission checks.
pub fn zone_covers(zone: &str, domain: &str) -> bool {
    let z = zone.trim().trim_end_matches('.').to_lowercase();
    let d = domain.trim().trim_end_matches('.').to_lowercase();
    !z.is_empty() && (d == z || d.ends_with(&format!(".{}", z)))
}

/// Compatibility shim: returns just the global-scope permission union.
/// Kept because the login handler still calls into the simple form. Code
/// paths that need scope awareness should call [`load_user_grants`] instead.
pub async fn load_user_permissions(
    db: &SqlitePool,
    user_id: &str,
) -> Result<HashSet<String>, sqlx::Error> {
    Ok(load_user_grants(db, user_id).await?.global)
}

/// Load every role assignment for a user and bucket the resulting
/// permissions by scope.
pub async fn load_user_grants(db: &SqlitePool, user_id: &str) -> Result<UserGrants, sqlx::Error> {
    // (scope, permission_key) pairs across every assignment held by this user.
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT ra.scope, rp.permission_key
         FROM role_assignments ra
         JOIN role_permissions rp ON rp.role_id = ra.role_id
         WHERE ra.user_id = ?",
    )
    .bind(user_id)
    .fetch_all(db)
    .await?;

    let mut global: HashSet<String> = HashSet::new();
    let mut by_scope: std::collections::HashMap<String, HashSet<String>> =
        std::collections::HashMap::new();
    for (scope, perm) in rows {
        if scope == "global" {
            global.insert(perm);
        } else {
            by_scope.entry(scope).or_default().insert(perm);
        }
    }
    let scoped = by_scope
        .into_iter()
        .map(|(scope, permissions)| ScopedGrant { scope, permissions })
        .collect();
    Ok(UserGrants { global, scoped })
}

/// True iff the user has the SuperAdmin role assigned at global scope. Kept
/// as a dedicated query so the `is_admin` derived flag stays cheap and so
/// the answer is unambiguous regardless of what permissions SuperAdmin
/// currently bundles.
pub async fn is_super_admin(db: &SqlitePool, user_id: &str) -> Result<bool, sqlx::Error> {
    let row: Option<(i64,)> = sqlx::query_as(
        "SELECT 1 FROM role_assignments
         WHERE user_id = ? AND role_id = ? AND scope = 'global' LIMIT 1",
    )
    .bind(user_id)
    .bind(system_roles::SUPER_ADMIN)
    .fetch_optional(db)
    .await?;
    Ok(row.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_keys() -> HashSet<&'static str> {
        ALL.iter().map(|(k, _)| *k).collect()
    }

    // ── zone_covers ─────────────────────────────────────────────────────────

    #[test]
    fn zone_covers_exact_and_subdomain() {
        assert!(zone_covers("example.com", "example.com"));
        assert!(zone_covers("example.com", "www.example.com"));
        assert!(zone_covers("example.com", "a.b.example.com"));
    }

    #[test]
    fn zone_covers_is_case_and_trailing_dot_insensitive() {
        assert!(zone_covers("Example.COM.", "www.example.com"));
        assert!(zone_covers(" example.com ", "EXAMPLE.com."));
    }

    #[test]
    fn zone_covers_rejects_sibling_suffix_and_empty() {
        // A label boundary is required — a raw suffix match is not enough.
        assert!(!zone_covers("example.com", "notexample.com"));
        assert!(!zone_covers("example.com", "example.com.attacker.tld"));
        assert!(!zone_covers("", "example.com"));
        assert!(!zone_covers("   ", "example.com"));
    }

    // ── Permission registry + role invariants ───────────────────────────────

    #[test]
    fn permission_keys_are_unique() {
        let keys: Vec<&str> = ALL.iter().map(|(k, _)| *k).collect();
        let unique: HashSet<&str> = keys.iter().copied().collect();
        assert_eq!(keys.len(), unique.len(), "duplicate permission key in ALL");
    }

    #[test]
    fn super_admin_holds_every_permission() {
        let granted: HashSet<&str> = super_admin_perms().into_iter().collect();
        assert_eq!(
            granted,
            all_keys(),
            "SuperAdmin must hold exactly the full registry"
        );
    }

    #[test]
    fn operator_and_viewer_only_reference_registered_permissions() {
        let registry = all_keys();
        for p in operator_perms() {
            assert!(
                registry.contains(p),
                "operator references unregistered perm: {p}"
            );
        }
        for p in viewer_perms() {
            assert!(
                registry.contains(p),
                "viewer references unregistered perm: {p}"
            );
        }
    }

    #[test]
    fn viewer_is_a_subset_of_operator() {
        let operator: HashSet<&str> = operator_perms().into_iter().collect();
        for p in viewer_perms() {
            assert!(operator.contains(p), "viewer perm {p} not held by operator");
        }
    }

    #[test]
    fn viewer_is_strictly_read_only() {
        // No create/update/delete/renew/register/assign verbs leak into Viewer.
        for p in viewer_perms() {
            for verb in ["create", "update", "delete", "renew", "register", "assign"] {
                assert!(!p.contains(verb), "viewer must not hold a write perm: {p}");
            }
        }
    }

    #[test]
    fn every_system_role_grants_only_registered_permissions() {
        let registry = all_keys();
        for spec in SYSTEM_ROLES {
            for p in (spec.perms)() {
                assert!(
                    registry.contains(p),
                    "system role {} references unregistered perm {p}",
                    spec.id
                );
            }
        }
    }
}
