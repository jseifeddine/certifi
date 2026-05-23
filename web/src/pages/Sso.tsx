import { useEffect, useState, type FormEvent } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { usePageTitle } from '../components/Layout';
import { useToast } from '../components/Toast';
import { useConfirm } from '../components/ConfirmDialog';
import { oidcApi, type GroupMapping, type OidcConfig, type OidcConfigUpdate } from '../api/oidc';
import { rolesApi, type Role } from '../api/roles';

/**
 * Admin page for OIDC SSO. Two sections:
 *  - Provider configuration (issuer / client / claims / JIT toggle)
 *  - Group → role mappings (claim group name → role + scope)
 *
 * Fields whose value is locked by an environment variable render as
 * read-only and show the env var name as a hint. Mirrors the pattern the
 * DNS-integration UI uses for its own locked fields.
 */
export function Sso() {
  usePageTitle('SSO');
  const toast = useToast();
  const confirm = useConfirm();
  const [cfg, setCfg] = useState<OidcConfig | null>(null);
  const [draft, setDraft] = useState<OidcConfigUpdate>({});
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  const [mappings, setMappings] = useState<GroupMapping[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [newGroup, setNewGroup] = useState('');
  const [newRole, setNewRole] = useState('');
  const [newScope, setNewScope] = useState('global');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [c, m, r] = await Promise.all([
          oidcApi.getConfig(),
          oidcApi.listMappings(),
          rolesApi.list(),
        ]);
        if (cancelled) return;
        setCfg(c);
        setDraft({}); // start clean — fields show stored values
        setMappings(m);
        setRoles(r);
      } catch (e) {
        if (!cancelled) toast.error(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => { cancelled = true; };
    // Intentionally omit `toast` from deps — we only want to refetch when
    // `reloadKey` flips. Listing toast here would re-fire the effect on
    // every render (and was previously wiping the form draft).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reloadKey]);

  if (!cfg) {
    return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading...</div>;
  }

  const isLocked = (k: string) => cfg.locked.includes(k);
  const merged: OidcConfig = { ...cfg, ...(draft as Partial<OidcConfig>) };

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await oidcApi.putConfig(draft);
      toast.success('OIDC settings updated');
      setReloadKey((k) => k + 1);
    } catch (ex) {
      toast.error(ex instanceof Error ? ex.message : String(ex));
    } finally {
      setBusy(false);
    }
  }

  async function addMapping() {
    if (!newGroup.trim() || !newRole) {
      toast.error('Group name and role are required');
      return;
    }
    try {
      await oidcApi.createMapping({ group_name: newGroup.trim(), role_id: newRole, scope: newScope.trim() || 'global' });
      setNewGroup('');
      setNewRole('');
      setNewScope('global');
      setReloadKey((k) => k + 1);
      toast.success('Mapping added');
    } catch (ex) {
      toast.error(ex instanceof Error ? ex.message : String(ex));
    }
  }

  async function removeMapping(m: GroupMapping) {
    const ok = await confirm({
      title: 'Remove group mapping?',
      body: `Drop "${m.group_name}" → ${m.role_name} (${m.scope}). Users who only had this role through OIDC will lose it on next sign-in.`,
      confirmLabel: 'Remove',
      danger: true,
    });
    if (!ok) return;
    try {
      await oidcApi.deleteMapping(m.id);
      setReloadKey((k) => k + 1);
    } catch (ex) {
      toast.error(ex instanceof Error ? ex.message : String(ex));
    }
  }

  function LockedHint({ k }: { k: string }) {
    if (!isLocked(k)) return null;
    return <span className="text-[11px] text-dim ml-2">(locked by env var)</span>;
  }

  return (
    <div className="max-w-[820px]">
      <header className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Single Sign-On (OIDC)</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
          Provider config + group → role mappings. Env-locked fields are read-only here.
        </p>
      </header>

      <form onSubmit={save} className="card mb-6" autoComplete="off">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold">Provider</h2>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={!!merged.enabled}
              disabled={isLocked('oidc_enabled')}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
            />
            Enabled
            <LockedHint k="oidc_enabled" />
          </label>
        </div>

        <Field label="Issuer URL" hint="Discovery base, e.g. https://auth.example.com/realms/main" lockedKey="oidc_issuer" locked={isLocked('oidc_issuer')}>
          <input
            type="url"
            name="oidc-issuer"
            value={merged.issuer}
            disabled={isLocked('oidc_issuer')}
            onChange={(e) => setDraft({ ...draft, issuer: e.target.value })}
            placeholder="https://auth.example.com/realms/main"
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Client ID" lockedKey="oidc_client_id" locked={isLocked('oidc_client_id')}>
          <input
            type="text"
            name="oidc-client-id"
            value={merged.client_id}
            disabled={isLocked('oidc_client_id')}
            onChange={(e) => setDraft({ ...draft, client_id: e.target.value })}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Client secret" hint="Stored encrypted. Leave as *** to keep the current value." lockedKey="oidc_client_secret" locked={isLocked('oidc_client_secret')}>
          <input
            type="password"
            name="oidc-client-secret"
            value={merged.client_secret}
            disabled={isLocked('oidc_client_secret')}
            onChange={(e) => setDraft({ ...draft, client_secret: e.target.value })}
            placeholder="(unset)"
            autoComplete="new-password"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Redirect URI" hint="Must match what the IdP has registered. Typically https://<your host>/api/oidc/callback." lockedKey="oidc_redirect_uri" locked={isLocked('oidc_redirect_uri')}>
          <input
            type="url"
            name="oidc-redirect-uri"
            value={merged.redirect_uri}
            disabled={isLocked('oidc_redirect_uri')}
            onChange={(e) => setDraft({ ...draft, redirect_uri: e.target.value })}
            placeholder="https://certifi.example.com/api/oidc/callback"
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Scopes (comma-separated)" hint="openid is implicit. Most setups want: openid,email,profile,groups" lockedKey="oidc_scopes" locked={isLocked('oidc_scopes')}>
          <input
            type="text"
            name="oidc-scopes"
            value={merged.scopes}
            disabled={isLocked('oidc_scopes')}
            onChange={(e) => setDraft({ ...draft, scopes: e.target.value })}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Group claim name" hint="Token claim holding the user's group list (default: groups)" lockedKey="oidc_group_claim" locked={isLocked('oidc_group_claim')}>
          <input
            type="text"
            name="oidc-group-claim"
            value={merged.group_claim}
            disabled={isLocked('oidc_group_claim')}
            onChange={(e) => setDraft({ ...draft, group_claim: e.target.value })}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Username claim" hint="Token claim used for the local username (default: preferred_username)" lockedKey="oidc_username_claim" locked={isLocked('oidc_username_claim')}>
          <input
            type="text"
            name="oidc-username-claim"
            value={merged.username_claim}
            disabled={isLocked('oidc_username_claim')}
            onChange={(e) => setDraft({ ...draft, username_claim: e.target.value })}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <Field label="Email claim" lockedKey="oidc_email_claim" locked={isLocked('oidc_email_claim')}>
          <input
            type="text"
            name="oidc-email-claim"
            value={merged.email_claim}
            disabled={isLocked('oidc_email_claim')}
            onChange={(e) => setDraft({ ...draft, email_claim: e.target.value })}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
        </Field>

        <label className="flex items-center gap-2 text-sm my-4">
          <input
            type="checkbox"
            checked={!!merged.create_users}
            disabled={isLocked('oidc_create_users')}
            onChange={(e) => setDraft({ ...draft, create_users: e.target.checked })}
          />
          Create users on first sign-in (JIT provisioning)
          <LockedHint k="oidc_create_users" />
        </label>

        <label className="flex items-center gap-2 text-sm my-4">
          <input
            type="checkbox"
            checked={!!merged.force_login}
            disabled={isLocked('oidc_force_login')}
            onChange={(e) => setDraft({ ...draft, force_login: e.target.checked })}
          />
          <span>
            Force SSO at /login
            <span className="block text-[11px]" style={{ color: 'var(--color-fg-muted)' }}>
              Skip the local username/password form and bounce visitors straight to the IdP.
              `/login?local=1` is a per-visit override for break-glass access.
            </span>
          </span>
          <LockedHint k="oidc_force_login" />
        </label>

        <button type="submit" className="btn btn-primary" disabled={busy}>
          {busy ? <><span className="spinner" /> Saving…</> : 'Save provider config'}
        </button>
      </form>

      <div className="card">
        <h2 className="text-base font-semibold mb-2">Group → role mappings</h2>
        <p className="text-[12px] text-muted mb-4">
          When a user signs in via OIDC, every mapping whose <code className="bg-surface2 px-1 rounded">group_name</code> appears in the user's group claim is materialised as a role assignment. Hand-administered grants are left untouched; only OIDC-sourced assignments are reconciled.
        </p>

        <table className="w-full text-sm mb-4">
          <thead>
            <tr className="text-left text-[11px] uppercase text-muted bg-surface2 border-b border-border">
              <th className="px-3 py-2">IdP group</th>
              <th className="px-3 py-2">Role</th>
              <th className="px-3 py-2">Scope</th>
              <th className="px-3 py-2 text-right"></th>
            </tr>
          </thead>
          <tbody>
            {mappings.length === 0 ? (
              <tr><td colSpan={4} className="px-3 py-6 text-center text-muted">No mappings yet</td></tr>
            ) : mappings.map((m) => (
              <tr key={m.id} className="border-b border-border last:border-b-0">
                <td className="px-3 py-2"><code className="bg-surface2 px-1.5 py-0.5 rounded">{m.group_name}</code></td>
                <td className="px-3 py-2">{m.role_name}</td>
                <td className="px-3 py-2"><code className="bg-surface2 px-1.5 py-0.5 rounded">{m.scope}</code></td>
                <td className="px-3 py-2 text-right">
                  <button className="btn btn-sm btn-danger" onClick={() => removeMapping(m)}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div className="flex gap-2 items-end">
          <div className="flex-1">
            <label className="block text-[12px] text-muted mb-1">IdP group name</label>
            <input
              type="text"
              name="oidc-mapping-group"
              value={newGroup}
              onChange={(e) => setNewGroup(e.target.value)}
              placeholder="tls-admins"
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>
          <div className="flex-1">
            <label className="block text-[12px] text-muted mb-1">Role</label>
            <select value={newRole} onChange={(e) => setNewRole(e.target.value)} autoComplete="off">
              <option value="">— pick a role —</option>
              {roles.map((r) => (
                <option key={r.id} value={r.id}>{r.name}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-[12px] text-muted mb-1">Scope</label>
            <input
              type="text"
              name="oidc-mapping-scope"
              value={newScope}
              onChange={(e) => setNewScope(e.target.value)}
              placeholder="global or zone:example.com"
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>
          <button type="button" className="btn btn-primary" onClick={addMapping}>
            <Plus className="h-4 w-4" /> Add
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
  locked,
  lockedKey,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
  locked: boolean;
  lockedKey: string;
}) {
  return (
    <div className="mb-3">
      <label className="block text-[13px] font-medium text-muted mb-1.5">
        {label}
        {locked && <span className="text-[11px] text-dim ml-2">(locked by env {lockedKey.toUpperCase().replace(/^OIDC_/, 'OIDC_')})</span>}
      </label>
      {children}
      {hint && <p className="text-[11px] text-dim mt-1">{hint}</p>}
    </div>
  );
}
