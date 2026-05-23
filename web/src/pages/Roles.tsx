import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Plus, Trash2 } from 'lucide-react';
import { useAuth } from '../auth';
import { rolesApi, type Permission, type Role } from '../api/roles';
import { useConfirm } from '../components/ConfirmDialog';
import { usePageTitle } from '../components/Layout';
import { Modal } from '../components/Modal';
import { useToast } from '../components/Toast';

/**
 * Manage roles + browse the permission registry.
 *
 * System roles (SuperAdmin / Operator / Viewer) are visible but
 * read-only. Custom roles can be created or deleted by anyone holding
 * `role.create` / `role.delete`. The permission checkboxes on the create
 * form are filtered to keys the caller currently holds — there's no path
 * for an Operator to mint a custom role that grants `user.delete`.
 */
export function Roles() {
  usePageTitle('Roles');
  const toast = useToast();
  const confirm = useConfirm();
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [perms, setPerms] = useState<Permission[] | null>(null);
  const [reload, setReload] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    Promise.all([rolesApi.list(), rolesApi.listPermissions()])
      .then(([r, p]) => { setRoles(r); setPerms(p); })
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)));
  }, [reload, toast]);

  async function remove(role: Role) {
    const ok = await confirm({
      title: 'Delete role',
      body: `Delete "${role.name}"? Any assignment of this role is also dropped.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await rolesApi.delete(role.id);
      setReload((r) => r + 1);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  if (!roles || !perms) {
    return <div className="flex items-center gap-2" style={{ color: 'var(--color-fg-muted)' }}><span className="spinner" /> Loading…</div>;
  }

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Roles</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {roles.length} role{roles.length === 1 ? '' : 's'} — system + custom. Click the count to expand a role's permissions.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium hover:opacity-95"
          style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
        >
          <Plus className="h-4 w-4" /> New role
        </button>
      </header>

      <div className="overflow-hidden rounded-md border" style={{ borderColor: 'var(--color-border)' }}>
        <table className="w-full text-sm">
          <thead className="text-left text-xs font-medium uppercase tracking-wide" style={{ backgroundColor: 'var(--color-bg-subtle)', color: 'var(--color-fg-muted)' }}>
            <tr>
              <th className="px-4 py-2.5">Name</th>
              <th className="px-4 py-2.5">Description</th>
              <th className="px-4 py-2.5">Permissions</th>
              <th className="px-4 py-2.5 w-[1%]" />
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => (
              <tr key={r.id} className="border-t align-top" style={{ borderColor: 'var(--color-border)' }}>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{r.name}</span>
                    {r.is_system && <span className="badge badge-muted">system</span>}
                  </div>
                </td>
                <td className="px-4 py-3" style={{ color: 'var(--color-fg-muted)' }}>{r.description ?? '—'}</td>
                <td className="px-4 py-3">
                  <button
                    type="button"
                    className="text-xs hover:underline"
                    style={{ color: 'var(--color-accent)' }}
                    onClick={() => setExpanded((e) => ({ ...e, [r.id]: !e[r.id] }))}
                  >
                    {r.permissions.length} keys {expanded[r.id] ? '▴' : '▾'}
                  </button>
                  {expanded[r.id] && (
                    <ul className="mt-2 grid grid-cols-2 gap-x-3 gap-y-0.5 text-xs font-mono">
                      {r.permissions.map((p) => <li key={p}>{p}</li>)}
                    </ul>
                  )}
                </td>
                <td className="px-4 py-3 text-right">
                  {!r.is_system && (
                    <button
                      type="button"
                      onClick={() => remove(r)}
                      aria-label="Delete role"
                      className="inline-flex h-8 w-8 items-center justify-center rounded-md border"
                      style={{
                        borderColor: 'color-mix(in oklch, var(--color-error) 40%, transparent)',
                        color: 'var(--color-error)',
                        backgroundColor: 'var(--color-bg)',
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <section>
        <h2 className="text-base font-semibold">Permission registry</h2>
        <p className="mt-1 text-xs" style={{ color: 'var(--color-fg-muted)' }}>
          Every gate the server checks. Custom roles can only bind keys the role's creator currently holds.
        </p>
        <div
          className="mt-3 overflow-hidden rounded-md border"
          style={{ borderColor: 'var(--color-border)' }}
        >
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide" style={{ backgroundColor: 'var(--color-bg-subtle)', color: 'var(--color-fg-muted)' }}>
              <tr>
                <th className="px-4 py-2">Key</th>
                <th className="px-4 py-2">Description</th>
              </tr>
            </thead>
            <tbody>
              {perms.map((p) => (
                <tr key={p.key} className="border-t" style={{ borderColor: 'var(--color-border)' }}>
                  <td className="px-4 py-2 font-mono">{p.key}</td>
                  <td className="px-4 py-2" style={{ color: 'var(--color-fg-muted)' }}>{p.description ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {createOpen && (
        <CreateRoleModal
          perms={perms}
          onClose={() => setCreateOpen(false)}
          onCreated={() => { setCreateOpen(false); setReload((k) => k + 1); }}
        />
      )}
    </div>
  );
}

function CreateRoleModal({
  perms,
  onClose,
  onCreated,
}: {
  perms: Permission[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const { user } = useAuth();
  const grantable = useMemo(
    () => perms.filter((p) => user?.permissions.includes(p.key)),
    [perms, user],
  );
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    const permissions = grantable.filter((p) => picked[p.key]).map((p) => p.key);
    if (!name.trim()) { setError('Name required'); return; }
    if (permissions.length === 0) { setError('Pick at least one permission'); return; }
    setBusy(true);
    setError(null);
    try {
      await rolesApi.create({
        name: name.trim(),
        description: description.trim() || undefined,
        permissions,
      });
      onCreated();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="New role"
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={busy}>
            {busy ? <><span className="spinner" /> Creating…</> : <>Create</>}
          </button>
        </>
      }
    >
      <form onSubmit={submit} autoComplete="off">
        <div className="mb-4">
          <label className="block text-[13px] font-medium text-muted mb-1.5">Name</label>
          <input type="text" name="role-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="DeploymentBot" autoComplete="off" data-1p-ignore data-lpignore="true" />
        </div>
        <div className="mb-4">
          <label className="block text-[13px] font-medium text-muted mb-1.5">Description</label>
          <input type="text" name="role-description" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="e.g. CI tokens that only need cert downloads" autoComplete="off" data-1p-ignore data-lpignore="true" />
        </div>
        <div className="mb-2">
          <label className="block text-[13px] font-medium text-muted mb-1.5">Permissions</label>
          {grantable.length === 0 ? (
            <p className="text-[12px] text-muted">You hold no permissions to grant.</p>
          ) : (
            <div className="bg-surface2 border border-border rounded-md p-3 max-h-[280px] overflow-y-auto">
              <ul className="space-y-1 text-[12px]">
                {grantable.map((p) => (
                  <li key={p.key}>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={!!picked[p.key]}
                        onChange={(e) => setPicked((prev) => ({ ...prev, [p.key]: e.target.checked }))}
                      />
                      <code className="font-mono">{p.key}</code>
                      {p.description && <span className="text-muted">— {p.description}</span>}
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
        {error && <div className="alert alert-error mt-3">{error}</div>}
      </form>
    </Modal>
  );
}
