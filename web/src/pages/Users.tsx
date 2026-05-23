import { useEffect, useMemo, useState } from 'react';
import { KeyRound, Plus, Settings as SettingsIcon, ShieldCheck, Trash2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';
import { useAuth } from '../auth';
import { usersApi } from '../api/users';
import { rolesApi, type Role } from '../api/roles';
import { useConfirm } from '../components/ConfirmDialog';
import { usePageTitle } from '../components/Layout';
import { Modal } from '../components/Modal';
import { useToast } from '../components/Toast';
import { DataTable } from '../components/ui/data-table';
import { fmtDate } from '../lib/format';
import type { RoleAssignmentView, User } from '../types';

export function Users() {
  usePageTitle('Users');
  const { user: currentUser } = useAuth();
  const toast = useToast();
  const confirm = useConfirm();
  const [users, setUsers] = useState<User[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reload, setReload] = useState(0);
  const [createOpen, setCreateOpen] = useState(false);
  const [editUser, setEditUser] = useState<User | null>(null);
  const [pwUser, setPwUser] = useState<User | null>(null);
  const [rolesUser, setRolesUser] = useState<User | null>(null);

  useEffect(() => {
    usersApi.list()
      .then(setUsers)
      .catch((ex) => setError(ex instanceof Error ? ex.message : 'Failed to load'));
  }, [reload]);

  async function remove(id: string, username: string) {
    const ok = await confirm({
      title: 'Delete user',
      body: `Delete user "${username}"? Their API tokens will be revoked as well.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await usersApi.delete(id);
      setReload((r) => r + 1);
    } catch (ex) {
      toast.error('Failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  const columns = useMemo<ColumnDef<User, unknown>[]>(() => [
    { accessorKey: 'username', header: 'Username', cell: ({ row }) => <span className="font-medium">{row.original.username}</span> },
    { accessorKey: 'email', header: 'Email', cell: ({ row }) =>
      row.original.email ?? <span style={{ color: 'var(--color-fg-subtle)' }}>—</span> },
    { accessorKey: 'is_admin', header: 'Role', cell: ({ row }) =>
      row.original.is_admin
        ? <span className="badge badge-admin">SuperAdmin</span>
        : <span className="badge badge-muted">user</span> },
    { accessorKey: 'created_at', header: 'Created', cell: ({ row }) => fmtDate(row.original.created_at) },
    {
      id: 'actions',
      header: '',
      enableSorting: false,
      cell: ({ row }) => {
        const u = row.original;
        return (
          <div className="flex justify-end gap-1">
            <IconBtn title="Edit email / admin" onClick={() => setEditUser(u)}><SettingsIcon className="h-4 w-4" /></IconBtn>
            <IconBtn title="Manage roles" onClick={() => setRolesUser(u)}><ShieldCheck className="h-4 w-4" /></IconBtn>
            <IconBtn title="Change password" onClick={() => setPwUser(u)}><KeyRound className="h-4 w-4" /></IconBtn>
            {u.id !== currentUser?.id && (
              <IconBtn title="Delete" tone="danger" onClick={() => remove(u.id, u.username)}><Trash2 className="h-4 w-4" /></IconBtn>
            )}
          </div>
        );
      },
    },
  ], [currentUser?.id]);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!users) return <div className="flex items-center gap-2" style={{ color: 'var(--color-fg-muted)' }}><span className="spinner" /> Loading…</div>;

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {users.length} account{users.length === 1 ? '' : 's'}.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setCreateOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium hover:opacity-95"
          style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
        >
          <Plus className="h-4 w-4" /> New user
        </button>
      </header>

      <DataTable
        columns={columns}
        data={users}
        searchPlaceholder="Search by username or email…"
        initialSort={[{ id: 'created_at', desc: true }]}
      />

      {createOpen && (
        <CreateUserModal
          onClose={() => setCreateOpen(false)}
          onCreated={() => { setCreateOpen(false); setReload((r) => r + 1); }}
        />
      )}
      {editUser && (
        <EditUserModal
          user={editUser}
          onClose={() => setEditUser(null)}
          onSaved={() => { setEditUser(null); setReload((r) => r + 1); }}
        />
      )}
      {pwUser && (
        <ChangePasswordModal
          user={pwUser}
          onClose={() => setPwUser(null)}
        />
      )}
      {rolesUser && (
        <ManageRolesModal
          user={rolesUser}
          onClose={() => setRolesUser(null)}
          onChanged={() => setReload((r) => r + 1)}
        />
      )}
    </div>
  );
}

function ManageRolesModal({
  user,
  onClose,
  onChanged,
}: {
  user: User;
  onClose: () => void;
  onChanged: () => void;
}) {
  const toast = useToast();
  const confirm = useConfirm();
  const [assignments, setAssignments] = useState<RoleAssignmentView[] | null>(null);
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [newRole, setNewRole] = useState('');
  const [newScope, setNewScope] = useState('global');
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    Promise.all([rolesApi.listAssignments(user.id), rolesApi.list()])
      .then(([a, r]) => { setAssignments(a); setRoles(r); })
      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)));
  }, [reloadKey, user.id, toast]);

  // Sort assignments: global scope first, then alphabetic by scope.
  const sortedAssignments = useMemo(() => {
    if (!assignments) return null;
    return [...assignments].sort((a, b) => {
      if (a.scope === 'global' && b.scope !== 'global') return -1;
      if (a.scope !== 'global' && b.scope === 'global') return 1;
      return a.scope.localeCompare(b.scope);
    });
  }, [assignments]);

  async function add() {
    if (!newRole) { toast.error('Pick a role'); return; }
    setBusy(true);
    try {
      await rolesApi.assign(user.id, { role_id: newRole, scope: newScope.trim() || 'global' });
      setNewRole('');
      setNewScope('global');
      setReloadKey((k) => k + 1);
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(a: RoleAssignmentView) {
    const ok = await confirm({
      title: 'Revoke role',
      body: `Revoke "${a.role_name}" (${a.scope}) from ${user.username}? Takes effect on this user's next request.`,
      confirmLabel: 'Revoke',
      danger: true,
    });
    if (!ok) return;
    try {
      await rolesApi.revoke(user.id, a.id);
      setReloadKey((k) => k + 1);
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Modal
      title={`Roles: ${user.username}`}
      onClose={onClose}
      footer={<button className="btn btn-primary" onClick={onClose}>Done</button>}
    >
      {!sortedAssignments || !roles ? (
        <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading…</div>
      ) : (
        <>
          {sortedAssignments.length === 0 ? (
            <p className="text-muted text-[13px] mb-3">No roles assigned yet.</p>
          ) : (
            <table className="w-full text-sm mb-4">
              <thead>
                <tr className="text-left text-[11px] uppercase text-muted bg-surface2 border-b border-border">
                  <th className="px-3 py-2">Role</th>
                  <th className="px-3 py-2">Scope</th>
                  <th className="px-3 py-2"></th>
                </tr>
              </thead>
              <tbody>
                {sortedAssignments.map((a) => (
                  <tr key={a.id} className="border-b border-border last:border-b-0">
                    <td className="px-3 py-2">{a.role_name}</td>
                    <td className="px-3 py-2"><code className="bg-surface2 px-1.5 py-0.5 rounded text-[12px]">{a.scope}</code></td>
                    <td className="px-3 py-2 text-right">
                      <button className="btn btn-sm btn-danger" onClick={() => revoke(a)}><Trash2 className="h-4 w-4" /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          <div className="border-t border-border pt-4">
            <p className="text-[12px] text-muted mb-2">Add a role</p>
            <div className="flex gap-2 items-end">
              <div className="flex-1">
                <label className="block text-[12px] text-muted mb-1">Role</label>
                <select value={newRole} onChange={(e) => setNewRole(e.target.value)} autoComplete="off">
                  <option value="">— pick a role —</option>
                  {roles.map((r) => (
                    <option key={r.id} value={r.id}>{r.name}{r.is_system ? ' (system)' : ''}</option>
                  ))}
                </select>
              </div>
              <div className="flex-1">
                <label className="block text-[12px] text-muted mb-1">Scope</label>
                <input
                  type="text"
                  name="role-scope"
                  value={newScope}
                  onChange={(e) => setNewScope(e.target.value)}
                  placeholder="global or zone:example.com"
                  autoComplete="off"
                  data-1p-ignore
                  data-lpignore="true"
                />
              </div>
              <button className="btn btn-primary" onClick={add} disabled={busy}><Plus className="h-4 w-4" /> Add</button>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    try {
      await usersApi.create({
        username, password,
        email: email || undefined,
        is_admin: isAdmin,
      });
      onCreated();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    }
  }

  return (
    <Modal
      title="Create User"
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit}><Plus className="h-4 w-4" /> Create</button>
        </>
      }
    >
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">Username</label>
        <input type="text" name="new-username" autoFocus value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" />
      </div>
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">Password</label>
        <input type="password" name="new-password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
        <div className="text-[11px] text-dim mt-1">Min 8 characters</div>
      </div>
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">
          Email <span className="text-muted font-normal">(for renewal notifications)</span>
        </label>
        <input type="email" name="contact-email" placeholder="user@example.com" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" />
      </div>
      <div className="mb-4">
        <label className="flex items-center gap-2">
          <input type="checkbox" className="w-auto" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          Admin privileges
        </label>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
    </Modal>
  );
}

function EditUserModal({ user, onClose, onSaved }: { user: User; onClose: () => void; onSaved: () => void }) {
  const [email, setEmail] = useState(user.email ?? '');
  const [isAdmin, setIsAdmin] = useState(user.is_admin);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    try {
      await usersApi.update(user.id, { email: email || null, is_admin: isAdmin });
      onSaved();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    }
  }

  return (
    <Modal
      title={`Edit User: ${user.username}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit}>Save</button>
        </>
      }
    >
      <div className="mb-4">
        <label className="block text-[13px] font-medium text-muted mb-1.5">
          Email <span className="text-muted font-normal">(for renewal notifications)</span>
        </label>
        <input type="email" name="contact-email" placeholder="user@example.com" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="off" data-1p-ignore data-lpignore="true" />
      </div>
      <div className="mb-4">
        <label className="flex items-center gap-2">
          <input type="checkbox" className="w-auto" checked={isAdmin} onChange={(e) => setIsAdmin(e.target.checked)} />
          Admin privileges
        </label>
      </div>
      {error && <div className="alert alert-error">{error}</div>}
    </Modal>
  );
}

function ChangePasswordModal({ user, onClose }: { user: User; onClose: () => void }) {
  const [pw, setPw] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function submit() {
    try {
      await usersApi.changePassword(user.id, pw);
      setDone(true);
      setTimeout(onClose, 1000);
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    }
  }

  return (
    <Modal
      title={`Change Password: ${user.username}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={submit} disabled={done}>Change Password</button>
        </>
      }
    >
      {done ? (
        <div className="alert alert-success">Password updated.</div>
      ) : (
        <>
          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">New Password</label>
            <input type="password" name="new-password" autoFocus value={pw} onChange={(e) => setPw(e.target.value)} autoComplete="new-password" />
          </div>
          {error && <div className="alert alert-error">{error}</div>}
        </>
      )}
    </Modal>
  );
}


function IconBtn({
  children,
  title,
  onClick,
  tone = "default",
}: {
  children: React.ReactNode;
  title: string;
  onClick: () => void;
  tone?: "default" | "danger";
}) {
  const danger = tone === "danger";
  return (
    <button
      type="button"
      title={title}
      aria-label={title}
      onClick={(e) => { e.stopPropagation(); onClick(); }}
      className="inline-flex h-8 w-8 items-center justify-center rounded-md border"
      style={{
        borderColor: danger
          ? "color-mix(in oklch, var(--color-error) 40%, transparent)"
          : "var(--color-border)",
        color: danger ? "var(--color-error)" : "var(--color-fg)",
        backgroundColor: "var(--color-bg)",
      }}
    >
      {children}
    </button>
  );
}
