import { useEffect, useMemo, useState } from 'react';
import { Copy, KeyRound, Plus, Trash2 } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';
import { tokensApi } from '../api/tokens';
import { useAuth } from '../auth';
import { useConfirm } from '../components/ConfirmDialog';
import { usePageTitle } from '../components/Layout';
import { Modal } from '../components/Modal';
import { useToast } from '../components/Toast';
import { DataTable } from '../components/ui/data-table';
import { fmtDate } from '../lib/format';
import type { CreatedToken, Token } from '../types';

export function Tokens() {
  usePageTitle('API Tokens');
  const toast = useToast();
  const confirm = useConfirm();
  const [tokens, setTokens] = useState<Token[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [reload, setReload] = useState(0);

  useEffect(() => {
    tokensApi.list()
      .then(setTokens)
      .catch((ex) => setError(ex instanceof Error ? ex.message : 'Failed to load'));
  }, [reload]);

  async function revoke(id: string, name: string) {
    const ok = await confirm({
      title: 'Revoke API token',
      body: `Revoke "${name}"? Any caller using it will stop working immediately.`,
      confirmLabel: 'Revoke',
      danger: true,
    });
    if (!ok) return;
    try {
      await tokensApi.delete(id);
      setReload((r) => r + 1);
    } catch (ex) {
      toast.error('Failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  const columns = useMemo<ColumnDef<Token, unknown>[]>(() => [
    { accessorKey: 'name', header: 'Name', cell: ({ row }) => <span className="font-medium">{row.original.name}</span> },
    { accessorKey: 'created_at',   header: 'Created',   cell: ({ row }) => fmtDate(row.original.created_at) },
    { accessorKey: 'last_used_at', header: 'Last used', cell: ({ row }) => row.original.last_used_at
      ? fmtDate(row.original.last_used_at)
      : <span style={{ color: 'var(--color-fg-subtle)' }}>Never</span> },
    { accessorKey: 'expires_at', header: 'Expires', cell: ({ row }) => row.original.expires_at
      ? fmtDate(row.original.expires_at)
      : <span style={{ color: 'var(--color-fg-subtle)' }}>Never</span> },
    {
      accessorKey: 'permissions',
      header: 'Scope',
      cell: ({ row }) => {
        const p = row.original.permissions;
        if (p === null) return <span className="badge badge-muted">all of mine</span>;
        if (p.length === 0) return <span className="badge badge-warn">none</span>;
        return <span className="text-xs" title={p.join('\n')}>{p.length} {p.length === 1 ? 'perm' : 'perms'}</span>;
      },
    },
    {
      id: 'actions',
      header: '',
      enableSorting: false,
      cell: ({ row }) => (
        <div className="text-right">
          <button
            type="button"
            onClick={(e) => { e.stopPropagation(); revoke(row.original.id, row.original.name); }}
            aria-label="Revoke"
            className="rounded-md border p-1.5"
            style={{ borderColor: 'color-mix(in oklch, var(--color-error) 40%, transparent)', color: 'var(--color-error)' }}
          >
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ], []);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!tokens) return <div className="flex items-center gap-2" style={{ color: 'var(--color-fg-muted)' }}><span className="spinner" /> Loading…</div>;

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">API tokens</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            Authenticate non-browser callers with <code className="font-mono">Authorization: Bearer dapi_…</code>.
          </p>
        </div>
        <button
          type="button"
          onClick={() => setModalOpen(true)}
          className="inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium hover:opacity-95"
          style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
        >
          <Plus className="h-4 w-4" /> New token
        </button>
      </header>

      {tokens.length === 0 ? (
        <div
          className="rounded-md border py-16 text-center"
          style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
        >
          <KeyRound className="mx-auto mb-4 h-12 w-12 opacity-30" />
          <h3 className="text-base font-semibold mb-1">No API tokens</h3>
          <p className="text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            Create a token to access the API programmatically.
          </p>
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={tokens}
          searchPlaceholder="Search tokens…"
          initialSort={[{ id: 'created_at', desc: true }]}
        />
      )}

      {modalOpen && (
        <CreateTokenModal
          onClose={() => setModalOpen(false)}
          onCreated={() => setReload((r) => r + 1)}
        />
      )}
    </div>
  );
}

function CreateTokenModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const { user } = useAuth();
  const issuerPerms = (user?.permissions ?? []).slice().sort();
  const [name, setName] = useState('');
  const [expires, setExpires] = useState('');
  // Mode: 'inherit' (token has issuer's full set; same as omitting permissions)
  //       'restrict' (token has only the boxes ticked below)
  const [mode, setMode] = useState<'inherit' | 'restrict'>('inherit');
  const [picked, setPicked] = useState<Record<string, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [created, setCreated] = useState<CreatedToken | null>(null);
  const [copied, setCopied] = useState(false);

  async function submit() {
    if (!name.trim()) { setError('Name required'); return; }
    const permissions = mode === 'restrict'
      ? issuerPerms.filter((p) => picked[p])
      : undefined;
    try {
      const data = await tokensApi.create({
        name: name.trim(),
        expires_at: expires ? new Date(expires).toISOString() : undefined,
        permissions,
      });
      setCreated(data);
      onCreated();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    }
  }

  function copyTok() {
    if (!created) return;
    navigator.clipboard.writeText(created.token);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Modal
      title="Create API Token"
      onClose={onClose}
      footer={
        created ? (
          <button className="btn btn-primary" onClick={onClose}>Done</button>
        ) : (
          <>
            <button className="btn btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary" onClick={submit}><Plus className="h-4 w-4" /> Create token</button>
          </>
        )
      }
    >
      {created ? (
        <>
          <div className="alert alert-success">Token created! Copy it now — it won't be shown again.</div>
          <label className="block text-[13px] font-medium text-muted mb-1.5">Your API Token</label>
          <div className="bg-surface2 border border-border rounded-md p-3 font-mono text-[12px] break-all text-ok mb-3">
            {created.token}
          </div>
          <button className="btn btn-secondary btn-sm" onClick={copyTok}>
            <Copy className="h-4 w-4" /> {copied ? 'Copied!' : 'Copy token'}
          </button>
        </>
      ) : (
        <>
          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Token Name</label>
            <input
              type="text" name="token-name" autoFocus placeholder="e.g. deploy-server-01"
              value={name} onChange={(e) => setName(e.target.value)}
              autoComplete="off" data-1p-ignore data-lpignore="true"
            />
          </div>
          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Expires (optional)</label>
            <input
              type="datetime-local"
              name="token-expires"
              value={expires} onChange={(e) => setExpires(e.target.value)}
              autoComplete="off"
            />
            <div className="text-[11px] text-dim mt-1">Leave blank for no expiry</div>
          </div>

          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Permission scope</label>
            <div className="flex gap-3 text-sm mb-2">
              <label className="flex items-center gap-1.5">
                <input
                  type="radio"
                  name="permmode"
                  checked={mode === 'inherit'}
                  onChange={() => setMode('inherit')}
                />
                Inherit my current perms
              </label>
              <label className="flex items-center gap-1.5">
                <input
                  type="radio"
                  name="permmode"
                  checked={mode === 'restrict'}
                  onChange={() => setMode('restrict')}
                />
                Restrict to selected
              </label>
            </div>
            {mode === 'restrict' && (
              <div className="bg-surface2 border border-border rounded-md p-3 max-h-[220px] overflow-y-auto">
                {issuerPerms.length === 0 ? (
                  <p className="text-[12px] text-muted">You hold no permissions to grant.</p>
                ) : (
                  <ul className="space-y-1 text-[12px]">
                    {issuerPerms.map((p) => (
                      <li key={p}>
                        <label className="flex items-center gap-2">
                          <input
                            type="checkbox"
                            checked={!!picked[p]}
                            onChange={(e) => setPicked((prev) => ({ ...prev, [p]: e.target.checked }))}
                          />
                          <code className="font-mono">{p}</code>
                        </label>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            <p className="text-[11px] text-dim mt-1">
              Restricted tokens carry a ceiling — revoking a role from your own account still propagates to the token instantly.
            </p>
          </div>

          {error && <div className="alert alert-error">{error}</div>}
        </>
      )}
    </Modal>
  );
}
