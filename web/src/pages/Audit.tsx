import { useEffect, useMemo, useState } from 'react';
import { api } from '../api/client';
import { usePageTitle } from '../components/Layout';
import { fmtDate } from '../lib/format';

interface AuditRecord {
  id: string;
  created_at: string;
  actor_user_id: string | null;
  actor_username: string | null;
  actor_token_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  before_json: string | null;
  after_json: string | null;
  ip: string | null;
  user_agent: string | null;
  request_id: string | null;
}

export function Audit() {
  usePageTitle('Audit log');
  const [rows, setRows] = useState<AuditRecord[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [action, setAction] = useState('');
  const [resourceType, setResourceType] = useState('');
  const [actorUserId, setActorUserId] = useState('');
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    const params = new URLSearchParams();
    if (action) params.set('action', action);
    if (resourceType) params.set('resource_type', resourceType);
    if (actorUserId) params.set('actor_user_id', actorUserId);
    api.get<AuditRecord[]>(`/api/audit${params.toString() ? '?' + params : ''}`)
      .then(setRows)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [action, resourceType, actorUserId]);

  // Distinct values from the current page for friendly filter dropdowns.
  const distinctActions = useMemo(
    () => Array.from(new Set((rows ?? []).map((r) => r.action))).sort(),
    [rows],
  );
  const distinctResources = useMemo(
    () => Array.from(new Set((rows ?? []).map((r) => r.resource_type))).sort(),
    [rows],
  );

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!rows) return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading…</div>;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
          Append-only — every state-changing action across the instance. Secrets are redacted at write time.
        </p>
      </header>

      <div className="flex flex-wrap gap-2">
        <select value={action} onChange={(e) => setAction(e.target.value)} className="max-w-[220px]" autoComplete="off">
          <option value="">All actions</option>
          {distinctActions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>
        <select value={resourceType} onChange={(e) => setResourceType(e.target.value)} className="max-w-[220px]" autoComplete="off">
          <option value="">All resources</option>
          {distinctResources.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
        <input
          type="search"
          name="audit-actor-filter"
          value={actorUserId}
          onChange={(e) => setActorUserId(e.target.value)}
          placeholder="Filter by actor user id…"
          className="max-w-[280px]"
          autoComplete="off"
          data-1p-ignore
          data-lpignore="true"
        />
      </div>

      <div className="overflow-hidden rounded-md border" style={{ borderColor: 'var(--color-border)' }}>
        <table className="w-full text-sm">
          <thead className="text-left text-xs font-medium uppercase tracking-wide" style={{ backgroundColor: 'var(--color-bg-subtle)', color: 'var(--color-fg-muted)' }}>
            <tr>
              <th className="px-4 py-2.5">When</th>
              <th className="px-4 py-2.5">Actor</th>
              <th className="px-4 py-2.5">Action</th>
              <th className="px-4 py-2.5">Resource</th>
              <th className="px-4 py-2.5">From</th>
              <th className="px-4 py-2.5">Details</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={6} className="px-4 py-8 text-center" style={{ color: 'var(--color-fg-muted)' }}>No audit entries match those filters.</td></tr>
            ) : rows.map((r) => (
              <tr key={r.id} className="border-t align-top" style={{ borderColor: 'var(--color-border)' }}>
                <td className="px-4 py-3 whitespace-nowrap text-xs">{fmtDate(r.created_at)}</td>
                <td className="px-4 py-3">
                  {r.actor_username ?? <span style={{ color: 'var(--color-fg-subtle)' }}>—</span>}
                  {r.actor_token_id && <div className="text-xs" style={{ color: 'var(--color-fg-muted)' }}>via token</div>}
                </td>
                <td className="px-4 py-3"><code className="font-mono text-xs rounded px-1.5 py-0.5" style={{ backgroundColor: 'var(--color-bg-subtle)' }}>{r.action}</code></td>
                <td className="px-4 py-3">
                  <div className="text-sm">{r.resource_type}</div>
                  {r.resource_id && <div className="text-xs font-mono break-all" style={{ color: 'var(--color-fg-subtle)' }}>{r.resource_id}</div>}
                </td>
                <td className="px-4 py-3 text-xs" style={{ color: 'var(--color-fg-muted)' }}>{r.ip ?? '—'}</td>
                <td className="px-4 py-3">
                  {(r.before_json || r.after_json) ? (
                    <button
                      type="button"
                      className="text-xs hover:underline"
                      style={{ color: 'var(--color-accent)' }}
                      onClick={() => setExpanded((e) => ({ ...e, [r.id]: !e[r.id] }))}
                    >
                      {expanded[r.id] ? 'Hide' : 'Show'} diff
                    </button>
                  ) : <span className="text-xs" style={{ color: 'var(--color-fg-subtle)' }}>none</span>}
                  {expanded[r.id] && (
                    <div className="mt-2 space-y-2">
                      {r.before_json && (
                        <pre className="rounded border p-2 text-xs overflow-x-auto" style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg-subtle)' }}>
{'before: ' + tryPretty(r.before_json)}
                        </pre>
                      )}
                      {r.after_json && (
                        <pre className="rounded border p-2 text-xs overflow-x-auto" style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg-subtle)' }}>
{'after:  ' + tryPretty(r.after_json)}
                        </pre>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function tryPretty(s: string): string {
  try { return JSON.stringify(JSON.parse(s), null, 2); } catch { return s; }
}
