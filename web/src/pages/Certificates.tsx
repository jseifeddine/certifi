import { useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Plus, RefreshCw } from 'lucide-react';
import type { ColumnDef } from '@tanstack/react-table';
import { certsApi } from '../api/certificates';
import { useCertEvents } from '../api/events';
import { StatusBadge } from '../components/StatusBadge';
import { usePageTitle } from '../components/Layout';
import { DataTable } from '../components/ui/data-table';
import { daysUntil, expiryClass, fmtDate } from '../lib/format';
import type { Certificate } from '../types';

export function Certificates() {
  usePageTitle('Certificates');
  const navigate = useNavigate();
  const [certs, setCerts] = useState<Certificate[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    certsApi
      .list()
      .then((data) => { if (!cancelled) { setCerts(data); setError(null); } })
      .catch((ex) => { if (!cancelled) setError(ex instanceof Error ? ex.message : 'Failed to load'); });
    return () => { cancelled = true; };
  }, [reloadKey]);

  // Live updates: any cert change or deletion triggers a re-fetch.
  useCertEvents({
    onChanged: () => setReloadKey((k) => k + 1),
    onDeleted: () => setReloadKey((k) => k + 1),
  });

  const columns = useMemo<ColumnDef<Certificate, unknown>[]>(
    () => [
      {
        accessorKey: 'common_name',
        header: 'Domain / SANs',
        cell: ({ row }) => {
          const c = row.original;
          return (
            <div>
              <div className="font-medium">{c.common_name}</div>
              {c.sans.length > 0 && (
                <div className="text-xs" style={{ color: 'var(--color-fg-muted)' }}>
                  {c.sans.join(', ')}
                </div>
              )}
              {c.description && (
                <div className="text-xs italic mt-0.5" style={{ color: 'var(--color-fg-subtle)' }}>
                  {c.description}
                </div>
              )}
            </div>
          );
        },
      },
      {
        accessorKey: 'status',
        header: 'Status',
        cell: ({ row }) => <StatusBadge status={row.original.status} />,
      },
      {
        accessorKey: 'expires_at',
        header: 'Expires',
        cell: ({ row }) => {
          const c = row.original;
          if (!c.expires_at) return <span style={{ color: 'var(--color-fg-subtle)' }}>—</span>;
          const d = daysUntil(c.expires_at);
          return (
            <span className={expiryClass(c.expires_at)}>
              {fmtDate(c.expires_at)}{d !== null && ` (${d}d)`}
            </span>
          );
        },
      },
      {
        accessorKey: 'auto_renew',
        header: 'Renewal',
        cell: ({ row }) =>
          row.original.auto_renew
            ? <span className="badge badge-ok">↻ auto</span>
            : <span className="badge badge-muted">manual</span>,
      },
      {
        accessorKey: 'updated_at',
        header: 'Updated',
        cell: ({ row }) => (
          <span className="text-xs" style={{ color: 'var(--color-fg-subtle)' }}>
            {fmtDate(row.original.updated_at)}
          </span>
        ),
      },
    ],
    [],
  );

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!certs) return <div className="flex items-center gap-2" style={{ color: 'var(--color-fg-muted)' }}><span className="spinner" /> Loading…</div>;

  const total = certs.length;
  const active = certs.filter((c) => c.status === 'active').length;
  const expiring = certs.filter((c) => {
    const d = daysUntil(c.expires_at);
    return d !== null && d >= 0 && d < 30;
  }).length;
  const failed = certs.filter((c) => c.status === 'failed').length;
  const pending = certs.filter((c) => c.status === 'pending' || c.status === 'issuing').length;

  return (
    <div className="space-y-6">
      <header className="flex items-end justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Certificates</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {total} certificate{total === 1 ? '' : 's'} — issued & tracked by this instance.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setReloadKey((k) => k + 1)}
            aria-label="Refresh"
            className="rounded-md border p-2 text-sm"
            style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
          >
            <RefreshCw className="h-4 w-4" />
          </button>
          <Link
            to="/certificates/new"
            className="inline-flex items-center gap-1.5 rounded-md px-4 py-2 text-sm font-medium hover:opacity-95"
            style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
          >
            <Plus className="h-4 w-4" /> New certificate
          </Link>
        </div>
      </header>

      <div className="grid gap-3" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))' }}>
        <Stat label="Total" value={total} sub="all certificates" />
        <Stat label="Active" value={active} sub="valid & issued" tone="success" />
        <Stat label="Expiring" value={expiring} sub="within 30 days" tone="warn" />
        <Stat label="Failed" value={failed} sub="need attention" tone="error" />
        {pending > 0 && <Stat label="In progress" value={pending} sub="being issued" tone="accent" />}
      </div>

      <DataTable
        columns={columns}
        data={certs}
        searchPlaceholder="Search domains, SANs, description…"
        initialSort={[{ id: 'updated_at', desc: true }]}
        noDataMessage="No certificates yet — click ‘New certificate’ to issue your first."
        onRowClick={(c) => navigate(`/certificates/${c.id}`)}
      />
    </div>
  );
}

function Stat({
  label,
  value,
  sub,
  tone = 'default',
}: {
  label: string;
  value: number;
  sub: string;
  tone?: 'default' | 'success' | 'warn' | 'error' | 'accent';
}) {
  const colorFor: Record<typeof tone, string> = {
    default: 'var(--color-fg)',
    success: 'var(--color-success)',
    warn:    'var(--color-warn)',
    error:   'var(--color-error)',
    accent:  'var(--color-accent)',
  };
  return (
    <div
      className="rounded-md border p-4"
      style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
    >
      <div className="text-xs uppercase tracking-wide" style={{ color: 'var(--color-fg-muted)' }}>
        {label}
      </div>
      <div className="mt-1 text-3xl font-semibold" style={{ color: colorFor[tone] }}>
        {value}
      </div>
      <div className="mt-0.5 text-xs" style={{ color: 'var(--color-fg-muted)' }}>{sub}</div>
    </div>
  );
}
