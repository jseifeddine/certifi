import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { certsApi } from '../api/certificates';
import { useCertEvents } from '../api/events';
import { useConfirm } from '../components/ConfirmDialog';
import { RefreshCw } from 'lucide-react';
const IconRefresh = (p: React.SVGProps<SVGSVGElement>) => <RefreshCw className="h-4 w-4" {...p} />;
import { usePageTitle } from '../components/Layout';
import { PemViewer } from '../components/PemViewer';
import { StatusBadge } from '../components/StatusBadge';
import { useToast } from '../components/Toast';
import { daysUntil, expiryClass, fmtDate } from '../lib/format';
import type { Certificate } from '../types';

export function CertificateDetail() {
  usePageTitle('Certificate');
  const { id = '' } = useParams();
  const navigate = useNavigate();
  const toast = useToast();
  const confirm = useConfirm();
  const [cert, setCert] = useState<Certificate | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [renewing, setRenewing] = useState(false);
  const [togglingAr, setTogglingAr] = useState(false);

  useEffect(() => {
    let cancelled = false;
    certsApi
      .get(id)
      .then((data) => { if (!cancelled) { setCert(data); setError(null); } })
      .catch((ex) => { if (!cancelled) setError(ex instanceof Error ? ex.message : 'Failed to load'); });
    return () => { cancelled = true; };
  }, [id]);

  // Live updates: any change to this cert refreshes the view; deletion
  // navigates away. Replaces the previous "poll every 3s while pending" timer.
  useCertEvents({
    onChanged: (changedId) => {
      if (changedId === id) {
        certsApi.get(id).then(setCert).catch(() => {});
      }
    },
    onDeleted: (deletedId) => {
      if (deletedId === id) navigate('/certificates');
    },
  });

  async function renew() {
    if (!cert) return;
    setRenewing(true);
    try {
      await certsApi.renew(cert.id);
      const fresh = await certsApi.get(cert.id);
      setCert(fresh);
    } catch (ex) {
      toast.error('Renew failed: ' + (ex instanceof Error ? ex.message : ex));
    } finally {
      setRenewing(false);
    }
  }

  async function toggleAutoRenew() {
    if (!cert) return;
    setTogglingAr(true);
    try {
      await certsApi.setAutoRenew(cert.id, !cert.auto_renew);
      const fresh = await certsApi.get(cert.id);
      setCert(fresh);
    } catch (ex) {
      toast.error('Failed to update auto-renew: ' + (ex instanceof Error ? ex.message : ex));
    } finally {
      setTogglingAr(false);
    }
  }

  async function remove() {
    if (!cert) return;
    const ok = await confirm({
      title: 'Delete certificate',
      body: `Delete the certificate for ${cert.common_name}? This cannot be undone.`,
      confirmLabel: 'Delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await certsApi.delete(cert.id);
      navigate('/certificates');
    } catch (ex) {
      toast.error('Delete failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!cert) return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading...</div>;

  const d = daysUntil(cert.expires_at);
  const isPending = cert.status === 'pending' || cert.status === 'issuing';

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3 flex-wrap">
          <button className="btn btn-secondary btn-sm" onClick={() => navigate('/certificates')}>← Back</button>
          <h1 className="text-lg font-bold">{cert.common_name}</h1>
          <StatusBadge status={cert.status} />
        </div>
        <div className="flex gap-2 items-center flex-wrap">
          <button className="btn btn-secondary btn-sm" onClick={renew} disabled={isPending || renewing}>
            <IconRefresh /> {renewing ? 'Renewing…' : 'Renew'}
          </button>
          <button
            className={`btn btn-sm ${cert.auto_renew ? 'btn-success' : 'btn-secondary'}`}
            onClick={toggleAutoRenew}
            disabled={togglingAr}
            title={cert.auto_renew ? 'Auto-renew ON — click to disable' : 'Auto-renew OFF — click to enable'}
          >
            <IconRefresh /> Auto-renew: {cert.auto_renew ? 'ON' : 'OFF'}
          </button>
          <button className="btn btn-danger btn-sm" onClick={remove}>Delete</button>
        </div>
      </div>

      {isPending && (
        <div className="alert alert-info">
          <div className="flex items-center gap-3">
            <span className="spinner" />
            <span>Issuing certificate via ACME dns-01 challenge — this may take 30–90 seconds...</span>
          </div>
        </div>
      )}

      {cert.error && (
        <div className="alert alert-error"><strong>Error:</strong> {cert.error}</div>
      )}

      <div className="card">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Detail label="Common Name" value={cert.common_name} />
          <Detail label="Status" valueNode={<StatusBadge status={cert.status} />} />
          <Detail
            label="SANs"
            valueNode={cert.sans.length
              ? <div className="space-y-0.5">{cert.sans.map((s) => <div key={s}>{s}</div>)}</div>
              : <>—</>}
          />
          <Detail label="Key Algorithm" value={cert.key_algo ?? '—'} />
          <Detail
            label="Expires"
            valueNode={
              <span className={expiryClass(cert.expires_at)}>
                {cert.expires_at ? <>{fmtDate(cert.expires_at)}{d !== null && ` (${d} days)`}</> : '—'}
              </span>
            }
          />
          <Detail label="Created" value={fmtDate(cert.created_at)} />
          <Detail label="Updated" value={fmtDate(cert.updated_at)} />
          <div className="md:col-span-2">
            <DescriptionEditor cert={cert} onUpdated={setCert} />
          </div>
        </div>
      </div>

      {cert.has_files && (
        <PemViewer certId={cert.id} commonName={cert.common_name} />
      )}
    </div>
  );
}

function Detail({ label, value, valueNode }: { label: string; value?: string; valueNode?: React.ReactNode }) {
  return (
    <div>
      <label className="text-[11px] font-semibold uppercase tracking-wider text-dim block mb-1">{label}</label>
      <div className="text-[13px] text-text break-all">{valueNode ?? value}</div>
    </div>
  );
}

function DescriptionEditor({
  cert,
  onUpdated,
}: {
  cert: Certificate;
  onUpdated: (next: Certificate) => void;
}) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState(cert.description ?? '');
  const [busy, setBusy] = useState(false);

  async function save() {
    const trimmed = value.trim();
    if ((trimmed || null) === (cert.description ?? null)) {
      setEditing(false);
      return;
    }
    setBusy(true);
    try {
      await certsApi.setDescription(cert.id, trimmed || null);
      const fresh = await certsApi.get(cert.id);
      onUpdated(fresh);
      setEditing(false);
    } catch (ex) {
      toast.error('Failed: ' + (ex instanceof Error ? ex.message : ex));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <label className="text-[11px] font-semibold uppercase tracking-wider text-dim block mb-1">Description</label>
      {editing ? (
        <div className="flex gap-2">
          <input
            type="text"
            name="cert-description"
            value={value}
            autoFocus
            maxLength={500}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') save();
              if (e.key === 'Escape') { setValue(cert.description ?? ''); setEditing(false); }
            }}
            autoComplete="off"
            data-1p-ignore
            data-lpignore="true"
          />
          <button className="btn btn-primary btn-sm" onClick={save} disabled={busy}>Save</button>
          <button className="btn btn-secondary btn-sm" onClick={() => { setValue(cert.description ?? ''); setEditing(false); }}>Cancel</button>
        </div>
      ) : (
        <div className="flex items-center gap-2 text-[13px] text-text break-all">
          <span className={cert.description ? '' : 'text-dim italic'}>{cert.description || '— no description'}</span>
          <button className="btn btn-secondary btn-sm" onClick={() => setEditing(true)}>Edit</button>
        </div>
      )}
    </div>
  );
}
