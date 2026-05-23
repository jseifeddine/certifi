import { useEffect, useMemo, useState, type ReactNode } from 'react';
import { certDownloadPath, certsApi } from '../api/certificates';
import { api, saveBlob } from '../api/client';
import { Copy, Download, File as FileIcon, KeyRound, ScrollText, Shield } from 'lucide-react';
const IconCert     = (p: React.SVGProps<SVGSVGElement>) => <ScrollText className="h-4 w-4" {...p} />;
const IconCopy     = (p: React.SVGProps<SVGSVGElement>) => <Copy       className="h-4 w-4" {...p} />;
const IconDownload = (p: React.SVGProps<SVGSVGElement>) => <Download   className="h-4 w-4" {...p} />;
const IconFile     = (p: React.SVGProps<SVGSVGElement>) => <FileIcon   className="h-4 w-4" {...p} />;
const IconKey      = (p: React.SVGProps<SVGSVGElement>) => <KeyRound   className="h-4 w-4" {...p} />;
const IconShield   = (p: React.SVGProps<SVGSVGElement>) => <Shield     className="h-4 w-4" {...p} />;
import { useToast } from './Toast';
import type { PemBundle } from '../types';

type TabKey = 'fullchain' | 'cert' | 'chain' | 'privkey' | 'pfx';

interface Tab {
  key: TabKey;
  label: string;
  hint: string;
  icon: ReactNode;
  sensitive?: boolean;
}

const TABS: Tab[] = [
  { key: 'fullchain', label: 'Fullchain', hint: 'Leaf certificate + intermediate CA chain', icon: <IconFile /> },
  { key: 'cert',      label: 'Certificate', hint: 'Leaf certificate only',                  icon: <IconCert /> },
  { key: 'chain',     label: 'CA Chain',  hint: 'Intermediate CA chain only',               icon: <IconShield /> },
  { key: 'privkey',   label: 'Private Key', hint: 'Keep this secret', icon: <IconKey />, sensitive: true },
  { key: 'pfx',       label: 'PFX', hint: 'PKCS#12 archive for Windows / IIS', icon: <IconShield /> },
];

const TAB_TO_DOWNLOAD: Record<Exclude<TabKey, 'pfx'>, 'fullchain' | 'cert' | 'chain' | 'privkey'> = {
  fullchain: 'fullchain',
  cert: 'cert',
  chain: 'chain',
  privkey: 'privkey',
};

export function PemViewer({ certId, commonName }: { certId: string; commonName: string }) {
  const [bundle, setBundle] = useState<PemBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [active, setActive] = useState<TabKey>('fullchain');
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    let cancelled = false;
    certsApi.pemBundle(certId)
      .then((b) => { if (!cancelled) setBundle(b); })
      .catch((ex) => { if (!cancelled) setError(ex instanceof Error ? ex.message : 'Failed'); });
    return () => { cancelled = true; };
  }, [certId, reloadKey]);

  const visible = useMemo(() => TABS.filter((t) => {
    if (!bundle) return false;
    if (t.key === 'fullchain') return !!bundle.fullchain_pem;
    if (t.key === 'cert')      return !!bundle.cert_pem;
    if (t.key === 'chain')     return !!bundle.chain_pem;
    if (t.key === 'privkey')   return !!bundle.privkey_pem;
    if (t.key === 'pfx')       return !!bundle.fullchain_pem && !!bundle.privkey_pem;
    return false;
  }), [bundle]);

  useEffect(() => {
    if (visible.length && !visible.some((t) => t.key === active)) {
      setActive(visible[0].key);
    }
  }, [visible, active]);

  if (error) return <div className="alert alert-error">{error}</div>;
  if (!bundle) return <div className="card flex items-center gap-2 text-muted"><span className="spinner" /> Loading certificate files…</div>;
  if (visible.length === 0) return null;

  const activeTab = visible.find((t) => t.key === active) ?? visible[0];

  return (
    <div className="card !p-0 overflow-hidden">
      <div className="flex flex-wrap items-end gap-1 border-b border-border px-3 pt-3 bg-surface2/40">
        {visible.map((t) => (
          <button
            key={t.key}
            onClick={() => setActive(t.key)}
            className={`flex items-center gap-2 px-3 py-2 text-[13px] font-medium border-b-2 -mb-px transition-colors rounded-t-md
              ${active === t.key
                ? 'text-brand border-brand bg-surface'
                : 'text-muted border-transparent hover:text-text hover:bg-surface'}`}
          >
            <span className={active === t.key ? 'text-brand' : 'text-muted'}>{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>

      <div className="p-5">
        <div className="flex items-start justify-between gap-4 mb-3 flex-wrap">
          <div>
            <div className="text-[15px] font-semibold text-text">{activeTab.label}</div>
            <div className="text-[12px] text-muted">{activeTab.hint}</div>
          </div>
        </div>

        {activeTab.key === 'pfx' ? (
          <PfxPanel
            certId={certId}
            commonName={commonName}
            password={bundle.pfx_password}
            onRotated={() => setReloadKey((k) => k + 1)}
          />
        ) : activeTab.key === 'privkey' ? (
          <PemPanel
            content={bundle.privkey_pem!}
            certId={certId}
            commonName={commonName}
            kind="privkey"
            sensitive
          />
        ) : (
          <PemPanel
            content={
              activeTab.key === 'fullchain' ? bundle.fullchain_pem! :
              activeTab.key === 'cert'      ? bundle.cert_pem!      :
                                              bundle.chain_pem!
            }
            certId={certId}
            commonName={commonName}
            kind={TAB_TO_DOWNLOAD[activeTab.key as 'fullchain' | 'cert' | 'chain']}
          />
        )}
      </div>
    </div>
  );
}

function PemPanel({
  content, certId, commonName, kind, sensitive,
}: {
  content: string;
  certId: string;
  commonName: string;
  kind: 'fullchain' | 'cert' | 'chain' | 'privkey';
  sensitive?: boolean;
}) {
  const toast = useToast();
  const [revealed, setRevealed] = useState(!sensitive);
  const [copied, setCopied] = useState(false);

  async function copy() {
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  async function download() {
    try {
      const blob = await api.downloadBlob(certDownloadPath(certId, kind));
      saveBlob(blob, `${commonName}-${kind}.pem`);
    } catch (ex) {
      toast.error('Download failed: ' + (ex instanceof Error ? ex.message : ex));
    }
  }

  return (
    <>
      {sensitive && !revealed && (
        <div className="alert alert-warning">
          The private key is sensitive — anyone with this value can impersonate{' '}
          <strong>{commonName}</strong>. Click <strong>Reveal</strong> to view.
        </div>
      )}

      <CodeBlock content={content} masked={sensitive && !revealed} />

      <div className="flex gap-2 mt-3 flex-wrap">
        {sensitive && (
          <button className="btn btn-secondary btn-sm" onClick={() => setRevealed((v) => !v)}>
            {revealed ? 'Hide' : 'Reveal'}
          </button>
        )}
        <button className="btn btn-secondary btn-sm" onClick={copy} disabled={sensitive && !revealed}>
          <IconCopy /> {copied ? 'Copied!' : 'Copy'}
        </button>
        <button className="btn btn-primary btn-sm" onClick={download}>
          <IconDownload /> Download .pem
        </button>
      </div>
    </>
  );
}

function PfxPanel({
  certId, commonName, password, onRotated,
}: {
  certId: string;
  commonName: string;
  password: string | null;
  onRotated: () => void;
}) {
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function downloadPfx() {
    setBusy(true);
    setError(null);
    try {
      const data = await certsApi.generatePfx(certId);
      const bytes = Uint8Array.from(atob(data.pfx_b64), (c) => c.charCodeAt(0));
      saveBlob(new Blob([bytes], { type: 'application/x-pkcs12' }), data.filename);
      if (!password) onRotated();
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed');
    } finally {
      setBusy(false);
    }
  }

  async function copyPw() {
    if (!password) return;
    await navigator.clipboard.writeText(password);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  return (
    <>
      {error && <div className="alert alert-error">{error}</div>}

      <div className="bg-surface2 border border-border rounded-md p-4 mb-3">
        <label className="block text-[11px] font-semibold uppercase tracking-wider text-dim mb-1.5">PFX Password</label>
        {password ? (
          <div className="flex items-center gap-2 flex-wrap">
            <code
              className={`flex-1 min-w-[200px] font-mono text-[13px] px-3 py-2 bg-bg border border-border rounded text-ok ${revealed ? '' : 'tracking-widest'}`}
              style={{ wordBreak: 'break-all' }}
            >
              {revealed ? password : '•'.repeat(Math.max(12, password.length))}
            </code>
            <button className="btn btn-secondary btn-sm" onClick={() => setRevealed((v) => !v)}>
              {revealed ? 'Hide' : 'Reveal'}
            </button>
            <button className="btn btn-secondary btn-sm" onClick={copyPw}>
              <IconCopy /> {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        ) : (
          <p className="text-[12px] text-muted">
            No PFX has been generated yet. Click <strong>Download .pfx</strong> below — a password
            will be generated, stored encrypted, and shown here on subsequent visits.
          </p>
        )}
      </div>

      <div className="text-[12px] text-muted mb-3">
        Use this password when importing <code className="font-mono text-text">{commonName}.pfx</code> into Windows, IIS,
        or any application that accepts PKCS#12 archives.
      </div>

      <button className="btn btn-primary btn-sm" onClick={downloadPfx} disabled={busy}>
        {busy ? <><span className="spinner" /> Building…</> : <><IconDownload /> Download .pfx</>}
      </button>
    </>
  );
}

function CodeBlock({ content, masked }: { content: string; masked?: boolean }) {
  return (
    <pre
      className="bg-bg border border-border rounded-md p-4 text-[12px] leading-[1.45] text-text overflow-auto max-h-[440px] font-mono select-all whitespace-pre"
      style={{ tabSize: 2 }}
    >
      {masked ? maskBody(content) : content}
    </pre>
  );
}

/// Mask the base64 body of a PEM but keep the BEGIN/END headers so the user
/// still knows what's there.
function maskBody(pem: string): string {
  return pem
    .split('\n')
    .map((line) => (line.startsWith('-----') || line.trim() === '' ? line : '•'.repeat(Math.min(line.length, 64))))
    .join('\n');
}
