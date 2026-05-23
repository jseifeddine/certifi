import { useEffect, useState, type FormEvent, type KeyboardEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { certsApi } from '../api/certificates';
import { domainsApi } from '../api/domains';
import { ScrollText } from 'lucide-react';
const IconCert = (p: React.SVGProps<SVGSVGElement>) => <ScrollText className="h-4 w-4" {...p} />;
import { usePageTitle } from '../components/Layout';

interface ZoneMatch {
  prefix: string;
  matches: string[];
}

function bestMatch(val: string, domains: string[]): ZoneMatch | null {
  if (!val.includes('.')) return null;
  const parts = val.split('.');
  for (let i = 1; i < parts.length; i++) {
    const fragment = parts.slice(i).join('.').toLowerCase();
    const matches = domains.filter((d) => d.toLowerCase().startsWith(fragment));
    if (matches.length > 0) {
      return { prefix: parts.slice(0, i).join('.') + '.', matches };
    }
  }
  return { prefix: val.slice(0, val.lastIndexOf('.') + 1), matches: domains };
}

function validateDomain(val: string, domains: string[]): { ok: boolean; zone?: string } | null {
  const v = val.trim();
  if (!v) return null;
  const hit = domains.find((z) => v === z || v.endsWith('.' + z));
  return hit ? { ok: true, zone: hit } : { ok: false };
}

function DomainInput({
  value, onChange, onSelect, onEnter, domains, placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  onSelect?: (v: string) => void;
  onEnter?: () => void;
  domains: string[];
  placeholder?: string;
}) {
  const [show, setShow] = useState(false);
  const [activeIdx, setActiveIdx] = useState(-1);
  const m = bestMatch(value, domains);
  const matches = m ? m.matches.slice(0, 12) : [];

  function commit(zone: string) {
    const newVal = (m ? m.prefix : '') + zone;
    onChange(newVal);
    setShow(false);
    setActiveIdx(-1);
    onSelect?.(newVal);
  }

  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      if (show && activeIdx >= 0 && matches[activeIdx]) {
        e.preventDefault();
        e.stopPropagation();
        commit(matches[activeIdx]);
        return;
      }
      if (onEnter) {
        e.preventDefault();
        onEnter();
      }
      return;
    }
    if (!show || matches.length === 0) return;
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx((i) => Math.min(i + 1, matches.length - 1)); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx((i) => Math.max(i - 1, 0)); }
    else if (e.key === 'Escape') { setShow(false); setActiveIdx(-1); }
  }

  return (
    <div className="relative">
      <input
        type="text"
        autoComplete="off"
        placeholder={placeholder}
        value={value}
        onChange={(e) => { onChange(e.target.value); setShow(true); setActiveIdx(-1); }}
        onFocus={() => setShow(true)}
        onBlur={() => setTimeout(() => setShow(false), 150)}
        onKeyDown={onKey}
      />
      {show && matches.length > 0 && (
        <div className="absolute top-full left-0 right-0 bg-surface3 border border-border2 rounded-md max-h-[200px] overflow-y-auto z-10 mt-0.5">
          {matches.map((mt, i) => (
            <div
              key={mt}
              className={`px-3 py-2 text-[13px] cursor-pointer ${i === activeIdx ? 'bg-brand text-white' : ''}`}
              onMouseEnter={() => setActiveIdx(i)}
              onMouseDown={(e) => { e.preventDefault(); commit(mt); }}
            >
              {mt}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function CertificateNew() {
  usePageTitle('New Certificate');
  const navigate = useNavigate();
  const [cn, setCn] = useState('');
  const [sans, setSans] = useState<string[]>([]);
  const [sanInput, setSanInput] = useState('');
  const [autoRenew, setAutoRenew] = useState(true);
  const [keyAlgo, setKeyAlgo] = useState('');
  const [description, setDescription] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    domainsApi.list().then(setDomains).catch(() => setDomains([]));
  }, []);

  const cnValid = validateDomain(cn, domains);
  const sanValid = validateDomain(sanInput, domains);

  function addSan(val: string) {
    const v = val.trim();
    if (!v) return;
    if (v === cn || sans.includes(v)) return;
    setSans([...sans, v]);
    setSanInput('');
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!cn.trim()) { setError('Common name is required'); return; }
    setBusy(true);
    setError(null);
    try {
      const result = await certsApi.create({
        common_name: cn.trim(),
        sans,
        auto_renew: autoRenew,
        key_algo: keyAlgo || null,
        description: description.trim() || null,
      });
      navigate(`/certificates/${result.id}`);
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Failed to issue');
      setBusy(false);
    }
  }

  return (
    <div>
      <div className="flex items-center gap-3 mb-4">
        <button className="btn btn-secondary btn-sm" onClick={() => navigate('/certificates')}>← Back</button>
        <h1 className="text-lg font-bold">New Certificate</h1>
      </div>

      <div className="table-wrap p-6 max-w-[600px]">
        {error && <div className="alert alert-error">{error}</div>}
        <form onSubmit={submit}>
          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Common Name (Primary Domain)</label>
            <DomainInput
              value={cn} onChange={setCn} domains={domains}
              placeholder="example.com"
            />
            <div className="text-[11px] mt-1 min-h-[16px]">
              {cnValid && (cnValid.ok
                ? <span className="text-ok">✓ Matches zone <strong>{cnValid.zone}</strong></span>
                : <span className="text-warn">⚠ Not in any managed DNS zone</span>)}
            </div>
          </div>

          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Subject Alternative Names (SANs)</label>
            <div className="flex flex-wrap gap-1.5 mb-2">
              {sans.map((s, i) => (
                <span key={s} className="flex items-center gap-1 bg-surface3 border border-border rounded px-2 py-0.5 text-[12px]">
                  {s}
                  <span
                    className="cursor-pointer text-danger text-base leading-none"
                    onClick={() => setSans(sans.filter((_, j) => j !== i))}
                  >×</span>
                </span>
              ))}
            </div>
            <DomainInput
              value={sanInput}
              onChange={setSanInput}
              onSelect={(v) => addSan(v)}
              onEnter={() => addSan(sanInput)}
              domains={domains}
              placeholder="Add domain and press Enter..."
            />
            <div className="text-[11px] mt-1 min-h-[16px]">
              {sanValid && (sanValid.ok
                ? <span className="text-ok">✓ Matches zone <strong>{sanValid.zone}</strong></span>
                : <span className="text-warn">⚠ Not in any managed DNS zone</span>)}
            </div>
            <div className="text-[11px] text-dim mt-0.5">Press Enter to add each SAN</div>
          </div>

          <div className="mb-4 flex items-center gap-2">
            <input
              id="auto-renew" type="checkbox" className="w-auto m-0 cursor-pointer"
              checked={autoRenew} onChange={(e) => setAutoRenew(e.target.checked)}
            />
            <label htmlFor="auto-renew" className="m-0 cursor-pointer font-normal text-text text-[13px]">
              Auto-renew when expiring within 30 days
            </label>
          </div>

          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Description (optional)</label>
            <input
              type="text"
              name="cert-description"
              placeholder="e.g. app.example.com — production web tier"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={500}
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
            <div className="text-[11px] text-dim mt-1">Free-text label shown in the certificate list and detail page</div>
          </div>

          <div className="mb-4">
            <label className="block text-[13px] font-medium text-muted mb-1.5">Key Algorithm</label>
            <select value={keyAlgo} onChange={(e) => setKeyAlgo(e.target.value)} autoComplete="off">
              <option value="">Use global default</option>
              <option value="ec-p384">ECDSA P-384 (recommended)</option>
              <option value="ec-p256">ECDSA P-256</option>
              <option value="rsa-2048">RSA 2048-bit (legacy)</option>
              <option value="rsa-4096">RSA 4096-bit (legacy)</option>
            </select>
            <div className="text-[11px] text-dim mt-1">Override the global key algorithm for this certificate only</div>
          </div>

          <div className="flex gap-2 mt-3">
            <button type="submit" className="btn btn-primary" disabled={busy}>
              {busy ? <><span className="spinner" /> Issuing...</> : <><IconCert /> Issue Certificate</>}
            </button>
            <button type="button" className="btn btn-secondary" onClick={() => navigate('/certificates')}>
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
