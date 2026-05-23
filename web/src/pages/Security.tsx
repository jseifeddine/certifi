import { useEffect, useState } from 'react';
import { authApi, type EnrollResponse, type TotpStatus } from '../api/auth';
import { usePageTitle } from '../components/Layout';
import { useConfirm } from '../components/ConfirmDialog';
import { useToast } from '../components/Toast';

/**
 * Per-user security settings. Phase 6 surfaces just the TOTP factor;
 * future additions (WebAuthn, backup codes) drop in alongside.
 */
export function Security() {
  usePageTitle('Security');
  const toast = useToast();
  const confirm = useConfirm();
  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [enrollment, setEnrollment] = useState<EnrollResponse | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);

  useEffect(() => {
    authApi.totpStatus().then(setStatus).catch((e) => toast.error(e instanceof Error ? e.message : String(e)));
  }, [reloadKey, toast]);

  async function startEnroll() {
    setBusy(true);
    try {
      const r = await authApi.totpEnroll();
      setEnrollment(r);
      setCode('');
      setReloadKey((k) => k + 1);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnroll() {
    setBusy(true);
    try {
      await authApi.totpConfirm(code.trim());
      toast.success('TOTP enabled — required at your next sign-in');
      setEnrollment(null);
      setCode('');
      setReloadKey((k) => k + 1);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function disable() {
    const ok = await confirm({
      title: 'Disable TOTP?',
      body: 'Your account will sign in with username + password only until you re-enroll. Continue?',
      confirmLabel: 'Disable',
      danger: true,
    });
    if (!ok) return;
    try {
      await authApi.totpDisable();
      toast.success('TOTP disabled');
      setEnrollment(null);
      setReloadKey((k) => k + 1);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  }

  if (!status) {
    return <div className="flex items-center gap-2 text-muted"><span className="spinner" /> Loading…</div>;
  }

  return (
    <div className="max-w-[640px] space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Security</h1>
        <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
          Per-account security settings.
        </p>
      </header>

      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-semibold">Authenticator app (TOTP)</h2>
            <p className="text-[12px] text-muted">Time-based one-time code (RFC 6238). Works with 1Password, Authy, Google Authenticator, etc.</p>
          </div>
          <span className={`badge ${status.verified ? 'badge-ok' : status.enrolled ? 'badge-warn' : 'badge-muted'}`}>
            {status.verified ? 'Enabled' : status.enrolled ? 'Pending' : 'Off'}
          </span>
        </div>

        {!status.verified && !enrollment && (
          <button className="btn btn-primary" onClick={startEnroll} disabled={busy}>
            {status.enrolled ? 'Re-enroll' : 'Enable TOTP'}
          </button>
        )}

        {enrollment && (
          <div className="space-y-3">
            <p className="text-[13px] text-muted">
              Scan the QR code with your authenticator app, then confirm a code below.
            </p>
            <div className="bg-white p-3 rounded-md inline-block">
              <img
                alt="TOTP QR"
                src={`data:image/png;base64,${enrollment.qr_png_b64}`}
                width={200}
                height={200}
              />
            </div>
            <div>
              <label className="block text-[12px] text-muted mb-1">Or paste the secret manually</label>
              <code className="block bg-surface2 p-2 rounded text-[12px] break-all">{enrollment.secret_b32}</code>
            </div>
            <div>
              <label className="block text-[13px] font-medium text-muted mb-1.5">Confirmation code</label>
              <input
                type="text" inputMode="numeric" placeholder="123456" maxLength={8} autoFocus
                value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                className="max-w-[200px]"
                name="totp-enroll-code"
                autoComplete="one-time-code"
              />
            </div>
            <div className="flex gap-2">
              <button className="btn btn-primary" onClick={confirmEnroll} disabled={busy || code.length < 6}>
                {busy ? <><span className="spinner" /> Verifying…</> : 'Confirm & enable'}
              </button>
              <button className="btn btn-secondary" onClick={() => { setEnrollment(null); setCode(''); }}>
                Cancel
              </button>
            </div>
          </div>
        )}

        {status.verified && !enrollment && (
          <div className="mt-2 flex gap-2">
            <button className="btn btn-secondary" onClick={startEnroll}>Re-enroll</button>
            <button className="btn btn-danger" onClick={disable}>Disable</button>
          </div>
        )}
      </div>
    </div>
  );
}
