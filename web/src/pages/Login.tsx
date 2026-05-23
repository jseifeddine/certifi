import { useEffect, useState, type FormEvent } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../auth';
import { oidcApi, type OidcStatus } from '../api/oidc';
import { ThemeToggle } from '../components/ui/theme-toggle';
import { Wordmark } from '../components/ui/wordmark';

/**
 * Sign-in page. Single-column card on a muted page background. Branches into
 * three states:
 *
 *   - default        — OIDC button (if enabled), divider, username/password form
 *   - challenge      — TOTP code prompt after a successful password step
 *   - busy/error     — pre-empts the relevant button label
 */
export function Login() {
  const { login, loginTotp, user } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [oidc, setOidc] = useState<OidcStatus | null>(null);
  const [oidcBusy, setOidcBusy] = useState(false);
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [otp, setOtp] = useState('');

  const rawFrom = (location.state as { from?: string } | null)?.from;
  const redirectTo = rawFrom && !rawFrom.startsWith('/login') ? rawFrom : '/certificates';

  // `/login?local=1` lets admins reach the local form when SSO is mandatory
  // but broken. Keep the check in a memoised value so the auto-redirect
  // effect doesn't re-fire if the URL is identical.
  const queryParams = new URLSearchParams(location.search);
  const forceLocal = queryParams.has('local');
  // The server-side OIDC callback redirects here with ?error=<message> when
  // an IdP refusal / state mismatch interrupts the round trip. Show it once
  // and let the user retry.
  const callbackError = queryParams.get('error');

  useEffect(() => { document.title = 'Sign in — Certifi'; }, []);
  useEffect(() => { if (user) navigate(redirectTo, { replace: true }); }, [user, navigate, redirectTo]);
  useEffect(() => { if (callbackError) setError(callbackError); }, [callbackError]);

  useEffect(() => {
    let cancelled = false;
    oidcApi.status()
      .then((s) => { if (!cancelled) setOidc(s); })
      .catch(() => { /* OIDC absent or misconfigured — fine */ });
    return () => { cancelled = true; };
  }, []);

  // When OIDC is configured AND `force_login` is on AND the visitor hasn't
  // overridden via ?local=1 (and an earlier callback didn't already fail),
  // kick off the IdP redirect as soon as we know.
  useEffect(() => {
    if (!oidc?.enabled || !oidc.force_login) return;
    if (forceLocal || callbackError) return;
    if (challengeId || oidcBusy) return;
    void ssoSignIn();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [oidc, forceLocal, callbackError]);

  async function ssoSignIn() {
    setError(null);
    setOidcBusy(true);
    try {
      const { authorize_url } = await oidcApi.start(redirectTo);
      window.location.href = authorize_url;
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'OIDC sign-in failed');
      setOidcBusy(false);
    }
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const challenge = await login(username, password);
      if (challenge) {
        setChallengeId(challenge.challenge_id);
        setBusy(false);
      } else {
        navigate(redirectTo, { replace: true });
      }
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'Login failed');
      setBusy(false);
    }
  }

  async function submitOtp(e: FormEvent) {
    e.preventDefault();
    if (!challengeId) return;
    setError(null);
    setBusy(true);
    try {
      await loginTotp(challengeId, otp.trim());
      navigate(redirectTo, { replace: true });
    } catch (ex) {
      setError(ex instanceof Error ? ex.message : 'TOTP code rejected');
      setBusy(false);
    }
  }

  return (
    <div
      className="flex min-h-dvh items-center justify-center p-4 relative"
      style={{ backgroundColor: 'var(--color-bg-subtle)' }}
    >
      <div className="absolute right-4 top-4"><ThemeToggle /></div>

      <div
        className="w-full max-w-sm rounded-lg border p-8 shadow-sm"
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
      >
        <div className="flex items-center justify-center mb-6">
          <Wordmark />
        </div>

        <header className="mb-6">
          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {challengeId
              ? 'Two-factor authentication is required for your account.'
              : 'Use your Certifi credentials to continue.'}
          </p>
        </header>

        {error && (
          <div
            className="mb-4 rounded-md border p-3 text-sm"
            style={{
              borderColor: 'color-mix(in oklch, var(--color-error) 40%, transparent)',
              backgroundColor: 'color-mix(in oklch, var(--color-error) 8%, transparent)',
              color: 'var(--color-error)',
            }}
          >
            {error}
          </div>
        )}

        {oidc?.enabled && oidc.force_login && !forceLocal && !challengeId && !callbackError ? (
          <div className="flex flex-col items-center gap-3 py-6">
            <span className="spinner" />
            <p className="text-sm" style={{ color: 'var(--color-fg-muted)' }}>
              Redirecting to {oidc.provider_name}…
            </p>
            <a
              href="?local=1"
              className="text-xs hover:underline"
              style={{ color: 'var(--color-accent)' }}
            >
              Sign in with a local account instead
            </a>
          </div>
        ) : challengeId ? (
          <form onSubmit={submitOtp}>
            <div className="mb-4">
              <label className="mb-1.5 block text-sm font-medium">One-time code</label>
              <input
                type="text" inputMode="numeric" autoComplete="one-time-code" autoFocus
                placeholder="123456" maxLength={8}
                value={otp} onChange={(e) => setOtp(e.target.value.replace(/\D/g, ''))}
              />
            </div>
            <PrimaryButton type="submit" busy={busy} disabled={otp.length < 6}>
              {busy ? 'Verifying…' : 'Verify'}
            </PrimaryButton>
            <SecondaryButton
              type="button"
              className="mt-2"
              onClick={() => { setChallengeId(null); setOtp(''); setPassword(''); setError(null); }}
            >
              Cancel
            </SecondaryButton>
          </form>
        ) : (
          <>
            {oidc?.enabled && (
              <>
                <button
                  type="button"
                  onClick={ssoSignIn}
                  disabled={oidcBusy}
                  className="flex w-full items-center justify-center rounded-md border px-4 py-2 text-sm font-medium transition-colors"
                  style={{
                    borderColor: 'var(--color-border)',
                    backgroundColor: 'var(--color-bg-subtle)',
                  }}
                >
                  {oidcBusy ? 'Redirecting…' : `Continue with ${oidc.provider_name}`}
                </button>
                <div className="my-4 flex items-center gap-3 text-xs" style={{ color: 'var(--color-fg-subtle)' }}>
                  <span className="h-px flex-1" style={{ backgroundColor: 'var(--color-border)' }} />
                  <span>or</span>
                  <span className="h-px flex-1" style={{ backgroundColor: 'var(--color-border)' }} />
                </div>
              </>
            )}

            <form onSubmit={submit}>
              <div className="mb-4">
                <label className="mb-1.5 block text-sm font-medium">Username</label>
                <input
                  type="text" autoFocus required autoComplete="username"
                  value={username} onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="mb-4">
                <label className="mb-1.5 block text-sm font-medium">Password</label>
                <input
                  type="password" required autoComplete="current-password"
                  value={password} onChange={(e) => setPassword(e.target.value)}
                />
              </div>
              <PrimaryButton type="submit" busy={busy}>
                {busy ? 'Signing in…' : 'Sign in'}
              </PrimaryButton>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

function PrimaryButton({
  busy,
  disabled,
  children,
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & { busy?: boolean }) {
  return (
    <button
      {...rest}
      disabled={busy || disabled}
      className="flex w-full items-center justify-center rounded-md px-4 py-2 text-sm font-medium hover:opacity-95 disabled:opacity-50"
      style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
    >
      {busy ? <span className="spinner mr-2" /> : null}
      {children}
    </button>
  );
}

function SecondaryButton({ children, className = '', ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      {...rest}
      className={`flex w-full items-center justify-center rounded-md border px-4 py-2 text-sm font-medium ${className}`}
      style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
    >
      {children}
    </button>
  );
}
