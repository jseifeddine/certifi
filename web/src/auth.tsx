import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { authApi, isTotpChallenge, type LoginOutcome, type TotpChallenge } from './api/auth';
import { clearToken, setOnUnauthorized, setToken } from './api/client';
import { hasPerm, type PermissionKey } from './lib/perms';
import type { UserInfo } from './types';

interface AuthContextValue {
  user: UserInfo | null;
  loading: boolean;
  /** True iff the logged-in user holds the given permission. Returns false
   *  while loading or when nobody is logged in. */
  has: (perm: PermissionKey) => boolean;
  /** Submit username + password. Returns `null` on a direct session, or a
   *  `TotpChallenge` when the user has TOTP enrolled — the caller must
   *  then call `loginTotp(challenge_id, code)` to complete sign-in. */
  login: (username: string, password: string) => Promise<TotpChallenge | null>;
  /** Complete a TOTP challenge handed back from `login`. */
  loginTotp: (challenge_id: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    setOnUnauthorized(() => {
      setUser(null);
      navigate('/login');
    });

    // Always ask /api/auth/me on boot: even when sessionStorage is empty,
    // the `session=` cookie set by the server-side OIDC callback (or a
    // prior tab's local login) is enough to authenticate. A 401 here just
    // means logged-out — fall through and let RequireAuth route them to
    // /login.
    authApi
      .me()
      .then(setUser)
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, [navigate]);

  const login = async (username: string, password: string): Promise<TotpChallenge | null> => {
    const outcome: LoginOutcome = await authApi.login(username, password);
    if (isTotpChallenge(outcome)) {
      // Don't set token / user — caller renders the OTP prompt and follows
      // up with loginTotp() to finish sign-in.
      return outcome;
    }
    setToken(outcome.token);
    setUser(outcome.user);
    return null;
  };

  const loginTotp = async (challenge_id: string, code: string) => {
    const resp = await authApi.loginTotp(challenge_id, code);
    setToken(resp.token);
    setUser(resp.user);
  };

  const logout = async () => {
    // When the session was minted via OIDC, the backend hands back the
    // IdP's RP-initiated-logout URL — navigate there so the user lands
    // on the provider's signed-out screen (with "Log out of <idp>" etc.)
    // instead of being silently re-authenticated by force_login.
    let idpLogoutUrl: string | undefined;
    try {
      const resp = await authApi.logout();
      idpLogoutUrl = resp.logout_url;
    } catch { /* ignore — clear local state regardless */ }
    clearToken();
    setUser(null);
    if (idpLogoutUrl) {
      window.location.replace(idpLogoutUrl);
      return;
    }
    navigate('/login');
  };

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      loading,
      has: (perm) => hasPerm(user?.permissions, perm),
      login,
      loginTotp,
      logout,
    }),
    // login/logout/etc. are stable closures over setState — no deps needed.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [user, loading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!loading && !user) {
      // Capture pathname + search + hash so deep links (e.g. /docs/api#section)
      // survive the bounce through /login.
      const from = location.pathname + location.search + location.hash;
      navigate('/login', { replace: true, state: { from } });
    }
  }, [user, loading, navigate, location.pathname, location.search, location.hash]);

  if (loading) return <div className="flex items-center justify-center h-full text-muted"><span className="spinner mr-2" /> Loading...</div>;
  if (!user) return null;
  return <>{children}</>;
}

export function RequireAdmin({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  const navigate = useNavigate();
  useEffect(() => {
    if (!loading && user && !user.is_admin) navigate('/certificates', { replace: true });
  }, [user, loading, navigate]);
  if (!user?.is_admin) return null;
  return <>{children}</>;
}

/**
 * Route gate that requires a specific permission. Bounces the user back to
 * /certificates if they're missing it. Use for routes whose entire page is
 * useless without the permission (e.g. user admin); for fine-grained button
 * toggles inside a page, use `useAuth().has(...)` directly instead.
 */
export function RequirePermission({
  perm,
  children,
}: {
  perm: PermissionKey;
  children: ReactNode;
}) {
  const { user, loading, has } = useAuth();
  const navigate = useNavigate();
  useEffect(() => {
    if (!loading && user && !has(perm)) navigate('/certificates', { replace: true });
  }, [user, loading, has, perm, navigate]);
  if (!user || !has(perm)) return null;
  return <>{children}</>;
}
