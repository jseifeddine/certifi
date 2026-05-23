/**
 * App shell — grid layout matching PowerDNS-AuthUI:
 *
 *   ┌─ sidebar ────┬─ header ────────────────┐
 *   │   wordmark   │       theme  user-menu  │
 *   │   ─────────  ├─────────────────────────┤
 *   │   nav links  │                         │
 *   │              │     <Outlet />          │
 *   │   admin grp  │                         │
 *   └──────────────┴─────────────────────────┘
 *
 * Sidebar items are filtered by the caller's permissions; an empty admin
 * section just doesn't render.
 *
 * `usePageTitle()` is a thin tab-title setter — the visible page header
 * lives inside each page now (matching the reference app's pattern where
 * pages own their own `<header>` block).
 */

import { NavLink, Outlet } from 'react-router-dom';
import {
  Activity,
  BookOpen,
  KeyRound,
  Plug,
  ScrollText,
  ShieldCheck,
  ShieldHalf,
  ShieldQuestion,
  Users as UsersIcon,
} from 'lucide-react';
import { useAuth } from '../auth';
import { perms } from '../lib/perms';
import { docsUrl, releaseUrl, useAppVersion } from '../lib/appMeta';
import { ThemeToggle } from './ui/theme-toggle';
import { UserMenu } from './ui/user-menu';
import { Wordmark } from './ui/wordmark';

export function Layout() {
  const { user, has } = useAuth();
  if (!user) return null;

  const canReadUsers    = has(perms.USER_LIST);
  const canReadRoles    = has(perms.ROLE_LIST);
  const canReadAudit    = has(perms.AUDIT_READ);
  const canReadSettings = has(perms.SETTINGS_READ);
  const hasAdminSection =
    canReadUsers || canReadRoles || canReadAudit || canReadSettings;

  return (
    // Mark the whole authenticated shell as "do not autofill" for every
    // password manager we know about. Heuristic-based PMs (1Password,
    // Bitwarden, LastPass, Dashlane) walk up the DOM looking for these
    // attributes and skip the subtree when present. Without this, fields
    // with labels like "Email claim" trigger email autofill no matter how
    // we name the input. The login page lives OUTSIDE this layout, so
    // sign-in + save-after-sign-in still work normally.
    <div
      className="grid min-h-dvh"
      data-1p-ignore
      data-lpignore="true"
      data-bwignore
      data-form-type="other"
      style={{
        gridTemplateColumns: '16rem 1fr',
        gridTemplateRows: '3.5rem 1fr',
      }}
    >
      <aside
        className="row-span-2 flex flex-col border-r"
        style={{
          borderColor: 'var(--color-border)',
          backgroundColor: 'var(--color-bg-subtle)',
        }}
      >
        <div className="flex h-14 items-center border-b px-4" style={{ borderColor: 'var(--color-border)' }}>
          <NavLink to="/certificates" aria-label="Certifi home" className="block w-full">
            <Wordmark />
          </NavLink>
        </div>
        <nav className="space-y-1 p-3 text-sm">
          {has(perms.CERTIFICATE_LIST) && (
            <SideLink to="/certificates" icon={<ScrollText className="h-4 w-4" />} label="Certificates" />
          )}
          <SideLink to="/tokens" icon={<KeyRound className="h-4 w-4" />} label="API Tokens" />
          <SideLink to="/docs"   icon={<BookOpen className="h-4 w-4" />} label="Docs" />

          {hasAdminSection ? (
            <NavSection label="Admin settings">
              {canReadSettings && <SideLink to="/settings/acme"         icon={<ShieldCheck    className="h-4 w-4" />} label="ACME account" />}
              {canReadSettings && <SideLink to="/settings/integrations" icon={<Plug           className="h-4 w-4" />} label="DNS integrations" />}
              {canReadUsers    && <SideLink to="/settings/users"        icon={<UsersIcon      className="h-4 w-4" />} label="Users" />}
              {canReadRoles    && <SideLink to="/settings/roles"        icon={<ShieldQuestion className="h-4 w-4" />} label="Roles" />}
              {canReadSettings && <SideLink to="/settings/sso"          icon={<ShieldHalf     className="h-4 w-4" />} label="SSO" />}
              {canReadAudit    && <SideLink to="/settings/audit"        icon={<Activity       className="h-4 w-4" />} label="Audit log" />}
            </NavSection>
          ) : null}
        </nav>

        <AppVersionFooter />
      </aside>

      <header
        className="flex h-14 items-center justify-end gap-3 border-b px-4"
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
      >
        <ThemeToggle />
        <UserMenu />
      </header>

      <section className="overflow-y-auto p-8">
        <div className="mx-auto max-w-[1200px] w-full">
          <Outlet />
        </div>
      </section>
    </div>
  );
}

function SideLink({
  to,
  icon,
  label,
}: {
  to: string;
  icon: React.ReactNode;
  label: string;
}) {
  return (
    <NavLink
      to={to}
      end
      className={({ isActive }) =>
        `flex items-center gap-2.5 rounded-md px-3 py-2 transition-colors ${isActive ? 'font-medium' : ''}`
      }
      style={({ isActive }) =>
        isActive
          ? { backgroundColor: 'var(--color-bg-muted)', color: 'var(--color-fg)' }
          : { color: 'var(--color-fg-muted)' }
      }
    >
      {icon}
      {label}
    </NavLink>
  );
}

/**
 * Sidebar footer: the running version (linked to its GitHub release) and a
 * Docs link pinned to the matching version's `docs/`. The version comes from
 * `GET /api/health`, so it always reflects the binary actually serving the UI.
 * Both links are derived in `lib/appMeta`, so a release bump is a one-file
 * change on the server (the Cargo workspace version).
 */
function AppVersionFooter() {
  const version = useAppVersion();
  return (
    <div
      className="mt-auto flex items-center justify-between border-t px-4 py-3 text-xs"
      style={{ borderColor: 'var(--color-border)', color: 'var(--color-fg-subtle)' }}
    >
      {version ? (
        <a
          href={releaseUrl(version)}
          target="_blank"
          rel="noreferrer"
          title={`Certifi v${version} — view this release on GitHub`}
          className="tabular-nums transition-colors hover:underline"
        >
          v{version}
        </a>
      ) : (
        // Reserve the line height until /api/health resolves.
        <span aria-hidden className="tabular-nums opacity-0">
          v0.0.0
        </span>
      )}
      {version && (
        <a
          href={docsUrl(version)}
          target="_blank"
          rel="noreferrer"
          title="Documentation for this version on GitHub"
          className="transition-colors hover:underline"
        >
          Docs ↗
        </a>
      )}
    </div>
  );
}

function NavSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="pt-4">
      <div className="px-3 pb-1 text-xs font-medium uppercase tracking-wide" style={{ color: 'var(--color-fg-subtle)' }}>
        {label}
      </div>
      <div className="space-y-1">{children}</div>
    </div>
  );
}

/**
 * Set the browser tab title. Pages own their visible header block now;
 * the legacy in-header span this used to update is gone, so the function
 * is just `document.title = …` plus a noop-on-SSR guard.
 */
export function usePageTitle(title: string) {
  if (typeof document !== 'undefined') {
    document.title = `${title} — Certifi`;
  }
}
