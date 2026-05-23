/**
 * Top-right avatar dropdown. Routing uses react-router and the sign-out hook
 * is bound to our existing `useAuth().logout`. No external avatar service — a
 * monogram derived from the username.
 */

import { useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, Lock, LogOut, ShieldCheck } from 'lucide-react';
import { useAuth } from '../../auth';

export function UserMenu() {
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false);
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (!user) return null;

  const display = user.username;
  const initial = (user.username[0] ?? '?').toUpperCase();

  return (
    <div ref={containerRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 rounded-md border px-2 py-1 text-sm transition-colors"
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
      >
        <span
          aria-hidden
          className="flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium"
          style={{ backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }}
        >
          {initial}
        </span>
        <span className="hidden max-w-[16ch] truncate sm:inline">{display}</span>
        {user.is_admin && (
          <span
            className="hidden rounded-full px-1.5 py-0.5 text-[10px] font-medium sm:inline"
            style={{
              backgroundColor: 'color-mix(in oklch, var(--color-accent) 12%, transparent)',
              color: 'var(--color-accent)',
            }}
          >
            admin
          </span>
        )}
      </button>

      {open ? (
        <div
          role="menu"
          className="absolute right-0 z-50 mt-2 w-56 origin-top-right rounded-md border shadow-lg"
          style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
        >
          <div className="border-b px-3 py-2 text-xs" style={{ borderColor: 'var(--color-border)' }}>
            <div className="font-medium">{display}</div>
            <div className="truncate" style={{ color: 'var(--color-fg-muted)' }}>
              {user.is_admin ? 'SuperAdmin' : 'Signed in'}
            </div>
          </div>
          <div className="py-1">
            <MenuLink to="/security" onSelect={() => setOpen(false)} icon={<ShieldCheck className="h-4 w-4" aria-hidden />}>
              Security (TOTP)
            </MenuLink>
            <MenuLink to="/settings/password" onSelect={() => setOpen(false)} icon={<Lock className="h-4 w-4" aria-hidden />}>
              Change password
            </MenuLink>
            <MenuLink to="/tokens" onSelect={() => setOpen(false)} icon={<KeyRound className="h-4 w-4" aria-hidden />}>
              My API tokens
            </MenuLink>
            <button
              type="button"
              role="menuitem"
              onClick={() => { setOpen(false); void logout(); }}
              className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm transition-colors"
              style={{ color: 'var(--color-fg)' }}
            >
              <LogOut className="h-4 w-4" aria-hidden />
              Sign out
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function MenuLink({
  to,
  icon,
  children,
  onSelect,
}: {
  to: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  onSelect: () => void;
}) {
  return (
    <Link
      to={to}
      role="menuitem"
      onClick={onSelect}
      className="flex items-center gap-2 px-3 py-2 text-sm transition-colors"
      style={{ color: 'var(--color-fg)' }}
    >
      {icon}
      {children}
    </Link>
  );
}
