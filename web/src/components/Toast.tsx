/**
 * Compat shim — re-exports the new `useDialog` API as the legacy
 * `useToast` shape so pre-rewrite call sites still compile:
 *
 *   const toast = useToast();
 *   toast.error("…");
 *   toast.success("…");
 *
 * `ToastProvider` is a no-op pass-through; the real provider is
 * `DialogProvider` in `components/ui/dialog.tsx`, mounted once from
 * `main.tsx`.
 */

import { useMemo, type ReactNode } from 'react';
import { useDialog } from './ui/dialog';

export function useToast() {
  // The new DialogApi already exposes error/success/info as thin wrappers
  // over toast(), and a `push` method existed on the legacy API too.
  //
  // **Memoise the returned object.** Several callers list the toast as a
  // dep on useEffects ("if the toast changes, refetch"). Without this
  // memo, every render would emit a new object identity and bounce those
  // effects on every keystroke — which on the SSO page was wiping the
  // draft + unmounting the input on every character, killing focus.
  const dlg = useDialog();
  return useMemo(
    () => ({
      push: (message: string, variant: 'error' | 'success' | 'info' = 'info') =>
        dlg.toast({ description: message, kind: variant }),
      error: dlg.error,
      success: dlg.success,
      info: dlg.info,
    }),
    [dlg],
  );
}

/** No-op — `DialogProvider` replaces it. Kept so legacy main.tsx imports
 *  resolve until they're updated. */
export function ToastProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
