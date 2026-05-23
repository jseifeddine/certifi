/**
 * Compat shim — `useConfirm()` keeps the legacy `{ title, body, danger }`
 * options shape but resolves through the new `useDialog().confirm`. New
 * code should use `useDialog()` directly.
 */

import type { ReactNode } from 'react';
import { useDialog } from './ui/dialog';

interface ConfirmOpts {
  title?: string;
  body: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  /** If true, render the confirm button in the destructive style. */
  danger?: boolean;
}

export function useConfirm() {
  const { confirm } = useDialog();
  return (opts: ConfirmOpts) =>
    confirm({
      title: opts.title ?? 'Confirm',
      description: opts.body,
      confirmLabel: opts.confirmLabel,
      cancelLabel: opts.cancelLabel,
      variant: opts.danger ? 'danger' : 'default',
    });
}

/** No-op — `DialogProvider` provides the real implementation. Kept so the
 *  current main.tsx import still resolves. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
