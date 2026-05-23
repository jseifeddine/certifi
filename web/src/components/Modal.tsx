/**
 * Compat shim — wraps the new `<Dialog>` primitive so existing pages keep
 * importing `<Modal title=… onClose=…>`. New code should reach for
 * `components/ui/dialog.tsx` directly.
 */

import { type ReactNode } from 'react';
import { Dialog } from './ui/dialog';

export function Modal({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <Dialog open onClose={onClose} title={title} maxWidthClass="max-w-xl" footer={footer}>
      {children}
    </Dialog>
  );
}
