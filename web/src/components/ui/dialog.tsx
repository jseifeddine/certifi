/**
 * In-app modal + toast system that replaces the trio of legacy components:
 * Modal.tsx, ConfirmDialog.tsx, Toast.tsx.
 *
 * Two public surfaces:
 *
 *   1. `useDialog()` — imperative hook for code-driven confirms and toasts:
 *
 *        const { confirm, toast } = useDialog();
 *        if (await confirm({ title: "Delete?", variant: "danger" })) { ... }
 *        toast({ kind: "success", description: "Saved." });
 *
 *   2. `<Dialog open={...} onClose={...} title="...">{...}</Dialog>` — a
 *      declarative primitive for modals that carry custom content (forms,
 *      diff previews, multi-step flows).
 *
 * Both flows live inside the single `DialogProvider` mounted in main.tsx.
 *
 * Accessibility:
 *   - role="dialog", aria-modal, aria-labelledby / aria-describedby
 *   - Escape closes (resolves false for confirms)
 *   - Backdrop click closes (configurable)
 *   - Focus moves into the dialog on open; primary action gets initial focus
 *   - Focus trap via Tab cycling
 *   - Body scroll lock while open
 *
 * Toasts are non-blocking, auto-dismiss after 4–8s depending on kind,
 * stacked top-right, dismissible.
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

// ── Public API ───────────────────────────────────────────────────────────────

export type DialogVariant = 'default' | 'danger';

export interface ConfirmOptions {
  title: string;
  description?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: DialogVariant;
  /** When true (default), backdrop click cancels. */
  dismissOnBackdrop?: boolean;
}

export type ToastKind = 'success' | 'error' | 'info' | 'warn';

export interface ToastOptions {
  title?: string;
  description: string;
  kind?: ToastKind;
  /** Duration in ms. Default depends on kind (error 8s, warn 6s, others 4s). */
  durationMs?: number;
}

interface DialogApi {
  confirm: (opts: ConfirmOptions) => Promise<boolean>;
  toast: (opts: ToastOptions) => void;
  /**
   * Convenience helpers that mirror the legacy `useToast()` shape so
   * pre-rewrite callers (`toast.error(msg)`, `toast.success(msg)`) keep
   * working without per-call-site refactors.
   */
  error: (msg: string) => void;
  success: (msg: string) => void;
  info: (msg: string) => void;
}

const DialogContext = createContext<DialogApi | null>(null);

export function useDialog(): DialogApi {
  const ctx = useContext(DialogContext);
  if (!ctx) throw new Error('useDialog must be used inside <DialogProvider>');
  return ctx;
}

// ── Provider ─────────────────────────────────────────────────────────────────

interface ConfirmState extends ConfirmOptions {
  id: number;
  resolve: (value: boolean) => void;
}
interface ToastState extends ToastOptions { id: number }

export function DialogProvider({ children }: { children: ReactNode }) {
  const [confirmStack, setConfirmStack] = useState<ConfirmState[]>([]);
  const [toasts, setToasts] = useState<ToastState[]>([]);
  const nextId = useRef(1);

  const confirm = useCallback((opts: ConfirmOptions): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      setConfirmStack((stack) => [...stack, { ...opts, id: nextId.current++, resolve }]);
    });
  }, []);

  const resolveTop = useCallback((value: boolean) => {
    setConfirmStack((stack) => {
      const top = stack[stack.length - 1];
      if (!top) return stack;
      top.resolve(value);
      return stack.slice(0, -1);
    });
  }, []);

  const toast = useCallback((opts: ToastOptions) => {
    const id = nextId.current++;
    const durationMs =
      opts.durationMs ??
      (opts.kind === 'error' ? 8000 : opts.kind === 'warn' ? 6000 : 4000);
    setToasts((cur) => [...cur, { ...opts, id }]);
    if (durationMs > 0) {
      window.setTimeout(() => {
        setToasts((cur) => cur.filter((t) => t.id !== id));
      }, durationMs);
    }
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((cur) => cur.filter((t) => t.id !== id));
  }, []);

  const error   = useCallback((msg: string) => toast({ description: msg, kind: 'error' }),   [toast]);
  const success = useCallback((msg: string) => toast({ description: msg, kind: 'success' }), [toast]);
  const info    = useCallback((msg: string) => toast({ description: msg, kind: 'info' }),    [toast]);

  const api = useMemo<DialogApi>(
    () => ({ confirm, toast, error, success, info }),
    [confirm, toast, error, success, info],
  );

  return (
    <DialogContext.Provider value={api}>
      {children}
      {confirmStack.map((state, index) => (
        <ConfirmModal
          key={state.id}
          state={state}
          isTopMost={index === confirmStack.length - 1}
          onResolve={resolveTop}
        />
      ))}
      <ToastViewport toasts={toasts} onDismiss={dismissToast} />
    </DialogContext.Provider>
  );
}

// ── Confirm modal ────────────────────────────────────────────────────────────

function ConfirmModal({
  state,
  isTopMost,
  onResolve,
}: {
  state: ConfirmState;
  isTopMost: boolean;
  onResolve: (value: boolean) => void;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    return () => { previouslyFocused.current?.focus?.(); };
  }, []);

  useEffect(() => {
    if (!isTopMost) return;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const tabbables = getTabbables(dialogRef.current);
    const initial = tabbables.find((el) => el.dataset['dialogFocus'] === 'true') ?? tabbables[0];
    initial?.focus();

    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') { event.preventDefault(); onResolve(false); return; }
      if (event.key === 'Tab') trapTab(event, dialogRef.current);
    }
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [isTopMost, onResolve]);

  const titleId = `dlg-title-${state.id}`;
  const descId = state.description ? `dlg-desc-${state.id}` : undefined;
  const variant = state.variant ?? 'default';
  const dismissOnBackdrop = state.dismissOnBackdrop !== false;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" aria-hidden={!isTopMost}>
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={() => dismissOnBackdrop && onResolve(false)} aria-hidden />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descId}
        className="relative w-full max-w-md rounded-lg border p-6 shadow-xl"
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
      >
        <h2 id={titleId} className="text-lg font-semibold">{state.title}</h2>
        {state.description ? (
          <p id={descId} className="mt-2 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {state.description}
          </p>
        ) : null}
        <div className="mt-6 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={() => onResolve(false)}
            className="rounded-md border px-4 py-2 text-sm"
            style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
          >
            {state.cancelLabel ?? 'Cancel'}
          </button>
          <button
            type="button"
            data-dialog-focus="true"
            onClick={() => onResolve(true)}
            className="rounded-md px-4 py-2 text-sm font-medium hover:opacity-95"
            style={
              variant === 'danger'
                ? { backgroundColor: 'var(--color-error)', color: 'white' }
                : { backgroundColor: 'var(--color-accent)', color: 'var(--color-accent-fg)' }
            }
          >
            {state.confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Generic Dialog primitive ────────────────────────────────────────────────

interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  hideTitle?: boolean;
  description?: ReactNode;
  /** Tailwind max-width class — default "max-w-lg". */
  maxWidthClass?: string;
  dismissOnBackdrop?: boolean;
  children: ReactNode;
  /** Optional footer; rendered below `children`. */
  footer?: ReactNode;
}

export function Dialog({
  open,
  onClose,
  title,
  hideTitle = false,
  description,
  maxWidthClass = 'max-w-lg',
  dismissOnBackdrop = true,
  children,
  footer,
}: DialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const previouslyFocused = useRef<HTMLElement | null>(null);
  const titleId = useRef(`dlg-title-${Math.random().toString(36).slice(2)}`);
  const descId = useRef(description ? `dlg-desc-${Math.random().toString(36).slice(2)}` : undefined);
  const onCloseRef = useRef(onClose);
  useEffect(() => { onCloseRef.current = onClose; }, [onClose]);

  useEffect(() => {
    if (!open) return;
    previouslyFocused.current = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const tabbables = getTabbables(dialogRef.current);
    const initial = tabbables.find((el) => el.dataset['dialogFocus'] === 'true') ?? tabbables[0];
    initial?.focus();

    function onKey(event: KeyboardEvent) {
      if (event.key === 'Escape') { event.preventDefault(); onCloseRef.current(); return; }
      if (event.key === 'Tab') trapTab(event, dialogRef.current);
    }
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prevOverflow;
      previouslyFocused.current?.focus?.();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center overflow-y-auto p-4 sm:items-center">
      <div className="absolute inset-0 bg-black/50 backdrop-blur-[1px]" onClick={() => dismissOnBackdrop && onClose()} aria-hidden />
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId.current}
        aria-describedby={descId.current}
        className={`relative my-4 w-full ${maxWidthClass} rounded-lg border p-6 shadow-xl`}
        style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
      >
        <h2
          id={titleId.current}
          className={hideTitle ? 'sr-only' : 'text-lg font-semibold'}
        >
          {title}
        </h2>
        {description ? (
          <p id={descId.current} className="mt-2 text-sm" style={{ color: 'var(--color-fg-muted)' }}>
            {description}
          </p>
        ) : null}
        <div className={hideTitle ? '' : 'mt-4'}>{children}</div>
        {footer ? <div className="mt-6 flex items-center justify-end gap-3">{footer}</div> : null}
      </div>
    </div>
  );
}

// ── Toast viewport ───────────────────────────────────────────────────────────

function ToastViewport({ toasts, onDismiss }: { toasts: ToastState[]; onDismiss: (id: number) => void }) {
  if (toasts.length === 0) return null;
  return (
    <div aria-live="polite" aria-atomic="false" className="pointer-events-none fixed right-4 top-4 z-[120] flex flex-col gap-2">
      {toasts.map((t) => (
        <ToastCard key={t.id} toast={t} onDismiss={() => onDismiss(t.id)} />
      ))}
    </div>
  );
}

function ToastCard({ toast, onDismiss }: { toast: ToastState; onDismiss: () => void }) {
  const kind = toast.kind ?? 'info';
  const borderColor =
    kind === 'success' ? 'var(--color-success)'
    : kind === 'error' ? 'var(--color-error)'
    : kind === 'warn'  ? 'var(--color-warn)'
                       : 'var(--color-border)';
  return (
    <div
      role={kind === 'error' ? 'alert' : 'status'}
      style={{
        borderColor: `color-mix(in oklch, ${borderColor} 50%, transparent)`,
        backgroundColor: 'var(--color-bg)',
      }}
      className="pointer-events-auto w-80 max-w-[90vw] rounded-md border p-3 text-sm shadow-lg"
    >
      <div className="flex items-start gap-3">
        <span aria-hidden className="mt-1 h-2 w-2 flex-none rounded-full" style={{ backgroundColor: borderColor }} />
        <div className="flex-1">
          {toast.title ? <div className="font-medium">{toast.title}</div> : null}
          <div style={toast.title ? { color: 'var(--color-fg-muted)' } : undefined}>{toast.description}</div>
        </div>
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className="text-xs"
          style={{ color: 'var(--color-fg-muted)' }}
        >
          ×
        </button>
      </div>
    </div>
  );
}

// ── Internals ────────────────────────────────────────────────────────────────

function getTabbables(root: HTMLElement | null): HTMLElement[] {
  if (!root) return [];
  const nodes = root.querySelectorAll<HTMLElement>(
    "a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])"
  );
  return Array.from(nodes).filter((el) => !el.hasAttribute('data-dialog-skip-tab'));
}

function trapTab(event: KeyboardEvent, root: HTMLElement | null) {
  const focusable = getTabbables(root);
  if (focusable.length === 0) return;
  const first = focusable[0]!;
  const last = focusable[focusable.length - 1]!;
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}
