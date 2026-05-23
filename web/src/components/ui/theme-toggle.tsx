/**
 * Three-way light / dark / system theme switch, driven by our existing
 * ThemeProvider in `src/theme.tsx` so the boot-script + localStorage logic
 * stays unified.
 */

import { Monitor, Moon, Sun } from 'lucide-react';
import { useTheme, type ThemeMode } from '../../theme';

interface ThemeToggleProps { className?: string }

export function ThemeToggle({ className = '' }: ThemeToggleProps) {
  const { mode, setMode } = useTheme();
  return (
    <div
      role="group"
      aria-label="Theme"
      className={`inline-flex items-center gap-0.5 rounded-md border p-0.5 ${className}`}
      style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
    >
      <ToggleButton label="Light"  active={mode === 'light'}  onClick={() => setMode('light')}><Sun     className="h-4 w-4" aria-hidden /></ToggleButton>
      <ToggleButton label="System" active={mode === 'system'} onClick={() => setMode('system')}><Monitor className="h-4 w-4" aria-hidden /></ToggleButton>
      <ToggleButton label="Dark"   active={mode === 'dark'}   onClick={() => setMode('dark')}><Moon     className="h-4 w-4" aria-hidden /></ToggleButton>
    </div>
  );
}

function ToggleButton({
  label,
  active,
  onClick,
  children,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      aria-label={label}
      title={label}
      className="flex h-7 w-7 items-center justify-center rounded transition-colors"
      style={
        active
          ? { backgroundColor: 'var(--color-bg-muted)', color: 'var(--color-fg)' }
          : { color: 'var(--color-fg-muted)' }
      }
    >
      {children}
    </button>
  );
}

// Suppress unused warning if a caller imports the legacy ThemeMode type from
// here rather than from theme.tsx.
export type { ThemeMode };
