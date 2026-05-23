/**
 * Brand wordmark — text-first variant.
 *
 * This project hasn't picked a final logo yet, so we render the existing
 * "🦎 Certifi" wordmark (block-level, scales to its container) and a designed
 * asset can drop in later by replacing the children of this component.
 */

import type { CSSProperties } from 'react';

interface WordmarkProps {
  className?: string;
  style?: CSSProperties;
}

export function Wordmark({ className = '', style }: WordmarkProps) {
  return (
    <span
      className={`inline-flex items-center gap-2 ${className}`}
      style={style}
      aria-label="Certifi"
      role="img"
    >
      <span aria-hidden className="text-xl leading-none">🦎</span>
      <span className="text-lg font-semibold tracking-tight" style={{ color: 'var(--color-fg)' }}>
        Certifi
      </span>
    </span>
  );
}
