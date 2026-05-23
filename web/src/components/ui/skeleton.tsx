/**
 * Skeleton placeholder block.
 * Use in suspended / loading states instead of a bare spinner.
 */
import type { CSSProperties } from 'react';

interface SkeletonProps {
  /** Tailwind className for sizing (e.g. "h-4 w-32"). */
  className?: string;
  style?: CSSProperties;
}

export function Skeleton({ className = 'h-4 w-full', style }: SkeletonProps) {
  return (
    <span
      aria-hidden
      className={`inline-block animate-pulse rounded ${className}`}
      style={{ backgroundColor: 'var(--color-bg-muted)', ...style }}
    />
  );
}
