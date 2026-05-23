export function fmtDate(s: string | null | undefined): string {
  if (!s) return '—';
  const d = new Date(s);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function daysUntil(s: string | null | undefined): number | null {
  if (!s) return null;
  return Math.floor((new Date(s).getTime() - Date.now()) / 86400000);
}

export function expiryClass(s: string | null | undefined): string {
  const d = daysUntil(s);
  if (d === null) return '';
  if (d < 14) return 'text-danger';
  if (d < 30) return 'text-warn';
  return '';
}
