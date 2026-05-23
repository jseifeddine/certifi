export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: 'badge-ok',
    pending: 'badge-warn',
    issuing: 'badge-warn',
    failed: 'badge-danger',
    expired: 'badge-danger',
  };
  return (
    <span className={`badge ${map[status] ?? 'badge-warn'}`}>
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}
