/**
 * Reusable data table built on TanStack Table v8.
 *
 * Features:
 *   - Click-to-sort on column headers with direction indicators
 *   - Global search across every accessor
 *   - Client-side pagination + page-size selector
 *   - "Showing N–M of K" counter
 *   - Empty / no-data distinction
 *
 * Usage:
 *
 *   const columns: ColumnDef<Cert>[] = [
 *     { accessorKey: 'common_name', header: 'Domain',
 *       cell: (ctx) => <Link to={...}>{ctx.getValue<string>()}</Link> },
 *     { accessorKey: 'status', header: 'Status' },
 *   ];
 *   <DataTable columns={columns} data={certs} searchPlaceholder="Search domains…" />
 */

import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type PaginationState,
  type SortingState,
} from '@tanstack/react-table';
import { ChevronDown, ChevronsUpDown, ChevronUp, Search } from 'lucide-react';
import { useMemo, useState } from 'react';

export interface DataTableProps<TData> {
  columns: ColumnDef<TData, unknown>[];
  data: TData[];
  initialSort?: SortingState;
  searchPlaceholder?: string;
  pageSize?: number;
  pageSizeOptions?: number[];
  emptyMessage?: string;
  noDataMessage?: string;
  className?: string;
  hideSearch?: boolean;
  hidePagination?: boolean;
  /** Optional onRowClick — makes rows clickable (use for table-as-nav). */
  onRowClick?: (row: TData) => void;
}

const DEFAULT_PAGE_SIZE_OPTIONS = [10, 25, 50, 100];

export function DataTable<TData>({
  columns,
  data,
  initialSort = [],
  searchPlaceholder = 'Search…',
  pageSize = 25,
  pageSizeOptions = DEFAULT_PAGE_SIZE_OPTIONS,
  emptyMessage = 'No matches.',
  noDataMessage = 'No data.',
  className = '',
  hideSearch = false,
  hidePagination = false,
  onRowClick,
}: DataTableProps<TData>) {
  const [sorting, setSorting] = useState<SortingState>(initialSort);
  const [globalFilter, setGlobalFilter] = useState('');
  const [pagination, setPagination] = useState<PaginationState>({ pageIndex: 0, pageSize });

  const table = useReactTable({
    data,
    columns,
    state: { sorting, globalFilter, pagination },
    onSortingChange: setSorting,
    onGlobalFilterChange: setGlobalFilter,
    onPaginationChange: setPagination,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getPaginationRowModel: getPaginationRowModel(),
  });

  const rows = table.getRowModel().rows;
  const filteredCount = table.getFilteredRowModel().rows.length;
  const totalCount = data.length;
  const pageSizeOptionsResolved = useMemo(
    () => Array.from(new Set([pageSize, ...pageSizeOptions])).sort((a, b) => a - b),
    [pageSize, pageSizeOptions],
  );
  const showingFrom = rows.length === 0 ? 0 : pagination.pageIndex * pagination.pageSize + 1;
  const showingTo = pagination.pageIndex * pagination.pageSize + rows.length;

  return (
    <div className={`space-y-3 ${className}`}>
      {!hideSearch ? (
        <div className="flex items-center gap-2">
          <div className="relative max-w-xs flex-1">
            <Search aria-hidden className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2" style={{ color: 'var(--color-fg-muted)' }} />
            <input
              type="search"
              value={globalFilter}
              onChange={(e) => { setGlobalFilter(e.target.value); table.setPageIndex(0); }}
              placeholder={searchPlaceholder}
              className="block w-full rounded-md border py-1.5 pl-8 pr-3 text-sm"
              style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
              autoComplete="off"
              data-1p-ignore
              data-lpignore="true"
            />
          </div>
          {globalFilter ? (
            <span className="text-xs" style={{ color: 'var(--color-fg-muted)' }}>
              {filteredCount} match{filteredCount === 1 ? '' : 'es'}
            </span>
          ) : null}
        </div>
      ) : null}

      <div className="overflow-hidden rounded-md border" style={{ borderColor: 'var(--color-border)' }}>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs font-medium uppercase tracking-wide"
              style={{ backgroundColor: 'var(--color-bg-subtle)', color: 'var(--color-fg-muted)' }}>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id}>
                  {headerGroup.headers.map((header) => {
                    const canSort = header.column.getCanSort();
                    const sortDir = header.column.getIsSorted();
                    return (
                      <th
                        key={header.id}
                        scope="col"
                        className={[
                          'px-4 py-2.5',
                          canSort ? 'cursor-pointer select-none' : '',
                          (header.column.columnDef.meta as { className?: string } | undefined)?.className ?? '',
                        ].join(' ')}
                        onClick={canSort ? header.column.getToggleSortingHandler() : undefined}
                        aria-sort={sortDir === 'asc' ? 'ascending' : sortDir === 'desc' ? 'descending' : canSort ? 'none' : undefined}
                      >
                        <span className="inline-flex items-center gap-1.5">
                          {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                          {canSort ? (
                            sortDir === 'asc' ? <ChevronUp className="h-3 w-3" aria-hidden />
                            : sortDir === 'desc' ? <ChevronDown className="h-3 w-3" aria-hidden />
                            : <ChevronsUpDown className="h-3 w-3 opacity-40" aria-hidden />
                          ) : null}
                        </span>
                      </th>
                    );
                  })}
                </tr>
              ))}
            </thead>
            <tbody>
              {rows.length === 0 ? (
                <tr>
                  <td colSpan={table.getAllColumns().length} className="px-4 py-10 text-center text-sm" style={{ color: 'var(--color-fg-muted)' }}>
                    {totalCount === 0 ? noDataMessage : emptyMessage}
                  </td>
                </tr>
              ) : (
                rows.map((row) => (
                  <tr
                    key={row.id}
                    onClick={onRowClick ? () => onRowClick(row.original) : undefined}
                    className={`border-t transition-colors ${onRowClick ? 'cursor-pointer' : ''}`}
                    style={{ borderColor: 'var(--color-border)' }}
                  >
                    {row.getVisibleCells().map((cell) => (
                      <td
                        key={cell.id}
                        className={[
                          'px-4 py-3 align-middle',
                          (cell.column.columnDef.meta as { className?: string } | undefined)?.className ?? '',
                        ].join(' ')}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {!hidePagination && totalCount > 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-3 text-xs" style={{ color: 'var(--color-fg-muted)' }}>
          <span>
            Showing {showingFrom}–{showingTo} of {filteredCount}
            {globalFilter && filteredCount !== totalCount ? ` (filtered from ${totalCount})` : ''}
          </span>
          <div className="flex items-center gap-3">
            <label className="flex items-center gap-2">
              <span>Rows</span>
              <select
                value={pagination.pageSize}
                onChange={(e) => table.setPageSize(Number(e.target.value))}
                className="rounded-md border px-1.5 py-1 text-xs"
                style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
              >
                {pageSizeOptionsResolved.map((size) => (
                  <option key={size} value={size}>{size}</option>
                ))}
              </select>
            </label>
            <div className="inline-flex items-center gap-1">
              <PaginationButton onClick={() => table.setPageIndex(0)} disabled={!table.getCanPreviousPage()} label="First" />
              <PaginationButton onClick={() => table.previousPage()} disabled={!table.getCanPreviousPage()} label="Prev" />
              <span className="px-2 tabular-nums">
                {table.getState().pagination.pageIndex + 1} / {Math.max(1, table.getPageCount())}
              </span>
              <PaginationButton onClick={() => table.nextPage()} disabled={!table.getCanNextPage()} label="Next" />
              <PaginationButton onClick={() => table.setPageIndex(table.getPageCount() - 1)} disabled={!table.getCanNextPage()} label="Last" />
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function PaginationButton({ onClick, disabled, label }: { onClick: () => void; disabled: boolean; label: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-md border px-2 py-1 text-xs disabled:opacity-40"
      style={{ borderColor: 'var(--color-border)', backgroundColor: 'var(--color-bg)' }}
    >
      {label}
    </button>
  );
}
