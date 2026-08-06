import { SearchIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

export const PAGE_SIZES = [10, 25, 50, 100] as const
export const DEFAULT_PAGE_SIZE = 25

export interface Column<T> {
  key: string
  header: string
  cell: (row: T) => React.ReactNode

  /** Narrow columns that should not absorb the remaining width. */
  width?: string

  /** Hidden below `sm`, for columns that are context rather than identity. */
  secondary?: boolean
}

interface DataTableProps<T> {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string

  total: number
  offset: number
  limit: number
  onPage: (offset: number) => void
  onLimit: (limit: number) => void

  search: string
  onSearch: (value: string) => void
  searchPlaceholder: string

  isPending: boolean
  empty: string
  onRowClick?: (row: T) => void
}

/**
 * A paginated, searchable table.
 *
 * Paging is server-side: the component is handed one page and the total, and
 * asks for another by offset. Paginating a full payload in the browser still
 * ships every row, which misses the point of paginating a directory that grows —
 * and the point here is that these lists are expected to grow.
 *
 * Deliberately not a generic table library. Sorting, column visibility and row
 * selection are all features nobody has asked for, and every one of them is a
 * server round-trip away from being a lie about what is on screen.
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  total,
  offset,
  limit,
  onPage,
  onLimit,
  search,
  onSearch,
  searchPlaceholder,
  isPending,
  empty,
  onRowClick,
}: DataTableProps<T>) {
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))
  const first = total === 0 ? 0 : offset + 1
  const last = Math.min(offset + rows.length, total)

  return (
    <div className="space-y-3">
      <div className="relative max-w-sm">
        <SearchIcon className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pl-9"
          value={search}
          onChange={(event) => { onSearch(event.target.value) }}
          placeholder={searchPlaceholder}
          aria-label={searchPlaceholder}
        />
      </div>

      <div className="overflow-x-auto rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              {columns.map((column) => (
                <TableHead
                  key={column.key}
                  className={column.secondary === true ? 'hidden sm:table-cell' : undefined}
                  style={column.width === undefined ? undefined : { width: column.width }}
                >
                  {column.header}
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>

          <TableBody>
            {isPending ? (
              // Rows rather than one block, so the table does not change height
              // when the data arrives.
              Array.from({ length: 3 }, (_, i) => (
                <TableRow key={i}>
                  {columns.map((column) => (
                    <TableCell key={column.key}>
                      <Skeleton className="h-4 w-24" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : rows.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length}
                  className="h-24 text-center text-muted-foreground"
                >
                  {search === '' ? empty : `Nothing matches “${search}”.`}
                </TableCell>
              </TableRow>
            ) : (
              rows.map((row) => (
                <TableRow
                  key={rowKey(row)}
                  className={onRowClick === undefined ? undefined : 'cursor-pointer'}
                  onClick={onRowClick === undefined ? undefined : () => { onRowClick(row) }}
                >
                  {columns.map((column) => (
                    <TableCell
                      key={column.key}
                      className={column.secondary === true ? 'hidden sm:table-cell' : undefined}
                    >
                      {column.cell(row)}
                    </TableCell>
                  ))}
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3 text-sm text-muted-foreground">
        <div className="flex items-center gap-3">
          <span>
            {/* The total, not just what is on screen. "25 of 412" is what tells
                an administrator whether the thing they are looking for is
                likely on this page. */}
            {total === 0 ? 'Nothing to show' : `${first}–${last} of ${total}`}
          </span>
          <Select
            value={String(limit)}
            onValueChange={(value) => { onLimit(Number(value)) }}
          >
            <SelectTrigger size="sm" className="w-[110px]" aria-label="Rows per page">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {PAGE_SIZES.map((size) => (
                <SelectItem key={size} value={String(size)}>
                  {size} per page
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="flex items-center gap-2">
          <span>
            Page {page} of {pages}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={offset === 0 || isPending}
            onClick={() => { onPage(Math.max(0, offset - limit)) }}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + rows.length >= total || isPending}
            onClick={() => { onPage(offset + limit) }}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  )
}
