import { useState } from 'react'
import type { PageQuery } from '@/lib/api'
import { DEFAULT_PAGE_SIZE } from '@/components/DataTable'

/**
 * Paging and search for one table.
 *
 * Changing the search or the page size resets the offset. Without that, typing
 * a filter while on page four shows an empty table and looks like the search
 * found nothing — a confusing failure with an obvious cause that nobody sees.
 */
export function usePageState(): {
  page: PageQuery
  setSearch: (q: string) => void
  setOffset: (offset: number) => void
  setLimit: (limit: number) => void
} {
  const [page, setPage] = useState<PageQuery>({
    q: '',
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
  })

  return {
    page,
    setSearch: (q) => { setPage((p) => ({ ...p, q, offset: 0 })) },
    setOffset: (offset) => { setPage((p) => ({ ...p, offset })) },
    setLimit: (limit) => { setPage((p) => ({ ...p, limit, offset: 0 })) },
  }
}
