import { useMutation, useQuery } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export interface AuditFilter {
  action: string
  subject: string
  before: number
}

export function useAuditEvents(filter: AuditFilter) {
  return useQuery({
    queryKey: queryKeys.auditEvents(filter),
    queryFn: () => api.audit.events(filter),
    // The journal only ever gains rows at one end, so a page that has been
    // fetched can never change. Refetching it would be work that cannot
    // produce a different answer.
    staleTime: Infinity,
  })
}

/**
 * Verifying the chain, on demand only.
 *
 * A mutation rather than a query because it must not run on render: it reads
 * every event in the journal, and a page that did that on load would get slower
 * with age until somebody turned it off.
 */
export function useVerifyChain() {
  return useMutation({ mutationFn: api.audit.verify })
}
