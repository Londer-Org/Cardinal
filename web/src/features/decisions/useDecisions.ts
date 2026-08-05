import { useQuery } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export function useDecisions(deniedOnly: boolean) {
  return useQuery({
    queryKey: queryKeys.decisions(deniedOnly),
    queryFn: () => api.decisions.list(deniedOnly),
    // Decisions accumulate as you browse, so the list is stale the moment it
    // arrives. Refetching keeps the explorer useful for the thing people
    // actually do with it: hit a denial, then come here to see why.
    refetchInterval: 5000,
  })
}

export function usePolicy() {
  return useQuery({
    queryKey: queryKeys.policy,
    queryFn: api.policy.active,
    // The policy set only changes when someone activates a version, so there
    // is no reason to poll it.
    staleTime: 60_000,
    retry: false,
  })
}

/**
 * Extracts one policy's text from the Cedar document.
 *
 * The server sends the whole set rather than per-policy fragments, because a
 * permit means nothing without knowing which forbids sat alongside it — Cedar
 * evaluates a set, not a rule. Slicing here keeps that whole document available
 * for the "show me everything" case while still being able to highlight the one
 * that fired.
 */
export function extractPolicy(document: string, name: string): string | null {
  // Policies are annotated `@id("name")` and run to the terminating semicolon.
  const marker = `@id("${name}")`
  const start = document.indexOf(marker)
  if (start === -1) return null

  const end = document.indexOf(';', start)
  if (end === -1) return document.slice(start).trim()

  return document.slice(start, end + 1).trim()
}
