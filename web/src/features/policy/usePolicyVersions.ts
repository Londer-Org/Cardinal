import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export function usePolicyVersions() {
  return useQuery({
    queryKey: queryKeys.policyVersions,
    queryFn: api.policy.versions,
    // The live version can change without this browser doing anything — from
    // the CLI, from a pipeline, or from another administrator during the same
    // incident. Refetching on focus is what stops somebody rolling back on top
    // of a rollback they cannot see.
    refetchOnWindowFocus: true,
  })
}

export function usePolicyDocument(version: number | null) {
  return useQuery({
    queryKey: queryKeys.policyDocument(version ?? 0),
    queryFn: () => api.policy.version(version ?? 0),
    enabled: version !== null,
  })
}

export function useActivatePolicy() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.policy.activate,
    onSuccess: async () => {
      // Both: the version list, and the active set the decision explorer reads.
      // Leaving the second stale would have the explorer explaining decisions
      // against rules that are no longer in force.
      await queryClient.invalidateQueries({ queryKey: queryKeys.policyVersions })
      await queryClient.invalidateQueries({ queryKey: queryKeys.policy })
    },
  })
}
