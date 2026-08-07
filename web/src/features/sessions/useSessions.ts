import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

/** The signed-in person's own sessions. There is no way to see anybody else's. */
export function useSessions() {
  return useQuery({
    queryKey: queryKeys.sessions,
    queryFn: api.sessions.list,
  })
}

export function useRevokeSession() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.sessions.revoke,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.sessions })
    },
  })
}

export function useRevokeOtherSessions() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.sessions.revokeOthers,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.sessions })
    },
  })
}
