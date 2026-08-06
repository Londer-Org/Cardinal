import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export function useConsents() {
  return useQuery({
    queryKey: queryKeys.consents,
    queryFn: api.consents.list,
  })
}

export function useRevokeConsent() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: api.consents.revoke,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.consents })
    },
  })
}
