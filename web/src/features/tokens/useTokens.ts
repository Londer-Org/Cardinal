import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

/** The signed-in person's own tokens. There is no way to see anybody else's. */
export function useTokens() {
  return useQuery({
    queryKey: queryKeys.tokens,
    queryFn: api.tokens.list,
  })
}

export function useCreateToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.tokens.create,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.tokens })
    },
  })
}

export function useRevokeToken() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.tokens.revoke,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.tokens })
    },
  })
}
