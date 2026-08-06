import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export function useRecoveries() {
  return useQuery({ queryKey: queryKeys.recoveries, queryFn: api.recoveries.list })
}

export function useOpenRecovery() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { login: string; reason: string }) =>
      api.recoveries.open(input.login, input.reason),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.recoveries })
    },
  })
}

export function useApproveRecovery() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.recoveries.approve,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.recoveries })
    },
  })
}

export function useCancelRecovery() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.recoveries.cancel,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.recoveries })
    },
  })
}
