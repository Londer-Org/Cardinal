import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

export function useGenerateRecoveryCodes() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: api.recovery.generateCodes,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.me })
    },
  })
}
