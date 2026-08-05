import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

/**
 * Drives the two-step emergency flow.
 *
 * Challenge-response, so the offline private key never leaves the machine
 * holding it — the browser only ever sees a signature, which is worthless once
 * the single-use challenge is spent.
 */
export function useBreakGlass() {
  const queryClient = useQueryClient()

  const begin = useMutation({ mutationFn: api.auth.breakGlassBegin })

  const finish = useMutation({
    mutationFn: (input: { challenge: string; signature: string; login: string }) =>
      api.auth.breakGlassFinish(input.challenge, input.signature, input.login),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.me })
    },
  })

  return { challenge: begin, begin, finish }
}
