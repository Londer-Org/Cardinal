import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'
import { getCredential } from '@/lib/webauthn'

/**
 * Re-proves the key, and puts back whatever was refused for want of it.
 *
 * Shared by the in-page prompt and the dialog, which ask the same question in
 * two situations. Two copies of this would be two chances for one of them to
 * forget the invalidation and leave the user looking at a page that stayed
 * empty after they had done what it asked.
 */
export function useStepUp() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const ceremony = await api.auth.reauthBegin()
      const assertion = await getCredential(ceremony.options)
      return api.auth.reauthFinish(ceremony.ceremonyId, assertion)
    },
    onSuccess: (session) => {
      // The refreshed account written straight in: refetching would race the
      // write just made.
      queryClient.setQueryData(queryKeys.me, session)
      // And everything the page was refused, asked again.
      void queryClient.invalidateQueries()
    },
  })
}
