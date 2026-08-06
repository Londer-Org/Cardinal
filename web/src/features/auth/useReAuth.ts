import { useMutation, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'
import { getCredential } from '@/lib/webauthn'

/**
 * Step-up: prove the credential again without starting a new session.
 *
 * The missing half of the freshness rule. Policy can demand a device-bound key
 * used within the last five minutes, and until this existed the only way to
 * satisfy it was to sign out and sign in again — which closed the same window
 * five minutes later, usually mid-task.
 */
export function useReAuth() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const ceremony = await api.auth.reauthBegin()
      const assertion = await getCredential(ceremony.options)
      return api.auth.reauthFinish(ceremony.ceremonyId, assertion)
    },
    onSuccess: (session) => {
      // The response is the refreshed account, so write it straight into the
      // cache: refetching would race the write we just made.
      queryClient.setQueryData(queryKeys.me, session)
    },
  })
}
