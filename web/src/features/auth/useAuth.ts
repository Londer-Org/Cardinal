import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, queryKeys } from '@/lib/api'
import { getCredential } from '@/lib/webauthn'

/** The signed-in account, or null when there is no session. */
export function useSession() {
  const query = useQuery({
    queryKey: queryKeys.me,
    queryFn: api.auth.me,
    // A 401 is the ordinary "not signed in" answer, not a transient failure, so
    // retrying it would only delay showing the login screen.
    retry: (failureCount, error) =>
      !(error instanceof ApiError && error.isUnauthenticated) && failureCount < 2,
  })

  return {
    session: query.data ?? null,
    isLoading: query.isPending,
    isSignedIn: query.isSuccess,
  }
}

export function useLogin() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      // No username is sent: a discoverable ceremony lets the user pick an
      // account from their authenticator.
      const ceremony = await api.auth.loginBegin()
      const assertion = await getCredential(ceremony.options)
      await api.auth.loginFinish(ceremony.ceremonyId, assertion)
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.me })
    },
  })
}

export function useLogout() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: api.auth.logout,
    onSuccess: () => {
      // Clear everything rather than invalidating: cached credential lists and
      // account details belong to the session that just ended, and leaving them
      // in memory for the next person to sign in would be a small but real leak.
      queryClient.clear()
    },
  })
}
