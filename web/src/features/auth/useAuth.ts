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

  // React Query keeps the last successful data when a later fetch errors, which
  // is right for a flaky endpoint and wrong for this one: a 401 means the
  // session is gone, and continuing to render the account page from stale data
  // would leave someone looking at an account they are no longer signed in to
  // while every request behind it fails. That is exactly what a break-glass
  // session does after fifteen minutes.
  const signedOut =
    query.error instanceof ApiError && query.error.isUnauthenticated

  return {
    session: signedOut ? null : (query.data ?? null),

    // Only before we have ever had an answer — not on every revalidation.
    //
    // query-core resets status to "pending" on any fetch where data is
    // undefined (see fetchState), and data is always undefined for a signed-out
    // user because the query errors. With refetchOnWindowFocus on, that made
    // isPending true every time the window regained focus, so the app swapped
    // in its loading skeleton and remounted the login page — discarding a
    // break-glass ceremony mid-flight, which is the one moment the user has
    // deliberately alt-tabbed away to sign a challenge.
    isLoading: query.isPending && !query.isFetched,

    isSignedIn: query.isSuccess && !signedOut,
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
