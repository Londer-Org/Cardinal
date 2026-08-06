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
  // while every request behind it fails — which is what any session does the
  // moment it expires or is revoked.
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
    // work in progress mid-flight, including a form the user had alt-tabbed
    // away from to fetch something.
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
  return useMutation({
    mutationFn: api.auth.logout,
    onSuccess: () => {
      // A full navigation, not a cache operation.
      //
      // This used to call queryClient.clear(), which removes queries from the
      // cache but does not notify observers already mounted — so the account
      // page went on rendering the session that had just ended, and signing out
      // appeared to do nothing at all.
      //
      // Reloading is also the stronger version of what clear() was reaching
      // for. Cached credential lists and account details belong to the session
      // that ended, but so does component state holding recovery codes, a
      // decision list, a half-filled form. Only discarding the whole heap
      // guarantees none of it is there for whoever signs in next.
      //
      // replace rather than assign, so Back cannot restore a rendered view of
      // the signed-in page.
      window.location.replace('/')
    },
  })
}
