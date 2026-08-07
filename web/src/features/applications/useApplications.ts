import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys, type RegisterApplicationRequest } from '@/lib/api'

export function useApplications() {
  return useQuery({
    queryKey: queryKeys.applications,
    queryFn: api.applications.list,
  })
}

/**
 * One application's detail, fetched only when a row is expanded.
 *
 * Separate from the list because the counts behind it are aggregate queries
 * over the token table, and running them for every row on every page load
 * would make the list slower for information nobody has asked to see.
 */
export function useApplication(clientID: string | null) {
  return useQuery({
    queryKey: queryKeys.application(clientID ?? ''),
    queryFn: () => api.applications.get(clientID ?? ''),
    enabled: clientID !== null,
  })
}

export function useRegisterApplication() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: RegisterApplicationRequest) => api.applications.register(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.applications })
    },
  })
}

export function useDisableApplication() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: api.applications.disable,
    onSuccess: async () => {
      // Both: the application leaves the list, and any consent the current user
      // had granted it was revoked server-side along with its tokens.
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.applications }),
        queryClient.invalidateQueries({ queryKey: queryKeys.consents }),
      ])
    },
  })
}
