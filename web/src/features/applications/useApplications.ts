import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  api,
  queryKeys,
  type CreateApplicationRequest,
  type RegisterApplicationRequest,
} from '@/lib/api'

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

/**
 * An application with no OIDC client, for something behind the proxy.
 *
 * A separate hook from registering a relying party because the two produce
 * different things: this one creates an entity for policy to name and a
 * hostname to belong to, and nothing that can complete a login.
 */
export function useCreateApplication() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: (input: CreateApplicationRequest) => api.applications.create(input),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.applications })
    },
  })
}

export function useAddHostname() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, hostname }: { name: string; hostname: string }) =>
      api.applications.addHostname(name, hostname),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.applications })
    },
  })
}

export function useRemoveHostname() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, hostname }: { name: string; hostname: string }) =>
      api.applications.removeHostname(name, hostname),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.applications })
    },
  })
}

/** Retires an application, or brings one back. Reaches both kinds. */
export function useSetApplicationEnabled() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) =>
      api.applications.setEnabled(name, enabled),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: queryKeys.applications }),
        // Disabling revoked whatever standing consent the current user had
        // granted it, so the account page is now showing something stale.
        queryClient.invalidateQueries({ queryKey: queryKeys.consents }),
      ])
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

/**
 * Replaces the secret, invalidating the old one at once.
 *
 * No grace period: two valid secrets would let a leaked one keep working while
 * somebody arranges the change-over, which is the opposite of what a rotation
 * is for. The application breaks until reconfigured, and that is intended.
 */
export function useRotateSecret() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.applications.rotateSecret,
    onSuccess: async () => {
      // Every token the old secret obtained is revoked with it, so the
      // "in use" counts on this page are now wrong.
      await queryClient.invalidateQueries({ queryKey: queryKeys.applications })
    },
  })
}

/**
 * How much of the directory an application is told about (ADR 0032).
 *
 * Fetched per application rather than carried on the list: it needs the group
 * count and the visible set, which is a query nobody browsing a table wants
 * paid for every row.
 */
export function useProjection(name: string) {
  return useQuery({
    queryKey: queryKeys.projection(name),
    queryFn: () => api.applications.projection(name),
  })
}

export function useSetProjection(name: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (mode: 'all' | 'owned') => api.applications.setProjection(name, mode),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.projection(name) })
    },
  })
}

export function useGroupSight(name: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ group, allow }: { group: string; allow: boolean }) =>
      allow
        ? api.applications.allowGroup(name, group)
        : api.applications.denyGroup(name, group),
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: queryKeys.projection(name) })
    },
  })
}
