import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, queryKeys, type GroupKind, type PageQuery } from '@/lib/api'

export function useUsers(page: PageQuery) {
  return useQuery({
    queryKey: queryKeys.users(page),
    queryFn: () => api.directory.users(page),
    // Keeps the previous page on screen while the next loads, so paging does
    // not flash an empty table on every click.
    placeholderData: (previous) => previous,
  })
}

/** One person's detail, fetched only when their row is opened. */
export function useUser(login: string | null) {
  return useQuery({
    queryKey: queryKeys.user(login ?? ''),
    queryFn: () => api.directory.user(login ?? ''),
    enabled: login !== null,
  })
}

export function useGroups(page: PageQuery, kind: GroupKind = '') {
  return useQuery({
    queryKey: queryKeys.groups(page, kind),
    queryFn: () => api.directory.groups(page, kind),
    placeholderData: (previous) => previous,
  })
}

/** Applications by name, for an owner picker. */
export function useApplicationRefs(page: PageQuery) {
  return useQuery({
    queryKey: queryKeys.refApplications(page),
    queryFn: () => api.directory.applications(page),
    placeholderData: (previous) => previous,
  })
}

export function useGroup(name: string | null) {
  return useQuery({
    queryKey: queryKeys.group(name ?? ''),
    queryFn: () => api.directory.group(name ?? ''),
    enabled: name !== null,
  })
}

export function useCreateUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.directory.createUser,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['directory', 'users'] })
    },
  })
}

export function useDisableUser() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.directory.disableUser,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['directory', 'users'] })
    },
  })
}

/**
 * Issuing or re-issuing an enrollment link.
 *
 * Re-issuing supersedes the outstanding one server-side, so a link that went to
 * the wrong person, expired, or was simply lost stops working the moment a
 * replacement is made.
 */
export function useIssueInvitation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.invitations.issue,
    onSuccess: async (_result, login) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['directory', 'users'] }),
        queryClient.invalidateQueries({ queryKey: queryKeys.user(login) }),
      ])
    },
  })
}

export function useRevokeInvitation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.invitations.revoke,
    onSuccess: async (_result, login) => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['directory', 'users'] }),
        queryClient.invalidateQueries({ queryKey: queryKeys.user(login) }),
      ])
    },
  })
}

export function useCreateGroup() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: api.directory.createGroup,
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ['directory', 'groups'] })
    },
  })
}

/**
 * Granting and revoking both invalidate people and groups.
 *
 * A membership is a fact about a pair, so it changes a count on each side, and
 * refreshing only the side that was clicked leaves the other quietly wrong.
 */
export function useGrantMembership() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: {
      group: string
      member: string
      until?: string
      reason: string
    }) =>
      api.directory.grant(input.group, {
        member: input.member,
        ...(input.until === undefined ? {} : { until: input.until }),
        reason: input.reason,
      }),
    onSuccess: async (_result, input) => {
      await invalidateMembership(queryClient, input.group, input.member)
    },
  })
}

export function useRevokeMembership() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (input: { group: string; member: string }) =>
      api.directory.revoke(input.group, input.member),
    onSuccess: async (_result, input) => {
      await invalidateMembership(queryClient, input.group, input.member)
    },
  })
}

async function invalidateMembership(
  queryClient: ReturnType<typeof useQueryClient>,
  group: string,
  member: string,
) {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ['directory', 'users'] }),
    queryClient.invalidateQueries({ queryKey: ['directory', 'groups'] }),
    queryClient.invalidateQueries({ queryKey: queryKeys.group(group) }),
    queryClient.invalidateQueries({ queryKey: queryKeys.user(member) }),
    // Admin rights are a membership too: granting or revoking directory-admins
    // changes what the person doing it can see.
    queryClient.invalidateQueries({ queryKey: queryKeys.me }),
  ])
}
