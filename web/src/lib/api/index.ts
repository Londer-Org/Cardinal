import { z } from 'zod'
import { request } from './client'
import {
  applicationDetailSchema,
  applicationsSchema,
  ceremonySchema,
  consentsSchema,
  createdUserSchema,
  credentialSchema,
  applicationRefsSchema,
  directoryGroupDetailSchema,
  directoryGroupsSchema,
  directoryUserDetailSchema,
  directoryUsersSchema,
  invitationSchema,
  issuedInvitationSchema,
  credentialsSchema,
  decisionsSchema,
  meSchema,
  pendingAuthorizationSchema,
  approvedRecoverySchema,
  pendingInvitationsSchema,
  recoveryRequestsSchema,
  recoveryRequestSchema,
  policySchema,
  recoveryCodesSchema,
  registeredApplicationSchema,
} from './schemas'

/**
 * Every endpoint Cardinal exposes, in one place.
 *
 * Grouped by resource rather than by screen, so a component asking for
 * something it should not have to reach for is visible in review.
 */
export const api = {
  auth: {
    me: () => request('/api/auth/me', meSchema),

    logout: () => request('/api/auth/logout', z.undefined(), { method: 'POST' }),

    /**
     * Edits your own display name and email.
     *
     * Not the login: that appears in policy and in every audit record a
     * colleague reads, so renaming stays an administrative act. Fields left
     * undefined are untouched rather than blanked.
     */
    updateProfile: (input: { displayName?: string; email?: string }) =>
      request('/api/auth/me', meSchema, { method: 'PATCH', body: input }),

    /**
     * Step-up: re-prove the credential without starting a new session.
     *
     * Policy can demand a device-bound key used in the last five minutes.
     * Without this the only way to satisfy that is to sign out and back in,
     * after which the window closes again five minutes later.
     */
    reauthBegin: () =>
      request('/api/auth/reauth/begin', ceremonySchema, { method: 'POST' }),

    reauthFinish: (ceremonyId: string, response: unknown) =>
      request('/api/auth/reauth/finish', meSchema, {
        method: 'POST',
        body: { ceremonyId, response },
      }),

    /**
     * Begins a login ceremony.
     *
     * Omitting `login` starts a discoverable (usernameless) ceremony, which is
     * what the UI does: the user picks an account from their authenticator, so
     * the server reveals nothing beforehand and username enumeration stops
     * being an attack surface at all.
     */
    loginBegin: (login?: string) =>
      request('/api/auth/login/begin', ceremonySchema, {
        method: 'POST',
        body: login === undefined ? {} : { login },
      }),

    /**
     * Completes a parked OIDC authorization now that a session exists.
     *
     * Returns where to send the browser next — the provider's own callback,
     * which redirects onwards to the application that started the flow.
     */
    oidcResume: (authID: string) =>
      request(`/api/oidc/resume?auth=${encodeURIComponent(authID)}`,
        z.object({ continue: z.string() })),

    /**
     * Describes a parked authorization: which application, asking for what.
     *
     * Fetched before resuming, because the answer decides whether the user is
     * shown anything at all. `needsConsent` is false for a first-party
     * application, and for one they have already agreed to.
     */
    oidcPending: (authID: string) =>
      request(`/api/oidc/pending?auth=${encodeURIComponent(authID)}`,
        pendingAuthorizationSchema),

    /** Records approval or refusal of a pending authorization. */
    oidcConsent: (authID: string, approve: boolean) =>
      request('/api/oidc/consent', z.object({ approved: z.boolean() }), {
        method: 'POST',
        body: { auth: authID, approve },
      }),

    loginFinish: (ceremonyId: string, response: unknown) =>
      request('/api/auth/login/finish', z.looseObject({}), {
        method: 'POST',
        body: { ceremonyId, response },
      }),
  },

  applications: {
    /** Every registered relying party. Admin-only, enforced server-side. */
    list: () => request('/api/applications', applicationsSchema),

    /** One application, including what it currently holds. */
    get: (clientID: string) =>
      request(`/api/applications/${encodeURIComponent(clientID)}`,
        applicationDetailSchema),

    register: (input: RegisterApplicationInput) =>
      request('/api/applications', registeredApplicationSchema, {
        method: 'POST',
        body: input,
      }),

    /**
     * Retires an application and revokes what it holds.
     *
     * Not a delete: the registration stays so past decisions and audit events
     * referencing this client remain explicable.
     */
    disable: (clientID: string) =>
      request(`/api/applications/${encodeURIComponent(clientID)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  /**
   * Enrollment: the unauthenticated path a new account takes to its first
   * passkey. The invitation token is the only thing authorising any of it.
   */
  enroll: {
    details: (token: string) =>
      request(`/api/enroll?token=${encodeURIComponent(token)}`, invitationSchema),

    begin: (token: string) =>
      request('/api/enroll/begin', ceremonySchema, {
        method: 'POST',
        body: { token },
      }),

    finish: (input: {
      token: string
      ceremonyId: string
      response: unknown
      name: string
      displayName: string
      email: string
    }) =>
      request('/api/enroll/finish', z.looseObject({}), {
        method: 'POST',
        body: input,
      }),
  },

  invitations: {
    list: () => request('/api/invitations', pendingInvitationsSchema),

    /** Issuing again supersedes any outstanding link, so the old one dies. */
    issue: (login: string) =>
      request('/api/invitations', issuedInvitationSchema, {
        method: 'POST',
        body: { login },
      }),

    revoke: (login: string) =>
      request(`/api/invitations/${encodeURIComponent(login)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  /** People and groups. Admin-only, enforced server-side. */
  directory: {
    users: (page: PageQuery) =>
      request(`/api/directory/users?${pageParams(page)}`, directoryUsersSchema),

    user: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}`,
        directoryUserDetailSchema),

    createUser: (input: { login: string; displayName: string; invite: boolean }) =>
      request('/api/directory/users', createdUserSchema, {
        method: 'POST',
        body: input,
      }),

    disableUser: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}`, z.undefined(),
        { method: 'DELETE' }),

    groups: (page: PageQuery, kind: GroupKind = '') =>
      request(
        `/api/directory/groups?${pageParams(page)}${kind === '' ? '' : `&kind=${kind}`}`,
        directoryGroupsSchema,
      ),

    /** Applications by name, readable by whoever manages groups. */
    applications: (page: PageQuery) =>
      request(`/api/directory/applications?${pageParams(page)}`, applicationRefsSchema),

    group: (name: string) =>
      request(`/api/directory/groups/${encodeURIComponent(name)}`,
        directoryGroupDetailSchema),

    createGroup: (input: { name: string; displayName: string; owner: string }) =>
      request('/api/directory/groups', z.looseObject({}), {
        method: 'POST',
        body: input,
      }),

    /** `until` omitted means unbounded — the grant that gets forgotten. */
    grant: (group: string, input: { member: string; until?: string; reason: string }) =>
      request(`/api/directory/groups/${encodeURIComponent(group)}/members`,
        z.undefined(), { method: 'POST', body: input }),

    revoke: (group: string, member: string) =>
      request(
        `/api/directory/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(member)}`,
        z.undefined(), { method: 'DELETE' }),
  },

  /** Dual-control recovery: two administrators, neither the subject. */
  recoveries: {
    list: () => request('/api/recoveries', recoveryRequestsSchema),

    open: (login: string, reason: string) =>
      request('/api/recoveries', recoveryRequestSchema, {
        method: 'POST',
        body: { login, reason },
      }),

    approve: (login: string) =>
      request(`/api/recoveries/${encodeURIComponent(login)}/approve`,
        approvedRecoverySchema, { method: 'POST' }),

    cancel: (login: string) =>
      request(`/api/recoveries/${encodeURIComponent(login)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  consents: {
    /** Applications this user has granted access to. */
    list: () => request('/api/consents', consentsSchema),

    /** Withdraws access, and the tokens it produced along with it. */
    revoke: (clientID: string) =>
      request(`/api/consents/${encodeURIComponent(clientID)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  credentials: {
    list: () => request('/api/credentials', credentialsSchema),

    registerBegin: () =>
      request('/api/credentials/register/begin', ceremonySchema, { method: 'POST' }),

    registerFinish: (ceremonyId: string, response: unknown, name: string) =>
      request('/api/credentials/register/finish', credentialSchema, {
        method: 'POST',
        body: { ceremonyId, response, name },
      }),

    revoke: (id: string) =>
      request(`/api/credentials/${id}`, z.undefined(), { method: 'DELETE' }),
  },

  decisions: {
    /** Recent authorization decisions. Scoped to the caller server-side. */
    list: (deniedOnly: boolean) =>
      request(
        `/api/decisions?limit=100${deniedOnly ? '&denied=true' : ''}`,
        decisionsSchema,
      ),
  },

  policy: {
    /** The live policy set, including its text, so the explorer can show the
     *  rule that fired rather than only its name. */
    active: () => request('/api/policy', policySchema),
  },

  recovery: {
    generateCodes: () =>
      request('/api/recovery/codes', recoveryCodesSchema, { method: 'POST' }),

    remaining: () =>
      request('/api/recovery/codes/remaining', z.object({ remaining: z.number() })),
  },
}

/** Paging and search, as the directory endpoints expect them. */
/** Which category of group to list. Empty means all of them. */
export type GroupKind = '' | 'system' | 'application' | 'plain'

export interface PageQuery {
  q: string
  limit: number
  offset: number
}

function pageParams({ q, limit, offset }: PageQuery): string {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  // Omitted rather than sent empty, so the URL a user sees while browsing is
  // the URL they would have typed.
  if (q !== '') params.set('q', q)
  return params.toString()
}

export interface RegisterApplicationInput {
  name: string
  displayName: string
  redirectUris: string[]
  scopes: string[]
  confidential: boolean
  requireConsent: boolean
  devMode: boolean
}

export { ApiError, onStepUpNeeded, requestStepUp } from './client'
export type {
  ApprovedRecovery,
  Application,
  ApplicationDetail,
  Consent,
  CreatedUser,
  Credential,
  DirectoryGroup,
  DirectoryGroupDetail,
  DirectoryUser,
  DirectoryUserDetail,
  Grant,
  Invitation,
  IssuedInvitation,
  PendingInvitation,
  Decision,
  Me,
  PendingAuthorization,
  Policy,
  RecoveryCodes,
  RecoveryRequest,
  RegisteredApplication,
  ScopeDetail,
} from './schemas'

/** Query keys, centralised so invalidation cannot drift from fetching. */
export const queryKeys = {
  me: ['me'] as const,
  applications: ['applications'] as const,
  application: (clientID: string) => ['applications', clientID] as const,
  consents: ['consents'] as const,
  invitations: ['invitations'] as const,
  recoveries: ['recoveries'] as const,
  users: (page: PageQuery) => ['directory', 'users', page] as const,
  user: (login: string) => ['directory', 'users', login] as const,
  groups: (page: PageQuery, kind: GroupKind) =>
    ['directory', 'groups', kind, page] as const,
  refApplications: (page: PageQuery) =>
    ['directory', 'ref-applications', page] as const,
  group: (name: string) => ['directory', 'groups', name] as const,
  credentials: ['credentials'] as const,
  decisions: (deniedOnly: boolean) => ['decisions', deniedOnly] as const,
  policy: ['policy'] as const,
}
