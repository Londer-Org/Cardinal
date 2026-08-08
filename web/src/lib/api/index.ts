import { z } from 'zod'
import { request } from './client'
import {
  createGroupRequest,
  createHostRequest,
  createTokenRequest,
  createUserRequest,
  enrollRequest,
  grantRequest,
  hostAliasRequest,
  issueInvitationRequest,
  nameCredentialRequest,
  openRecoveryRequest,
  registerApplicationRequest,
  updateProfileRequest,
  type CreateGroupRequest,
  type CreateHostRequest,
  type CreateTokenRequest,
  type CreateUserRequest,
  type GrantRequest,
  type OpenRecoveryRequest,
  type RegisterApplicationRequest,
  type UpdateProfileRequest,
} from './requests'
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
  accessTokensSchema,
  createdTokenSchema,
  sessionsSchema,
  directoryHostsSchema,
  hostDetailSchema,
  hostEnrollmentSchema,
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
  auditEventsSchema,
  chainReportSchema,
  policySchema,
  policyVersionsSchema,
  policyDocumentSchema,
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
    updateProfile: (input: UpdateProfileRequest) =>
      request('/api/auth/me', meSchema, {
        method: 'PATCH',
        body: updateProfileRequest.parse(input),
      }),

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

    register: (input: RegisterApplicationRequest) =>
      request('/api/applications', registeredApplicationSchema, {
        method: 'POST',
        body: registerApplicationRequest.parse(input),
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
        // Same split as registerFinish: the ceremony half is the
        // authenticator's, the profile half is typed by a person.
        body: {
          ...input,
          ...enrollRequest.parse({
            displayName: input.displayName,
            email: input.email,
          }),
        },
      }),
  },

  invitations: {
    list: () => request('/api/invitations', pendingInvitationsSchema),

    /** Issuing again supersedes any outstanding link, so the old one dies. */
    issue: (login: string) =>
      request('/api/invitations', issuedInvitationSchema, {
        method: 'POST',
        body: issueInvitationRequest.parse({ login }),
      }),

    revoke: (login: string) =>
      request(`/api/invitations/${encodeURIComponent(login)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  /** People and groups. Admin-only, enforced server-side. */
  /** Access tokens, always the signed-in person's own. */
  tokens: {
    list: () => request('/api/tokens', accessTokensSchema),

    create: (input: CreateTokenRequest) =>
      request('/api/tokens', createdTokenSchema, {
        method: 'POST',
        body: createTokenRequest.parse(input),
      }),

    revoke: (id: string) =>
      request(`/api/tokens/${encodeURIComponent(id)}`, z.undefined(),
        { method: 'DELETE' }),
  },

  /** Sessions, always the signed-in person's own. */
  sessions: {
    list: () => request('/api/sessions', sessionsSchema),

    revoke: (id: string) =>
      request(`/api/sessions/${encodeURIComponent(id)}`, z.undefined(),
        { method: 'DELETE' }),

    /** Signs out everywhere else, deliberately keeping this session alive. */
    revokeOthers: () =>
      request('/api/sessions', z.object({ revoked: z.number() }),
        { method: 'DELETE' }),
  },

  directory: {
    users: (page: PageQuery, status: UserStatus = '') =>
      request(
        `/api/directory/users?${pageParams(page)}${status === '' ? '' : `&status=${status}`}`,
        directoryUsersSchema,
      ),

    user: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}`,
        directoryUserDetailSchema),

    createUser: (input: CreateUserRequest) =>
      request('/api/directory/users', createdUserSchema, {
        method: 'POST',
        body: createUserRequest.parse(input),
      }),

    disableUser: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}`, z.undefined(),
        { method: 'DELETE' }),

    enableUser: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}/enable`,
        z.object({ login: z.string(), note: z.string() }), { method: 'POST' }),

    groups: (page: PageQuery, kind: GroupKind = '') =>
      request(
        `/api/directory/groups?${pageParams(page)}${kind === '' ? '' : `&kind=${kind}`}`,
        directoryGroupsSchema,
      ),

    hosts: (page: PageQuery) =>
      request(`/api/directory/hosts?${pageParams(page)}`, directoryHostsSchema),

    host: (name: string) =>
      request(`/api/directory/hosts/${encodeURIComponent(name)}`, hostDetailSchema),

    createHost: (input: CreateHostRequest) =>
      request('/api/directory/hosts', z.looseObject({}), {
        method: 'POST',
        body: createHostRequest.parse(input),
      }),

    /**
     * Hands a machine a way in.
     *
     * Returns the command rather than the bare token, following
     * `cardinal host enroll`: somebody holding a secret still has to know what
     * to do with it, and the step people get wrong is generating the keypair
     * anywhere other than on the machine itself.
     */
    enrollHost: (name: string) =>
      request(`/api/directory/hosts/${encodeURIComponent(name)}/enrollment`,
        hostEnrollmentSchema, { method: 'POST' }),

    addHostAlias: (name: string, alias: string) =>
      request(`/api/directory/hosts/${encodeURIComponent(name)}/aliases`,
        z.undefined(), { method: 'POST', body: hostAliasRequest.parse({ alias }) }),

    removeHostAlias: (name: string, alias: string) =>
      request(
        `/api/directory/hosts/${encodeURIComponent(name)}/aliases/${encodeURIComponent(alias)}`,
        z.undefined(), { method: 'DELETE' }),

    /** Applications by name, readable by whoever manages groups. */
    applications: (page: PageQuery) =>
      request(`/api/directory/applications?${pageParams(page)}`, applicationRefsSchema),

    group: (name: string) =>
      request(`/api/directory/groups/${encodeURIComponent(name)}`,
        directoryGroupDetailSchema),

    createGroup: (input: CreateGroupRequest) =>
      request('/api/directory/groups', z.looseObject({}), {
        method: 'POST',
        body: createGroupRequest.parse(input),
      }),

    /** `until` omitted means unbounded — the grant that gets forgotten. */
    grant: (group: string, input: GrantRequest) =>
      request(`/api/directory/groups/${encodeURIComponent(group)}/members`,
        z.undefined(), { method: 'POST', body: grantRequest.parse(input) }),

    revoke: (group: string, member: string) =>
      request(
        `/api/directory/groups/${encodeURIComponent(group)}/members/${encodeURIComponent(member)}`,
        z.undefined(), { method: 'DELETE' }),
  },

  /** Dual-control recovery: two administrators, neither the subject. */
  recoveries: {
    list: () => request('/api/recoveries', recoveryRequestsSchema),

    open: (input: OpenRecoveryRequest) =>
      request('/api/recoveries', recoveryRequestSchema, {
        method: 'POST',
        body: openRecoveryRequest.parse(input),
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
        // The ceremony fields come from the authenticator, not from a person,
        // so only the nickname is checked.
        body: { ceremonyId, response, ...nameCredentialRequest.parse({ name }) },
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

  /** The hash-chained journal of everything that happened. Admin-only. */
  audit: {
    events: (filter: { action?: string; subject?: string; before?: number }) => {
      const params = new URLSearchParams()
      if (filter.action !== undefined && filter.action !== '') {
        params.set('action', filter.action)
      }
      if (filter.subject !== undefined && filter.subject !== '') {
        params.set('subject', filter.subject)
      }
      if (filter.before !== undefined && filter.before !== 0) {
        params.set('before', String(filter.before))
      }
      return request(`/api/audit/events?${params.toString()}`, auditEventsSchema)
    },

    /**
     * Recomputes every hash from the first record forward.
     *
     * A POST despite reading nothing: it walks the entire journal, so it must
     * not be something a page does on load or a browser does on prefetch.
     */
    verify: () => request('/api/audit/verify', chainReportSchema, { method: 'POST' }),
  },

  policy: {
    /** The live policy set, including its text, so the explorer can show the
     *  rule that fired rather than only its name. */
    active: () => request('/api/policy', policySchema),

    /** Published versions, newest first. Admin-only. */
    versions: () => request('/api/policy/versions', policyVersionsSchema),

    /** One version's text, for reading before activating it. */
    version: (version: number) =>
      request(`/api/policy/versions/${String(version)}`, policyDocumentSchema),

    /**
     * Rolls the live set to a published version.
     *
     * There is deliberately no publish here. A policy set belongs in git,
     * reviewed and tested before it governs anything; one typed into a browser
     * is one nobody read. Rollback is the exception because it happens during
     * an incident.
     */
    activate: (version: number) =>
      request(`/api/policy/versions/${String(version)}/activate`,
        z.object({ live: z.number(), policyCount: z.number() }),
        { method: 'POST' }),
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
/** Which accounts a listing includes. Active by default. */
export type UserStatus = '' | 'disabled' | 'all'

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

export { ApiError, onStepUpNeeded } from './client'
export * from './requests'
export type {
  ApprovedRecovery,
  Application,
  ApplicationDetail,
  Consent,
  CreatedUser,
  Credential,
  DirectoryGroup,
  AccessToken,
  CreatedToken,
  Session,
  DirectoryHost,
  HostDetail,
  HostAccess,
  HostCredential,
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
  AuditEvent,
  AuditParty,
  ChainReport,
  PolicyVersion,
  PolicyDocument,
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
  users: (page: PageQuery, status: UserStatus) =>
    ['directory', 'users', status, page] as const,
  user: (login: string) => ['directory', 'users', login] as const,
  groups: (page: PageQuery, kind: GroupKind) =>
    ['directory', 'groups', kind, page] as const,
  hosts: (page: PageQuery) => ['directory', 'hosts', page] as const,
  host: (name: string) => ['directory', 'hosts', name] as const,
  refApplications: (page: PageQuery) =>
    ['directory', 'ref-applications', page] as const,
  group: (name: string) => ['directory', 'groups', name] as const,
  credentials: ['credentials'] as const,
  sessions: ['sessions'] as const,
  tokens: ['tokens'] as const,
  decisions: (deniedOnly: boolean) => ['decisions', deniedOnly] as const,
  policy: ['policy'] as const,
  auditEvents: (filter: { action: string; subject: string; before: number }) =>
    ['audit', 'events', filter] as const,
  policyVersions: ['policy', 'versions'] as const,
  policyDocument: (version: number) => ['policy', 'versions', version] as const,
}
