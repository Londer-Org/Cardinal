import { z } from 'zod'
import { request } from './client'
import {
  createGroupRequest,
  adminProfileRequest,
  createHostRequest,
  createTokenRequest,
  posixRequest,
  renameRequest,
  createUserRequest,
  enrollRequest,
  grantRequest,
  hostAliasRequest,
  issueInvitationRequest,
  nameCredentialRequest,
  openRecoveryRequest,
  registerApplicationRequest,
  ssfStreamRequest,
  createApplicationRequest,
  addHostnameRequest,
  addPolicyRuleRequest,
  updateProfileRequest,
  type CreateGroupRequest,
  type SSFStreamRequest,
  type AdminProfileRequest,
  type CreateHostRequest,
  type CreateTokenRequest,
  type PosixRequest,
  type CreateUserRequest,
  type GrantRequest,
  type OpenRecoveryRequest,
  type RegisterApplicationRequest,
  type CreateApplicationRequest,
  type AddPolicyRuleRequest,
  type UpdateProfileRequest,
} from './requests'
import {
  applicationDetailSchema,
  applicationsSchema,
  projectionSchema,
  applicationSummarySchema,
  ceremonySchema,
  consentsSchema,
  createdUserSchema,
  credentialSchema,
  applicationRefsSchema,
  directoryGroupDetailSchema,
  availabilitySchema,
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
  cliAuthorizationSchema,
  devicePendingSchema,
  configReportSchema,
  mailSettingsSchema,
  mailTemplatesSchema,
  mailTestResultSchema,
  redeemedRecoverySchema,
  pendingAuthorizationSchema,
  approvedRecoverySchema,
  pendingInvitationsSchema,
  recoveryRequestsSchema,
  recoveryRequestSchema,
  auditEventsSchema,
  healthSchema,
  authoritiesSchema,
  ssfStreamsSchema,
  ssfStreamSchema,
  chainReportSchema,
  policySchema,
  policyVersionsSchema,
  policyDocumentSchema,
  policyRulesSchema,
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
  /**
   * What this deployment is configured to do.
   *
   * Read-only, and no secret is ever in the response — only whether one is set.
   */
  config: () => request('/api/config', configReportSchema),

  /**
   * Notification email.
   *
   * The settings live in the database rather than the configuration file, so a
   * deployment running the published image can change them without rebuilding
   * a container. Nothing sent authorises anything (ADR 0009).
   */
  mail: {
    settings: () => request('/api/mail/settings', mailSettingsSchema),

    save: (input: unknown) =>
      request('/api/mail/settings', z.undefined(), { method: 'PUT', body: input }),

    /** Sends one and returns what the relay said, rather than only whether. */
    test: (to: string) =>
      request('/api/mail/test', mailTestResultSchema, {
        method: 'POST',
        body: { to },
      }),

    templates: () => request('/api/mail/templates', mailTemplatesSchema),

    saveTemplate: (kind: string, subject: string, body: string) =>
      request(`/api/mail/templates/${encodeURIComponent(kind)}`, z.undefined(), {
        method: 'PUT',
        body: { subject, body },
      }),

    resetTemplate: (kind: string) =>
      request(`/api/mail/templates/${encodeURIComponent(kind)}`, z.undefined(), {
        method: 'DELETE',
      }),
  },

  auth: {
    me: () => request('/api/auth/me', meSchema),

    logout: () => request('/api/auth/logout', z.undefined(), { method: 'POST' }),

    /**
     * Approves a terminal, handing it a code rather than a session.
     *
     * Requires a device-bound session, which is the whole point: the terminal
     * receives what the passkey proved. If this accepted an access token, a
     * leaked one could mint a device-bound session and walk past every rule
     * that refuses tokens.
     */
    authorizeCLI: (callback: string, verifierHash: string) =>
      request('/api/cli/authorize', cliAuthorizationSchema, {
        method: 'POST',
        body: { callback, verifierHash },
      }),

    /** What a device sign-in code refers to, before approving it. */
    pendingDevice: (code: string) =>
      request(`/api/cli/device/${encodeURIComponent(code)}`, devicePendingSchema),

    /** Approve one. Requires a device-bound session, like the loopback flow. */
    approveDevice: (code: string) =>
      request(`/api/cli/device/${encodeURIComponent(code)}/approve`, z.undefined(), {
        method: 'POST',
      }),

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
    /**
     * Every application, whether or not it speaks OIDC. Admin-only, enforced
     * server-side.
     */
    list: () => request('/api/applications', applicationsSchema),

    /**
     * An application with no OIDC client, for something behind the proxy.
     *
     * The server takes this branch when no redirect URIs are sent, so the same
     * endpoint registers both kinds — which one you get is decided by whether
     * the thing has anywhere to redirect to.
     */
    create: (input: CreateApplicationRequest) =>
      request('/api/applications', applicationSummarySchema, {
        method: 'POST',
        body: createApplicationRequest.parse(input),
      }),

    /**
     * Attaches an address, so forwardAuth can find the application from the
     * hostname it is handed.
     *
     * Keyed on the directory name, not a client id: the applications that need
     * this most do not have one.
     */
    addHostname: (name: string, hostname: string) =>
      request(`/api/applications/${encodeURIComponent(name)}/hostnames`,
        z.undefined(), {
          method: 'POST',
          body: addHostnameRequest.parse({ hostname }),
        }),

    /** Withdraws one. Effective at once — forwardAuth asks on every request. */
    removeHostname: (name: string, hostname: string) =>
      request(
        `/api/applications/${encodeURIComponent(name)}` +
          `/hostnames/${encodeURIComponent(hostname)}`,
        z.undefined(), { method: 'DELETE' }),

    /** How much of the directory this application is told about. */
    projection: (name: string) =>
      request(`/api/applications/${encodeURIComponent(name)}/projection`,
        projectionSchema),

    setProjection: (name: string, mode: 'all' | 'owned') =>
      request(`/api/applications/${encodeURIComponent(name)}/projection`,
        z.undefined(), { method: 'PUT', body: { mode } }),

    /** Sight of a group it does not own, and taking it back. */
    allowGroup: (name: string, group: string) =>
      request(
        `/api/applications/${encodeURIComponent(name)}` +
          `/projection/groups/${encodeURIComponent(group)}`,
        z.undefined(), { method: 'POST' }),

    denyGroup: (name: string, group: string) =>
      request(
        `/api/applications/${encodeURIComponent(name)}` +
          `/projection/groups/${encodeURIComponent(group)}`,
        z.undefined(), { method: 'DELETE' }),

    /**
     * Retires an application, or brings one back.
     *
     * By directory name so it reaches both kinds — an application behind the
     * proxy has no client id. Disabling revokes whatever tokens and standing
     * consents it holds; enabling does not restore them, because a revocation
     * that undoes itself is not one.
     */
    setEnabled: (name: string, enabled: boolean) =>
      request(
        `/api/applications/${encodeURIComponent(name)}/` +
          (enabled ? 'enable' : 'disable'),
        z.undefined(), { method: 'POST' }),

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

    /**
     * Replaces the secret and invalidates the old one immediately.
     *
     * No grace period, deliberately: two valid secrets would let a leaked one
     * keep working while somebody arranges the change-over, which is the
     * opposite of what this is for. The application breaks until it is
     * reconfigured, and that is the intended behaviour.
     */
    rotateSecret: (clientID: string) =>
      request(`/api/applications/${encodeURIComponent(clientID)}/secret`,
        z.object({ secret: z.string() }), { method: 'POST' }),
  },

  /**
   * Enrollment: the unauthenticated path a new account takes to its first
   * passkey. The invitation token is the only thing authorising any of it.
   */
  /**
   * Spending a recovery code, for somebody who cannot sign in.
   *
   * Returns an enrollment rather than a session. Credential self-service is
   * behind requireDeviceBound, so a session minted from a string on paper could
   * not register the passkey this exists to let somebody register.
   */
  redeemRecoveryCode: (login: string, code: string) =>
    request('/api/recovery/codes/redeem', redeemedRecoverySchema, {
      method: 'POST',
      body: { login, code },
    }),

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
      request(`/api/directory/users/${encodeURIComponent(login)}`,
        availabilitySchema, { method: 'DELETE' }),

    /**
     * Renames anything.
     *
     * The operation the data model exists to make ordinary: identity is an
     * immutable id and the name is an attribute, so this moves nothing else
     * (ADR 0002). Group membership, policy, sessions, tokens and the journal
     * all reference the id and do not notice.
     */
    rename: (kind: 'users' | 'groups' | 'hosts', name: string, next: string) =>
      request(`/api/directory/${kind}/${encodeURIComponent(name)}/rename`,
        z.object({ name: z.string() }),
        { method: 'POST', body: renameRequest.parse({ name: next }) }),

    updateUser: (login: string, input: AdminProfileRequest) =>
      request(`/api/directory/users/${encodeURIComponent(login)}`,
        z.object({ displayName: z.string(), email: z.string() }),
        { method: 'PATCH', body: adminProfileRequest.parse(input) }),

    setPosix: (login: string, input: PosixRequest) =>
      request(`/api/directory/users/${encodeURIComponent(login)}/posix`,
        z.object({
          uid: z.number(),
          homeDirectory: z.string(),
          loginShell: z.string(),
          adoptable: z.boolean(),
        }),
        { method: 'PUT', body: posixRequest.parse(input) }),

    enableUser: (login: string) =>
      request(`/api/directory/users/${encodeURIComponent(login)}/enable`,
        availabilitySchema, { method: 'POST' }),

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

  /**
   * Which build this is.
   *
   * From the server rather than compiled into the bundle, and that is the point:
   * the UI is embedded in the binary, so if these two could disagree something
   * has gone wrong with the deployment rather than with the number. Asking the
   * server means the console reports what is actually serving it.
   */
  health: () => request('/api/health', healthSchema),

  /** Who is told when access changes, and whether delivery is working. */
  ssfStreams: {
    get: () => request('/api/ssf/streams', ssfStreamsSchema),
    // PUT, because there is one stream per receiver: sending it twice is the
    // same request rather than a second stream.
    save: (application: string, input: SSFStreamRequest) =>
      request(`/api/ssf/streams/${encodeURIComponent(application)}`, ssfStreamSchema, {
        method: 'PUT',
        body: ssfStreamRequest.parse(input),
      }),
    setEnabled: (application: string, enabled: boolean) =>
      request(
        `/api/ssf/streams/${encodeURIComponent(application)}/${enabled ? 'resume' : 'pause'}`,
        z.undefined(),
        { method: 'POST' },
      ),
    remove: (application: string) =>
      request(`/api/ssf/streams/${encodeURIComponent(application)}`, z.undefined(), {
        method: 'DELETE',
      }),
  },

  /** The certificate authorities, and the bundles machines have to trust. */
  authorities: {
    get: () => request('/api/authorities', authoritiesSchema),
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
     * There is still no way to publish a whole policy set from here, and that
     * remains deliberate: a set belongs in git, reviewed and tested before it
     * governs anything, and one typed into a browser is one nobody read.
     * Rollback is the exception because it happens during an incident.
     */
    activate: (version: number) =>
      request(`/api/policy/versions/${String(version)}/activate`,
        z.object({ live: z.number(), policyCount: z.number() }),
        { method: 'POST' }),

    /**
     * The live set, rule by rule, structured where the builder recognises it.
     *
     * Adding one rule is not the same thing as publishing a set, which is why
     * this exists alongside the rule above rather than against it. The
     * difference is what can be reviewed: a set typed into a textarea is
     * arbitrary text nobody read, while a rule composed here names a group and
     * a resource chosen from the directory, is described as a sentence before
     * it is made, and lands as an ordinary version that rolls back like any
     * other. And for a deployment running the published image there is no file
     * to edit — the alternative to this is not review, it is the CLI or
     * nothing.
     */
    rules: () => request('/api/policy/rules', policyRulesSchema),

    addRule: (input: AddPolicyRuleRequest) =>
      request('/api/policy/rules', z.object({
        version: z.number(),
        rules: z.number(),
      }), { method: 'POST', body: addPolicyRuleRequest.parse(input) }),

    /**
     * Removes a rule the builder composed.
     *
     * The server refuses this for the forbids and the administration tiers.
     * They are the guardrails the other rules sit inside, and removing one goes
     * through the policy file where the change is reviewed as text.
     */
    removeRule: (id: string) =>
      request(`/api/policy/rules/${encodeURIComponent(id)}`, z.object({
        version: z.number(),
        rules: z.number(),
      }), { method: 'DELETE' }),
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
  DevicePending,
  Projection,
  SSFStream,
  SSFStreams,
  Setting,
  MailSettings,
  MailTemplate,
  Application,
  ApplicationDetail,
  ApplicationSummary,
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
  PosixIdentity,
  Grant,
  Invitation,
  IssuedInvitation,
  PendingInvitation,
  Decision,
  Me,
  PendingAuthorization,
  Health,
  Policy,
  AuditEvent,
  Authority,
  AuthorityKey,
  AuditParty,
  ChainReport,
  PolicyVersion,
  PolicyDocument,
  PolicyRule,
  RecoveryCodes,
  RecoveryRequest,
  RegisteredApplication,
  ScopeDetail,
} from './schemas'

/** Query keys, centralised so invalidation cannot drift from fetching. */
export const queryKeys = {
  mail: () => ['mail'] as const,
  mailTemplates: () => ['mail', 'templates'] as const,
  config: () => ['config'] as const,
  me: ['me'] as const,
  applications: ['applications'] as const,
  projection: (name: string) => ['applications', name, 'projection'] as const,
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
  health: ['health'] as const,
  authorities: ['authorities'] as const,
  ssfStreams: ['ssf', 'streams'] as const,
  auditEvents: (filter: { action: string; subject: string; before: number }) =>
    ['audit', 'events', filter] as const,
  policyVersions: ['policy', 'versions'] as const,
  policyRules: ['policy', 'rules'] as const,
  policyDocument: (version: number) => ['policy', 'versions', version] as const,
}
