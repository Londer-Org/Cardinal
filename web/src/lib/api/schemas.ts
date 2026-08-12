import { z } from 'zod'

/**
 * The wire contract, described once.
 *
 * Every response is parsed through one of these at the boundary. `unknown` is
 * permitted in exactly one place — the value handed to `.parse()` in client.ts —
 * and nowhere else, so untyped data never travels more than a line from where it
 * entered. See ADR 0008.
 *
 * Hand-written, which is the wrong way round and is worth fixing: generating
 * them from a spec produced by the Go handlers would make drift impossible,
 * and hand-maintained validation drifting from the server is a security bug in
 * an identity system rather than a papercut. Nothing generates that spec
 * today.
 */

export const meSchema = z.object({
  id: z.string(),
  login: z.string(),
  displayName: z.string(),
  authMethod: z.string(),
  authAt: z.string(),
  deviceBound: z.boolean(),
  fullyEnrolled: z.boolean(),
  recoveryCodesRemaining: z.number(),
  // Drives what the UI offers, never what it may do — every admin endpoint
  // evaluates the policy itself.
  canAdminister: z.boolean(),
  // True when membership is fine and only freshness is missing, so the UI can
  // offer a security key rather than hiding a section the user is entitled to.
  adminNeedsReauth: z.boolean(),
  // Which parts of administration this session may use. Rendering a form
  // someone will be refused reads as a broken system, not a missing permission.
  canManageUsers: z.boolean(),
  canManageApplications: z.boolean(),
  // The broad tier, which neither of the two above implies. Recovery sits
  // behind this one alone.
  canAdministerDirectory: z.boolean(),
  email: z.string(),
})
export type Me = z.infer<typeof meSchema>

export const credentialSchema = z.object({
  id: z.string(),
  name: z.string(),
  createdAt: z.string(),
  lastUsedAt: z.string().nullable(),
  backupEligible: z.boolean(),
  deviceBound: z.boolean(),
})
export type Credential = z.infer<typeof credentialSchema>

export const credentialsSchema = z.array(credentialSchema)

export const ceremonySchema = z.object({
  ceremonyId: z.string(),
  // Handed straight to the browser's WebAuthn API, which validates it and
  // rejects anything malformed. Re-describing the whole PublicKeyCredential
  // option surface here would add a second spec to maintain without adding a
  // check the platform does not already perform.
  options: z.unknown(),
})
export type Ceremony = z.infer<typeof ceremonySchema>

export const recoveryCodesSchema = z.object({
  codes: z.array(z.string()),
  note: z.string(),
})
export type RecoveryCodes = z.infer<typeof recoveryCodesSchema>

export const decisionSchema = z.object({
  decisionPoint: z.string(),
  principalId: z.string().nullable(),
  action: z.string(),
  resource: z.string(),
  allowed: z.boolean(),
  reasons: z.array(z.string()),
  errors: z.array(z.string()),
  policyVersion: z.number(),
  durationMs: z.number(),
  // Computed server-side so the CLI, the UI and anyone reading the API all say
  // the same thing about why a decision went the way it did.
  explanation: z.string(),
})
export type Decision = z.infer<typeof decisionSchema>

export const decisionsSchema = z.array(decisionSchema)

export const policySchema = z.object({
  version: z.number(),
  description: z.string(),
  activatedAt: z.string(),
  digest: z.string(),
  policies: z.array(z.string()),
  document: z.string(),
})
export type Policy = z.infer<typeof policySchema>

export const applicationSchema = z.object({
  clientId: z.string(),
  name: z.string(),
  authMethod: z.string(),
  public: z.boolean(),
  redirectUris: z.array(z.string()),
  scopes: z.array(z.string()),
  requirePkce: z.boolean(),
  requireConsent: z.boolean(),
  devMode: z.boolean(),
  accessTokenLifetime: z.string(),
})
export type Application = z.infer<typeof applicationSchema>

/**
 * One application as the console lists them.
 *
 * An application entity, which may or may not also be an OIDC relying party.
 * This list used to be the relying parties alone, so an application that only
 * sits behind the proxy — no client id, nothing to sign in with — did not
 * appear at all, while being exactly the kind that needs a hostname adding.
 *
 * `oidc` is null rather than an object of zero values, because "public client"
 * and "no client" are different facts and a `public: false` in that position
 * would assert the first.
 */
export const applicationSummarySchema = z.object({
  name: z.string(),
  displayName: z.string(),
  disabled: z.boolean(),
  hostnames: z.array(z.string()),
  oidc: applicationSchema.nullable(),
})
export type ApplicationSummary = z.infer<typeof applicationSummarySchema>

export const applicationsSchema = z.array(applicationSummarySchema)

/**
 * How much of the directory one application is told about (ADR 0032).
 *
 * `totalGroups` is what makes `all` legible: "told about every group" is a
 * setting, "told about 14 of which it owns 2" is an argument.
 */
export const projectionSchema = z.object({
  mode: z.enum(['all', 'owned']),
  groups: z.array(z.object({ name: z.string(), owned: z.boolean() })),
  totalGroups: z.number(),
})
export type Projection = z.infer<typeof projectionSchema>

/** What an application currently holds — the answer to "may I disable this?" */
export const applicationDetailSchema = applicationSchema.extend({
  activeTokens: z.number(),
  standingGrants: z.number(),
  lastIssuedAt: z.string().nullable(),
})
export type ApplicationDetail = z.infer<typeof applicationDetailSchema>

/**
 * Registration returns the secret exactly once.
 *
 * Optional in the schema because a public client has none — asking for a secret
 * in a browser or mobile app produces a credential shipped to every user, which
 * is worse than having none at all.
 */
export const registeredApplicationSchema = applicationSchema.extend({
  secret: z.string().optional(),
})
export type RegisteredApplication = z.infer<typeof registeredApplicationSchema>

/**
 * One rule of the live policy set, structured where the builder recognises it.
 *
 * `composable` is false for the forbids and the administration tiers. Those are
 * the guardrails the other rules sit inside, so the console shows them as text
 * and offers no remove button — changing one goes through the policy file,
 * where it is reviewed as text.
 */
export const policyRuleSchema = z.object({
  id: z.string(),
  kind: z.string(),
  composable: z.boolean(),
  summary: z.string(),
  principalGroup: z.string(),
  resource: z.string(),
  resourceKind: z.string(),
  localAccounts: z.array(z.string()),
  /**
   * What this rule names and the directory does not have. A rule naming a group
   * that is not there never matches, and Cedar being default-deny makes that
   * look exactly like the rule working.
   */
  missing: z.array(z.string()),
  source: z.string(),
})
export type PolicyRule = z.infer<typeof policyRuleSchema>

export const policyRulesSchema = z.object({
  version: z.number(),
  rules: z.array(policyRuleSchema),
})

export const invitationSchema = z.object({
  login: z.string(),
  displayName: z.string(),
  expiresAt: z.string(),
  alreadyEnrolled: z.boolean(),
})
export type Invitation = z.infer<typeof invitationSchema>

export const issuedInvitationSchema = z.object({
  login: z.string(),
  url: z.string(),
  expiresAt: z.string(),
  recovery: z.boolean(),
})
export type IssuedInvitation = z.infer<typeof issuedInvitationSchema>

export const pendingInvitationsSchema = z.array(
  z.object({
    login: z.string(),
    displayName: z.string(),
    expiresAt: z.string(),
  }),
)
export type PendingInvitation = z.infer<typeof pendingInvitationsSchema>[number]

export const directoryUserSchema = z.object({
  login: z.string(),
  displayName: z.string(),
  email: z.string(),
  credentials: z.number(),
  fullyEnrolled: z.boolean(),
  groups: z.number(),
  invitationPending: z.boolean(),
  // Listings can include disabled accounts, so a row has to say which it is.
  disabled: z.boolean(),
  createdAt: z.string(),
})
export type DirectoryUser = z.infer<typeof directoryUserSchema>

/** A page, and how much there is. The total is what lets a table say "25 of
 *  412" rather than only showing what it was handed. */
function paged<T extends z.ZodType>(item: T) {
  return z.object({
    items: z.array(item),
    total: z.number(),
    limit: z.number(),
    offset: z.number(),
  })
}

export const directoryUsersSchema = paged(directoryUserSchema)

/**
 * A membership, with its period.
 *
 * `until` is null for an unbounded grant — the kind every directory fills up
 * with, and the kind the temporal model exists to make avoidable.
 */
export const grantSchema = z.object({
  group: z.string(),
  member: z.string(),
  from: z.string(),
  until: z.string().nullable(),
  grantedBy: z.string(),
  reason: z.string(),
})
export type Grant = z.infer<typeof grantSchema>

/** A POSIX identity, when the account has one. */
export const posixIdentitySchema = z.object({
  uid: z.number(),
  homeDirectory: z.string(),
  loginShell: z.string(),
  // Until a host has been told, the number can still be changed to match one
  // an existing system already uses. After that it is on a filesystem
  // somewhere and changing it would move files rather than edit a row.
  adoptable: z.boolean(),
})
export type PosixIdentity = z.infer<typeof posixIdentitySchema>

export const directoryUserDetailSchema = directoryUserSchema.extend({
  memberships: z.array(grantSchema),
  // Null for the common case: most accounts never touch a Linux host.
  posix: posixIdentitySchema.nullable(),
  // Set while a link is outstanding. "issued" and "issued yesterday, expiring
  // in an hour" call for different actions.
  invitationExpiresAt: z.string().nullable(),
})
export type DirectoryUserDetail = z.infer<typeof directoryUserDetailSchema>

export const directoryGroupSchema = z.object({
  name: z.string(),
  displayName: z.string(),
  members: z.number(),
  // Membership confers authority within Cardinal. Shown because an
  // administrator cannot otherwise tell aura-admins from directory-admins.
  system: z.boolean(),
  // The application this group exists for, empty when none.
  owner: z.string(),
})
export type DirectoryGroup = z.infer<typeof directoryGroupSchema>

export const directoryGroupsSchema = paged(directoryGroupSchema)

export const directoryHostSchema = z.object({
  name: z.string(),
  displayName: z.string(),
  // Whether a live credential exists — the machine has proved which host it is
  // at least once.
  enrolled: z.boolean(),
  // RFC3339, or empty for never. The two are different facts: never enrolled is
  // a machine nobody has set up, and long ago is one that stopped checking in.
  lastSeen: z.string(),
  // Each alias is the power to *be* that name, so a machine quietly holding
  // several is worth noticing.
  aliases: z.number(),
  groups: z.number(),
  disabled: z.boolean(),
})
export type DirectoryHost = z.infer<typeof directoryHostSchema>

export const directoryHostsSchema = paged(directoryHostSchema)

/** Applications by name only, for an owner picker. */
export const applicationRefSchema = z.object({
  name: z.string(),
  displayName: z.string(),
})
export type ApplicationRef = z.infer<typeof applicationRefSchema>

export const applicationRefsSchema = paged(applicationRefSchema)

export const directoryGroupDetailSchema = z.object({
  name: z.string(),
  displayName: z.string(),
  system: z.boolean(),
  owner: z.string(),
  members: z.array(grantSchema),
})
export type DirectoryGroupDetail = z.infer<typeof directoryGroupDetailSchema>

export const createdUserSchema = z.object({
  login: z.string(),
  invitationUrl: z.string().optional(),
  expiresAt: z.string().optional(),
})
export type CreatedUser = z.infer<typeof createdUserSchema>

export const recoveryRequestSchema = z.object({
  subject: z.string(),
  requestedBy: z.string(),
  requestedAt: z.string(),
  expiresAt: z.string(),
  reason: z.string(),
  // Named so a second administrator can see who else has agreed. Approving
  // because someone you trust already did is a real part of how this decision
  // gets made, and hiding it does not stop it happening.
  approvers: z.array(z.string()),
  required: z.number(),
  satisfied: z.boolean(),
})
export type RecoveryRequest = z.infer<typeof recoveryRequestSchema>

export const recoveryRequestsSchema = z.array(recoveryRequestSchema)

export const approvedRecoverySchema = recoveryRequestSchema.extend({
  invitationUrl: z.string().optional(),
})
export type ApprovedRecovery = z.infer<typeof approvedRecoverySchema>

export const errorSchema = z.object({ error: z.string() })

/**
 * A scope, alongside a description a person can actually weigh.
 *
 * The description is server-rendered rather than translated in the UI: the
 * consent record and the screen that produced it must agree about what was
 * agreed to, and two independent copies of that wording would eventually not.
 */
export const scopeDetailSchema = z.object({
  scope: z.string(),
  description: z.string(),
})
export type ScopeDetail = z.infer<typeof scopeDetailSchema>

export const pendingAuthorizationSchema = z.object({
  application: z.string(),
  clientId: z.string(),
  scopes: z.array(scopeDetailSchema),
  needsConsent: z.boolean(),
  // Policy refused this person access to this application. Reported before the
  // flow completes so the UI can say so, rather than the user watching sign-in
  // appear to work and then stop.
  denied: z.boolean(),
  deniedReason: z.string().optional(),
  deniedBy: z.array(z.string()).optional(),
  expiresAt: z.string(),
})
export type PendingAuthorization = z.infer<typeof pendingAuthorizationSchema>

export const consentSchema = z.object({
  clientId: z.string(),
  application: z.string(),
  scopes: z.array(scopeDetailSchema),
  grantedAt: z.string(),
})
export type Consent = z.infer<typeof consentSchema>

export const consentsSchema = z.array(consentSchema)

/** An access token, as its owner sees it — never the value. */
export const accessTokenSchema = z.object({
  id: z.string(),
  name: z.string(),
  // The leading characters, kept in clear. Enough to tell which of four tokens
  // a value in a CI setting is, and not enough to authenticate with.
  prefix: z.string(),
  createdAt: z.string(),
  expiresAt: z.string(),
  lastUsedAt: z.string().nullable(),
  expired: z.boolean(),
  /**
   * What this token may attempt. A ceiling, not a grant: policy still decides,
   * and a scope can only narrow what the owner could already do.
   */
  scopes: z.array(z.string()),
})
export type AccessToken = z.infer<typeof accessTokenSchema>

export const accessTokensSchema = z.object({ tokens: z.array(accessTokenSchema) })

/** The one response that carries the value, returned once and never again. */
export const createdTokenSchema = z.object({
  id: z.string(),
  name: z.string(),
  expiresAt: z.string(),
  token: z.string(),
})
export type CreatedToken = z.infer<typeof createdTokenSchema>

/** A live session, as its owner sees it. Never the token — only its hash exists. */
export const sessionSchema = z.object({
  id: z.string(),
  // The session making the request. What stops somebody revoking the one they
  // are using by accident, and what labels the row they should not worry about.
  current: z.boolean(),
  startedAt: z.string(),
  expiresAt: z.string(),
  // The hard end, never extended by use.
  endsAt: z.string(),
  authMethod: z.string(),
  authAt: z.string(),
  deviceBound: z.boolean(),
  // Empty when unrecorded, which is a real state for sessions created before
  // these were captured. Said plainly rather than rendered as "Unknown device".
  clientIp: z.string(),
  userAgent: z.string(),
})
export type Session = z.infer<typeof sessionSchema>

export const sessionsSchema = z.object({ sessions: z.array(sessionSchema) })

/** A host's own keys. Retired ones are listed too — see the `live` flag. */
export const hostCredentialSchema = z.object({
  fingerprint: z.string(),
  enrolledAt: z.string(),
  lastSeenAt: z.string().nullable(),
  // The key it authenticates with now, as against ones it used before.
  // "Which key made that request last month" is a question only the retired
  // rows can answer, so they are shown rather than hidden.
  live: z.boolean(),
})
export type HostCredential = z.infer<typeof hostCredentialSchema>

/** Who may log into a machine, as whom. The question the page exists for. */
export const hostAccessSchema = z.object({
  login: z.string(),
  displayName: z.string(),
  // Not always the same as the login, and it is what somebody auditing the
  // machine actually reads out of /etc/passwd.
  localAccount: z.string(),
  uid: z.number(),
  sudo: z.boolean(),
})
export type HostAccess = z.infer<typeof hostAccessSchema>

export const hostDetailSchema = directoryHostSchema.extend({
  aliasNames: z.array(z.string()),
  memberships: z.array(grantSchema),
  credentials: z.array(hostCredentialSchema),
  access: z.array(hostAccessSchema),
  // "Nobody may log in" and "policy could not be consulted" look identical on
  // screen and mean opposite things, so they are separate fields.
  accessUnavailable: z.boolean(),
})
export type HostDetail = z.infer<typeof hostDetailSchema>

export const hostEnrollmentSchema = z.object({
  command: z.string(),
  expiresAt: z.string(),
})
export type HostEnrollment = z.infer<typeof hostEnrollmentSchema>

/** One published policy set. */
export const policyVersionSchema = z.object({
  version: z.number(),
  description: z.string(),
  digest: z.string(),
  publishedAt: z.string(),
  // What the database says is activated.
  active: z.boolean(),
  activatedAt: z.string().nullable(),
  // Whether the server that answered is actually evaluating it. Differs from
  // `active` for the seconds between an activation and each node picking it
  // up — and indefinitely if an uncompilable version were ever activated.
  live: z.boolean(),
  policyCount: z.number(),
  // The one version nobody must roll back to, and it looks like the others.
  invalid: z.boolean(),
})
export type PolicyVersion = z.infer<typeof policyVersionSchema>

export const policyVersionsSchema = z.object({
  versions: z.array(policyVersionSchema),
  live: z.number(),
})

export const policyDocumentSchema = z.object({
  version: policyVersionSchema,
  document: z.string(),
})
export type PolicyDocument = z.infer<typeof policyDocumentSchema>

/** One party to a journal entry: what it was about, or who caused it. */
export const auditPartySchema = z.object({
  id: z.string(),
  name: z.string(),
  type: z.string(),
  // The name is a tombstone rather than something somebody chose. The journal
  // holds no personal data by design, so an erased account leaves its events
  // intact and unreadable by name — the design working, not corruption.
  redacted: z.boolean(),
})
export type AuditParty = z.infer<typeof auditPartySchema>

export const auditEventSchema = z.object({
  seq: z.number(),
  id: z.string(),
  occurredAt: z.string(),
  action: z.string(),
  subject: auditPartySchema.nullable(),
  actor: auditPartySchema.nullable(),
  // Opaque identifiers and enumerations only — never free text (ADR 0010).
  payload: z.record(z.string(), z.unknown()),
})
export type AuditEvent = z.infer<typeof auditEventSchema>

export const auditEventsSchema = z.object({
  events: z.array(auditEventSchema),
  // Cursor for the next page. Zero means this is the end — an append-only log
  // is paged by sequence rather than offset, because counting one that grows
  // forever is a full scan and an offset into one skips rows as it grows.
  before: z.number(),
})

export const chainReportSchema = z.object({
  valid: z.boolean(),
  eventsChecked: z.number(),
  brokenAtSeq: z.number(),
  reason: z.string(),
})
export type ChainReport = z.infer<typeof chainReportSchema>

/** One key of a certificate authority. */
export const authorityKeySchema = z.object({
  id: z.string(),
  fingerprint: z.string(),
  algorithm: z.string(),
  // signing | published | retired. Three rather than a boolean because
  // "published" is the operationally interesting one: trusted, not yet signing,
  // which is a rotation waiting on its distribution step.
  state: z.string(),
  createdAt: z.string(),
  activeAt: z.string().nullable(),
  retiredAt: z.string().nullable(),
  expiresAt: z.string().nullable(),
  subject: z.string(),
})
export type AuthorityKey = z.infer<typeof authorityKeySchema>

export const authoritySchema = z.object({
  enabled: z.boolean(),
  keys: z.array(authorityKeySchema),
  // Every trusted key, signing or not. A machine trusting only the signing key
  // rejects certificates issued in the minutes before a rotation.
  bundle: z.string(),
})
export type Authority = z.infer<typeof authoritySchema>

export const authoritiesSchema = z.object({
  ssh: authoritySchema,
  x509: authoritySchema,
})

/** One receiver of security events. */
export const ssfStreamSchema = z.object({
  // The directory name, which is what an operator knows and what the CLI
  // takes. The client id is the token's audience, and is what a receiver
  // debugging a rejected token is looking for.
  application: z.string(),
  clientId: z.string(),
  // Empty for a poll stream: nothing is sent to it, so there is nowhere to
  // send. `delivery` is what tells that apart from a stream misconfigured with
  // no endpoint at all.
  endpoint: z.string(),
  delivery: z.enum(['push', 'poll']),
  events: z.array(z.string()),
  enabled: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
})
export type SSFStream = z.infer<typeof ssfStreamSchema>

export const ssfStreamsSchema = z.object({
  streams: z.array(ssfStreamSchema),
  // Offered by the server rather than listed here, so the console cannot drift
  // from the set the CLI validates against.
  knownEvents: z.array(z.string()),
  pending: z.number(),
  // The number that have exhausted their attempts — the only figure on the
  // page that means somebody has to do something.
  failing: z.number(),
  issuer: z.string(),
  jwksUri: z.string(),
})
export type SSFStreams = z.infer<typeof ssfStreamsSchema>

/** What /api/health reports. The version is why the console asks. */
export const healthSchema = z.object({
  status: z.string(),
  version: z.string(),
})
export type Health = z.infer<typeof healthSchema>

/**
 * What the server returns when a terminal is approved.
 *
 * A code, not a session token. The console hands the code to the terminal
 * through a redirect, and the terminal exchanges it presenting a verifier the
 * console never saw — so what passes through the browser is worthless alone.
 */
export const cliAuthorizationSchema = z.object({
  code: z.string(),
  expiresIn: z.number(),
})
export type CLIAuthorization = z.infer<typeof cliAuthorizationSchema>

/**
 * A pending device sign-in, as the console is about to show it.
 *
 * `requestedFrom` is the address the server saw, never a name the terminal
 * chose: "approve the code from web-01" is exactly the sentence somebody
 * running this attack would like to be able to arrange.
 */
export const devicePendingSchema = z.object({
  userCode: z.string(),
  expiresAt: z.string(),
  requestedFrom: z.string(),
});
export type DevicePending = z.infer<typeof devicePendingSchema>;

/**
 * One configured value as the running server sees it.
 *
 * `ignored` is the reason this page exists: a setting parsed, validated and read
 * by nothing reads as supported, and somebody tunes it believing the tuning
 * happened.
 */
export const settingSchema = z.object({
  section: z.string(),
  name: z.string(),
  value: z.string(),
  source: z.enum(['file', 'environment', 'default']),
  secret: z.boolean(),
  ignored: z.string().optional(),
})
export type Setting = z.infer<typeof settingSchema>

export const configReportSchema = z.object({
  settings: z.array(settingSchema),
})

/** What redeeming a recovery code returns: an enrollment, not a session. */
export const redeemedRecoverySchema = z.object({
  token: z.string(),
  expiresAt: z.string(),
})

/**
 * How this deployment sends notification email.
 *
 * No password comes back — only whether one is set. A settings page that could
 * show it is one that hands it to whoever is behind the reader.
 */
export const mailSettingsSchema = z.object({
  enabled: z.boolean(),
  host: z.string(),
  port: z.number(),
  username: z.string(),
  fromAddress: z.string(),
  fromName: z.string(),
  replyTo: z.string(),
  tlsMode: z.enum(['starttls', 'tls', 'none']),
  passwordSet: z.boolean(),
  queued: z.number(),
  failing: z.number(),
})
export type MailSettings = z.infer<typeof mailSettingsSchema>

export const mailTestResultSchema = z.object({
  sent: z.boolean(),
  error: z.string().optional(),
})

export const mailTemplateSchema = z.object({
  kind: z.string(),
  subject: z.string(),
  body: z.string(),
  overridden: z.boolean(),
  builtInSubject: z.string(),
  builtInBody: z.string(),
})
export type MailTemplate = z.infer<typeof mailTemplateSchema>

export const mailTemplatesSchema = z.object({
  templates: z.array(mailTemplateSchema),
})
