import { z } from 'zod'

/**
 * The wire contract, described once.
 *
 * Every response is parsed through one of these at the boundary. `unknown` is
 * permitted in exactly one place — the value handed to `.parse()` in client.ts —
 * and nowhere else, so untyped data never travels more than a line from where it
 * entered. See ADR 0008.
 *
 * These are hand-written today. Once the OpenAPI spec is generated from the Go
 * handlers (Phase 2), they get generated from it: hand-maintained validation
 * drifts from the server, and in an identity system that drift is a security
 * bug rather than a papercut.
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

export const applicationsSchema = z.array(applicationSchema)

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
