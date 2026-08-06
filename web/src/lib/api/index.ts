import { z } from 'zod'
import { request } from './client'
import {
  applicationDetailSchema,
  applicationsSchema,
  breakGlassChallengeSchema,
  ceremonySchema,
  consentsSchema,
  credentialSchema,
  credentialsSchema,
  decisionsSchema,
  meSchema,
  pendingAuthorizationSchema,
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
     * Requests an emergency-access challenge.
     *
     * Also the bootstrap path: enrolling a first passkey needs a session, and
     * the offline key is what breaks that circle.
     */
    breakGlassBegin: () =>
      request('/api/auth/break-glass/begin', breakGlassChallengeSchema, {
        method: 'POST',
      }),

    breakGlassFinish: (challenge: string, signature: string, login: string) =>
      request('/api/auth/break-glass/finish', z.looseObject({}), {
        method: 'POST',
        body: { challenge, signature, login },
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

export interface RegisterApplicationInput {
  name: string
  displayName: string
  redirectUris: string[]
  scopes: string[]
  confidential: boolean
  requireConsent: boolean
  devMode: boolean
}

export { ApiError } from './client'
export type {
  Application,
  ApplicationDetail,
  Consent,
  Credential,
  Decision,
  Me,
  PendingAuthorization,
  Policy,
  RecoveryCodes,
  RegisteredApplication,
  ScopeDetail,
} from './schemas'

/** Query keys, centralised so invalidation cannot drift from fetching. */
export const queryKeys = {
  me: ['me'] as const,
  applications: ['applications'] as const,
  application: (clientID: string) => ['applications', clientID] as const,
  consents: ['consents'] as const,
  credentials: ['credentials'] as const,
  decisions: (deniedOnly: boolean) => ['decisions', deniedOnly] as const,
  policy: ['policy'] as const,
}
