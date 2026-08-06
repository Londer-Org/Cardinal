import { z } from 'zod'
import { request } from './client'
import {
  breakGlassChallengeSchema,
  ceremonySchema,
  credentialSchema,
  credentialsSchema,
  decisionsSchema,
  meSchema,
  policySchema,
  recoveryCodesSchema,
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

    loginFinish: (ceremonyId: string, response: unknown) =>
      request('/api/auth/login/finish', z.looseObject({}), {
        method: 'POST',
        body: { ceremonyId, response },
      }),
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

export { ApiError } from './client'
export type { Credential, Decision, Me, Policy, RecoveryCodes } from './schemas'

/** Query keys, centralised so invalidation cannot drift from fetching. */
export const queryKeys = {
  me: ['me'] as const,
  credentials: ['credentials'] as const,
  decisions: (deniedOnly: boolean) => ['decisions', deniedOnly] as const,
  policy: ['policy'] as const,
}
