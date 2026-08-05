import { z } from 'zod'
import { request } from './client'
import {
  breakGlassChallengeSchema,
  ceremonySchema,
  credentialSchema,
  credentialsSchema,
  meSchema,
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

  recovery: {
    generateCodes: () =>
      request('/api/recovery/codes', recoveryCodesSchema, { method: 'POST' }),

    remaining: () =>
      request('/api/recovery/codes/remaining', z.object({ remaining: z.number() })),
  },
}

export { ApiError } from './client'
export type { Credential, Me, RecoveryCodes } from './schemas'

/** Query keys, centralised so invalidation cannot drift from fetching. */
export const queryKeys = {
  me: ['me'] as const,
  credentials: ['credentials'] as const,
}
