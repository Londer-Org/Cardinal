import { z } from 'zod'

/**
 * Every response is parsed through a zod schema at the boundary.
 *
 * `unknown` is permitted in exactly one place — the value handed to `.parse()` —
 * and nowhere else. Untyped data never travels more than one line from where it
 * entered. See ADR 0008.
 */

export const meSchema = z.object({
  id: z.string(),
  login: z.string(),
  displayName: z.string(),
  authMethod: z.string(),
  authAt: z.string(),
  deviceBound: z.boolean(),
  emergency: z.boolean(),
  fullyEnrolled: z.boolean(),
  recoveryCodesRemaining: z.number(),
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
  // The WebAuthn options are handed straight to the browser API, which does its
  // own validation and rejects anything malformed. Re-describing the entire
  // PublicKeyCredential option surface in zod would add a second spec to
  // maintain without adding a check the platform does not already perform.
  options: z.unknown(),
})
export type Ceremony = z.infer<typeof ceremonySchema>

export const recoveryCodesSchema = z.object({
  codes: z.array(z.string()),
  note: z.string(),
})

const errorSchema = z.object({ error: z.string() })

export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

/** Reads the CSRF cookie the server set. Deliberately readable by script: it is
 *  only useful alongside the session cookie, which stays HttpOnly. */
function csrfToken(): string {
  const match = /(?:^|;\s*)cardinal_csrf=([^;]*)/.exec(document.cookie)
  return match?.[1] ? decodeURIComponent(match[1]) : ''
}

async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers)
  headers.set('Accept', 'application/json')
  if (init?.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (init?.method !== undefined && init.method !== 'GET') {
    headers.set('X-Cardinal-CSRF', csrfToken())
  }

  const response = await fetch(path, {
    ...init,
    headers,
    // Cookies are the whole authentication mechanism here.
    credentials: 'same-origin',
  })

  if (response.status === 204) {
    return schema.parse(undefined)
  }

  const body: unknown = await response.json().catch(() => null)

  if (!response.ok) {
    const parsed = errorSchema.safeParse(body)
    throw new ApiError(
      response.status,
      parsed.success ? parsed.data.error : `request failed (${response.status})`,
    )
  }

  // The only place `unknown` is allowed to exist. After this line everything is
  // typed, and a server change that breaks the contract fails loudly here
  // rather than surfacing as undefined three components away.
  return schema.parse(body)
}

export const api = {
  me: () => request('/api/auth/me', meSchema),

  logout: () =>
    request('/api/auth/logout', z.undefined(), { method: 'POST' }),

  loginBegin: (login?: string) =>
    request('/api/auth/login/begin', ceremonySchema, {
      method: 'POST',
      body: JSON.stringify(login === undefined ? {} : { login }),
    }),

  loginFinish: (ceremonyId: string, response: unknown) =>
    request('/api/auth/login/finish', z.looseObject({}), {
      method: 'POST',
      body: JSON.stringify({ ceremonyId, response }),
    }),

  credentials: () => request('/api/credentials', credentialsSchema),

  registerBegin: () =>
    request('/api/credentials/register/begin', ceremonySchema, { method: 'POST' }),

  registerFinish: (ceremonyId: string, response: unknown, name: string) =>
    request('/api/credentials/register/finish', credentialSchema, {
      method: 'POST',
      body: JSON.stringify({ ceremonyId, response, name }),
    }),

  revokeCredential: (id: string) =>
    request(`/api/credentials/${id}`, z.undefined(), { method: 'DELETE' }),

  generateRecoveryCodes: () =>
    request('/api/recovery/codes', recoveryCodesSchema, { method: 'POST' }),
}
