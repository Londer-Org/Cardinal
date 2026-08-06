import type { z } from 'zod'
import { errorSchema } from './schemas'

/** A failed API call, carrying the status so callers can distinguish 401 from 429. */
export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }

  /** True when the session has gone — the UI should return to the login screen. */
  get isUnauthenticated(): boolean {
    return this.status === 401
  }
}

/**
 * Reads the CSRF cookie the server set.
 *
 * Deliberately readable by script, unlike the session cookie: it is not a
 * credential on its own. Double-submit works because an attacker's page can
 * make the browser *send* the cookie but cannot *read* it to set the matching
 * header.
 */
function csrfToken(): string {
  const match = /(?:^|;\s*)cardinal_csrf=([^;]*)/.exec(document.cookie)
  return match?.[1] ? decodeURIComponent(match[1]) : ''
}

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE'
  body?: unknown
}

/** Issues a request and parses the response through `schema`. */
export async function request<T>(
  path: string,
  schema: z.ZodType<T>,
  options: RequestOptions = {},
): Promise<T> {
  const method = options.method ?? 'GET'
  const headers = new Headers({ Accept: 'application/json' })

  if (options.body !== undefined) {
    headers.set('Content-Type', 'application/json')
  }
  if (method !== 'GET') {
    headers.set('X-Cardinal-CSRF', csrfToken())
  }

  const response = await fetch(path, {
    method,
    headers,
    // Cookies are the entire authentication mechanism. same-origin rather than
    // include: there is no cross-origin case, so allowing one would only widen
    // what a mistake could reach.
    credentials: 'same-origin',
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  })

  if (response.status === 204) {
    return schema.parse(undefined)
  }

  const body: unknown = await response.json().catch(() => null)

  if (!response.ok) {
    const parsed = errorSchema.safeParse(body)
    throw new ApiError(
      response.status,
      parsed.success ? parsed.data.error : `Request failed (${response.status}).`,
    )
  }

  // The single place `unknown` is allowed to exist. Past this line everything is
  // typed, and a server change that breaks the contract fails loudly here rather
  // than surfacing as `undefined` three components away.
  return schema.parse(body)
}
