import type { z } from 'zod'
import { errorSchema } from './schemas'

/** A failed API call, carrying the status so callers can distinguish 401 from 429. */
export class ApiError extends Error {
  readonly status: number

  /** Policy IDs that produced a refusal, when the server named any. */
  readonly policy: string[]

  constructor(status: number, message: string, policy: string[] = []) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.policy = policy
  }

  /** True when the session has gone — the UI should return to the login screen. */
  get isUnauthenticated(): boolean {
    return this.status === 401
  }

  /**
   * True when the only thing missing is a recent, device-bound credential.
   *
   * Distinguished from every other refusal because it is the one the user can
   * fix, in about two seconds, by touching a key. Anything else is a permission
   * they do not have, and offering them a key would be a lie.
   */
  get needsStepUp(): boolean {
    return (
      this.status === 403 &&
      this.policy.includes('admin-requires-fresh-device-bound-auth')
    )
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
    const error = new ApiError(
      response.status,
      parsed.success ? parsed.data.error : `Request failed (${response.status}).`,
      policyOf(body),
    )
    if (error.needsStepUp) {
      // Announced rather than handled here: this module knows nothing about
      // React, and the alternative is every caller remembering to check.
      stepUpNeeded()
    }
    throw error
  }

  // The single place `unknown` is allowed to exist. Past this line everything is
  // typed, and a server change that breaks the contract fails loudly here rather
  // than surfacing as `undefined` three components away.
  return schema.parse(body)
}

/** Reads the policy IDs a refusal named, if it named any. */
function policyOf(body: unknown): string[] {
  if (typeof body !== 'object' || body === null) return []
  const policy = (body as { policy?: unknown }).policy
  if (!Array.isArray(policy)) return []
  return policy.filter((id): id is string => typeof id === 'string')
}

type StepUpListener = () => void
const stepUpListeners = new Set<StepUpListener>()

/**
 * Called whenever a request is refused for want of a fresh credential.
 *
 * A module-level registry rather than a React context, because the thing that
 * detects this is a fetch wrapper with no component around it — and threading a
 * callback through every query and mutation would mean each one remembering.
 */
function stepUpNeeded() {
  for (const listener of stepUpListeners) listener()
}

export function onStepUpNeeded(listener: StepUpListener): () => void {
  stepUpListeners.add(listener)
  return () => stepUpListeners.delete(listener)
}

/**
 * Asks for the step-up dialog deliberately.
 *
 * The same signal a refused request raises, so there is one way in whether the
 * prompt was provoked by the server or by somebody pressing a button.
 */
export function requestStepUp() {
  stepUpNeeded()
}
