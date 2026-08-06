import { useEffect, useState } from 'react'
import { api } from '@/lib/api'

/**
 * Resumes an OpenID Connect authorization after sign-in.
 *
 * When an application sends someone to Cardinal, the provider parks the
 * authorization request and redirects here with `?oidc_auth=<id>`. Once they
 * have a session, that request has to be completed and the browser handed back
 * to the provider — otherwise sign-in appears to work and simply stops,
 * stranding the user on their own account page with no idea the application is
 * still waiting.
 */

/** Reads the pending authorization id from the URL, if any. */
export function pendingAuthorizationID(): string | null {
  return new URLSearchParams(window.location.search).get('oidc_auth')
}

export type ResumeState =
  | { status: 'idle' }
  | { status: 'resuming' }
  | { status: 'failed'; message: string }

/**
 * Completes a pending authorization once a session exists.
 *
 * Returns a state rather than rendering anything, so the caller decides what to
 * show. On success nothing is returned at all: the browser has already been
 * sent onwards.
 */
export function useOIDCResume(isSignedIn: boolean): ResumeState {
  const [state, setState] = useState<ResumeState>({ status: 'idle' })

  useEffect(() => {
    const authID = pendingAuthorizationID()
    if (authID === null || !isSignedIn || state.status !== 'idle') {
      return
    }

    setState({ status: 'resuming' })

    void (async () => {
      try {
        const { continue: next } = await api.auth.oidcResume(authID)

        // A full navigation, not a client-side route change: the destination
        // belongs to the OIDC provider, which is server-rendered and will
        // redirect onwards to the application. Treating it as an SPA route
        // would leave the browser here.
        window.location.replace(next)
      } catch (error) {
        // Landing back on the account page with no explanation would leave
        // someone wondering why the application they came from never loaded.
        setState({
          status: 'failed',
          message:
            error instanceof Error
              ? error.message
              : 'The sign-in request could not be completed.',
        })
      }
    })()
  }, [isSignedIn, state.status])

  return state
}
