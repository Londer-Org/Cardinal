import { useCallback, useEffect, useState } from 'react'
import { api, type PendingAuthorization } from '@/lib/api'

/**
 * Resumes an OpenID Connect authorization after sign-in.
 *
 * When an application sends someone to Cardinal, the provider parks the
 * authorization request and redirects here with `?oidc_auth=<id>`. Once they
 * have a session, that request has to be completed and the browser handed back
 * to the provider — otherwise sign-in appears to work and simply stops,
 * stranding the user on their own account page with no idea the application is
 * still waiting.
 *
 * Most applications resume silently. One registered with `-consent` stops here
 * first and asks.
 */

/** Reads the pending authorization id from the URL, if any. */
export function pendingAuthorizationID(): string | null {
  return new URLSearchParams(window.location.search).get('oidc_auth')
}

export type ResumeState =
  | { status: 'idle' }
  | { status: 'resuming' }
  | { status: 'consent'; pending: PendingAuthorization }
  | { status: 'refused'; application: string }
  | { status: 'denied'; application: string; reason: string; policies: string[] }
  | { status: 'failed'; message: string }

export interface Resume {
  state: ResumeState
  /** Records the user's answer. Approving continues the flow. */
  decide: (approve: boolean) => void
  deciding: boolean
}

function messageOf(error: unknown): string {
  return error instanceof Error
    ? error.message
    : 'The sign-in request could not be completed.'
}

/**
 * Completes a pending authorization once a session exists.
 *
 * Returns a state rather than rendering anything, so the caller decides what to
 * show. On success nothing is returned at all: the browser has already been
 * sent onwards.
 */
export function useOIDCResume(isSignedIn: boolean): Resume {
  const [state, setState] = useState<ResumeState>({ status: 'idle' })
  const [deciding, setDeciding] = useState(false)

  // A full navigation, not a client-side route change: the destination belongs
  // to the OIDC provider, which is server-rendered and will redirect onwards to
  // the application. Treating it as an SPA route would leave the browser here.
  const complete = useCallback(async (authID: string) => {
    const { continue: next } = await api.auth.oidcResume(authID)
    window.location.replace(next)
  }, [])

  useEffect(() => {
    const authID = pendingAuthorizationID()
    if (authID === null || !isSignedIn || state.status !== 'idle') {
      return
    }

    setState({ status: 'resuming' })

    void (async () => {
      try {
        // Ask what this is before doing anything with it. Resuming first and
        // asking afterwards would mean the claims were already released by the
        // time the question appeared.
        const pending = await api.auth.oidcPending(authID)
        if (pending.denied) {
          // Policy said no. Distinct from a failure: nothing is broken, and
          // telling someone to try again would waste their time.
          setState({
            status: 'denied',
            application: pending.application,
            reason: pending.deniedReason ?? 'You do not have access to this application.',
            policies: pending.deniedBy ?? [],
          })
          return
        }
        if (pending.needsConsent) {
          setState({ status: 'consent', pending })
          return
        }
        await complete(authID)
      } catch (error) {
        // Landing back on the account page with no explanation would leave
        // someone wondering why the application they came from never loaded.
        setState({ status: 'failed', message: messageOf(error) })
      }
    })()
  }, [isSignedIn, state.status, complete])

  const decide = useCallback((approve: boolean) => {
    const authID = pendingAuthorizationID()
    if (authID === null || state.status !== 'consent') {
      return
    }
    const application = state.pending.application

    setDeciding(true)
    void (async () => {
      try {
        await api.auth.oidcConsent(authID, approve)
        if (!approve) {
          // The user stays here rather than being bounced back to the
          // application. Redirecting to something they just declined to use
          // would read as the refusal not having worked.
          setState({ status: 'refused', application })
          return
        }
        setState({ status: 'resuming' })
        await complete(authID)
      } catch (error) {
        setState({ status: 'failed', message: messageOf(error) })
      } finally {
        setDeciding(false)
      }
    })()
  }, [state, complete])

  return { state, decide, deciding }
}
