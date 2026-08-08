import { useState } from 'react'
import { AlertTriangle, Check, TerminalSquare } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { ViewHeader } from '@/views/ViewHeader'

/**
 * Approving a terminal.
 *
 * The one screen in the console that exists to be arrived at from somewhere
 * else, and the only one where the safe answer is usually "no". A person sees
 * it because a process on some machine asked them to — and if they did not
 * start that process, this page is the last thing between it and a device-bound
 * session.
 *
 * So it says what is being granted rather than asking for a confirmation. The
 * decision is only meaningful if the two facts that matter are legible: which
 * terminal, and what it will be able to do.
 */
export function CLILoginView() {
  const params = new URLSearchParams(window.location.search)
  const callback = params.get('callback') ?? ''
  const state = params.get('state') ?? ''
  const verifierHash = params.get('verifier_hash') ?? ''

  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  // Checked here as well as on the server, because the server's answer arrives
  // after the request and this is a page somebody may have been sent to.
  const port = loopbackPort(callback)
  const malformed = port === null || verifierHash.length < 43

  async function approve() {
    setBusy(true)
    setError(null)
    try {
      const { code } = await api.auth.authorizeCLI(callback, verifierHash)
      setDone(true)
      // The code travels in the URL, which is exactly why it is a code and not
      // a session token: it is single-use, expires in ninety seconds, and is
      // worthless without the verifier the terminal never sent anywhere.
      const target = new URL(callback)
      target.searchParams.set('code', code)
      if (state) target.searchParams.set('state', state)
      window.location.replace(target.toString())
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not approve the terminal. Nothing was granted.',
      )
      setBusy(false)
    }
  }

  if (malformed) {
    return (
      <div className="mx-auto max-w-xl space-y-4">
        <ViewHeader title="Sign in a terminal" />
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>This request is not usable</AlertTitle>
          <AlertDescription>
            A terminal sign-in must come back to a loopback address on this
            machine. This one names{' '}
            <code className="font-mono">{callback || 'nothing'}</code>, so
            nothing has been granted. If you did not start this, you can close
            the page — arriving here does not authorise anything by itself.
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <ViewHeader
        title="Sign in a terminal"
        description="A program on this machine is asking to act as you."
      />

      <div className="rounded-lg border p-4">
        <div className="flex items-start gap-3">
          <TerminalSquare className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
          <div className="space-y-3 text-sm">
            <p>
              It will receive a session that carries{' '}
              <strong>the same passkey you signed in with</strong> — not a
              weaker credential. That is what lets it request SSH certificates
              for machines you may reach.
            </p>
            <ul className="list-disc space-y-1 pl-5 text-muted-foreground">
              <li>
                Returns to <code className="font-mono">127.0.0.1:{port}</code>{' '}
                on this machine, and nowhere else
              </li>
              <li>Expires in ten minutes, whether it is used or not</li>
              <li>
                Ends immediately if you sign out everywhere, like any other
                session
              </li>
            </ul>
          </div>
        </div>
      </div>

      <Alert>
        <AlertTriangle className="size-4" />
        <AlertTitle>Only approve this if you started it</AlertTitle>
        <AlertDescription>
          You should have just run a command such as{' '}
          <code className="font-mono">cardinal ssh</code>. If you did not, close
          this page. Nothing is granted until you approve.
        </AlertDescription>
      </Alert>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="flex gap-3">
        <Button onClick={() => void approve()} disabled={busy || done}>
          {done ? (
            <>
              <Check className="size-4" /> Approved — returning to the terminal
            </>
          ) : busy ? (
            'Approving…'
          ) : (
            'Approve this terminal'
          )}
        </Button>
        <Button
          variant="outline"
          onClick={() => {
            window.close()
          }}
          disabled={busy || done}
        >
          Cancel
        </Button>
      </div>
    </div>
  )
}

/**
 * The port, if the callback is a loopback address.
 *
 * By literal address rather than by name. "localhost" is something another
 * resolver can answer, and this is the URL a code is about to be handed to.
 */
function loopbackPort(raw: string): string | null {
  if (!raw) return null
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return null
  }
  if (url.protocol !== 'http:') return null
  if (url.hostname !== '127.0.0.1' && url.hostname !== '[::1]') return null
  return url.port || null
}
