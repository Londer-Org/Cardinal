import { useEffect, useState } from 'react'
import { AlertTriangle, Check, TerminalSquare } from 'lucide-react'
import { api, ApiError, type DevicePending } from '@/lib/api'
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

  // Two flows arrive here. The loopback one carries a callback in the URL; the
  // device one carries a code, or nothing at all when somebody opened the page
  // and is about to type one.
  //
  // Told apart by what is present rather than by a mode parameter, because the
  // terminal decides which flow it is running and the page should not need to
  // be told twice.
  if (!callback) {
    return <DeviceApproval initialCode={params.get('code') ?? ''} />
  }

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

/**
 * Approving a terminal that is somewhere else.
 *
 * The loopback flow's best property is that approval is delivered to the
 * machine that asked, so nobody can talk you into approving *their* terminal.
 * This flow gives that up — it exists because a terminal on a server you are
 * SSH'd into has no loopback you can reach — so the screen has to carry the
 * weight instead.
 *
 * Hence what it shows: the address the request came from as the *server* saw
 * it, and never a name the terminal chose. "Approve the code from web-01" is
 * exactly the sentence somebody running this attack would like to arrange, and
 * a self-reported hostname would hand it to them.
 */
function DeviceApproval({ initialCode }: { initialCode: string }) {
  const [code, setCode] = useState(initialCode)
  const [pending, setPending] = useState<DevicePending | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState(false)

  async function look() {
    setBusy(true)
    setError(null)
    try {
      setPending(await api.auth.pendingDevice(code))
    } catch (err) {
      setPending(null)
      setError(
        err instanceof ApiError
          ? err.message
          : 'No request is waiting for that code.',
      )
    } finally {
      setBusy(false)
    }
  }

  async function approve() {
    setBusy(true)
    setError(null)
    try {
      await api.auth.approveDevice(code)
      setDone(true)
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not approve the terminal. Nothing was granted.',
      )
    } finally {
      setBusy(false)
    }
  }

  // Looked up once on arrival when the code came in the link. Deliberately not
  // re-run as the field changes: the lookup is rate-limited, and firing one per
  // keystroke would turn that limit into a wall for somebody typing.
  useEffect(() => {
    if (initialCode) void look()
  }, [initialCode])

  if (done) {
    return (
      <div className="mx-auto max-w-xl space-y-4">
        <ViewHeader title="Sign in a terminal" />
        <Alert>
          <Check className="size-4" />
          <AlertTitle>Approved</AlertTitle>
          <AlertDescription>
            The terminal is collecting its session now. You can close this page.
          </AlertDescription>
        </Alert>
      </div>
    )
  }

  return (
    <div className="mx-auto max-w-xl space-y-6">
      <ViewHeader
        title="Sign in a terminal"
        description="Enter the code the terminal printed."
      />

      <div className="flex gap-2">
        <input
          className="w-48 rounded-md border bg-background px-3 py-2 font-mono text-lg tracking-widest"
          value={code}
          onChange={(e) => {
            setCode(e.target.value)
            setPending(null)
          }}
          placeholder="XXXX-XXXX"
          aria-label="Code from the terminal"
        />
        <Button
          variant="outline"
          onClick={() => void look()}
          disabled={busy || code.length < 8}
        >
          {busy ? 'Checking…' : 'Check'}
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {pending && (
        <>
          <div className="rounded-lg border p-4">
            <div className="flex items-start gap-3">
              <TerminalSquare className="mt-0.5 size-5 shrink-0 text-muted-foreground" />
              <div className="space-y-3 text-sm">
                <p>
                  A terminal at{' '}
                  <code className="font-mono">
                    {pending.requestedFrom || 'an address this server could not read'}
                  </code>{' '}
                  is asking to act as you. It will receive a session carrying{' '}
                  <strong>the same passkey you signed in with</strong>.
                </p>
                <p className="text-muted-foreground">
                  That address is what this server saw the request come from. It
                  is not a name the terminal chose, because a name it chose
                  could say anything.
                </p>
              </div>
            </div>
          </div>

          <Alert variant="destructive">
            <AlertTriangle className="size-4" />
            <AlertTitle>Only approve a code you are looking at</AlertTitle>
            <AlertDescription>
              You should have just run a command and be reading this code off
              your own screen. If somebody sent it to you — in a message, on a
              call, in a ticket — approving it signs <em>their</em> terminal in
              as you.
            </AlertDescription>
          </Alert>

          <Button onClick={() => void approve()} disabled={busy}>
            {busy ? 'Approving…' : 'Approve this terminal'}
          </Button>
        </>
      )}
    </div>
  )
}
