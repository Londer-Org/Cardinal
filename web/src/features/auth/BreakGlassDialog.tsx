import { useEffect, useRef, useState } from 'react'
import { CheckIcon, CopyIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useBreakGlass } from './useBreakGlass'

/**
 * Emergency access, and the only way to enrol a first passkey.
 *
 * Registering a credential needs a session; getting a session needs a
 * credential. The offline key breaks that circle — which means this is not only
 * an emergency path but the ordinary bootstrap one, and it is deliberately not
 * hidden behind a separate "setup mode" that someone could forget to disable.
 */
export function BreakGlassDialog({ onClose }: { onClose: () => void }) {
  const { challenge, begin, finish } = useBreakGlass()
  const [login, setLogin] = useState('')
  const [signature, setSignature] = useState('')

  return (
    <div className="mt-4">
      <Separator className="mb-4" />

      <Alert variant="destructive" className="mb-4">
        <ShieldAlertIcon />
        <AlertTitle>Emergency access</AlertTitle>
        <AlertDescription>
          Grants a 15-minute session using the offline break-glass key. Every use
          is recorded and should raise an alert. Use it to enrol your first
          passkey, then sign out.
        </AlertDescription>
      </Alert>

      {challenge.data === undefined ? (
        <div className="flex gap-2">
          <Button
            variant="outline"
            onClick={() => { begin.mutate() }}
            disabled={begin.isPending}
          >
            {begin.isPending ? 'Requesting…' : 'Request a challenge'}
          </Button>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
        </div>
      ) : (
        <form
          className="space-y-3"
          onSubmit={(event) => {
            event.preventDefault()
            finish.mutate({ challenge: challenge.data.challenge, signature, login })
          }}
        >
          <div>
            <div className="mb-1 flex items-baseline justify-between gap-2">
              <p className="text-xs font-medium text-muted-foreground">
                1. Sign this challenge on the machine holding the offline key
              </p>
              <Countdown
                expiresAt={challenge.data.expiresAt}
                onExpired={() => { challenge.reset() }}
              />
            </div>
            {/* Selectable and wrapped rather than truncated: this gets copied
                into a terminal, often under pressure. The copy button is not a
                nicety — the command is a hundred-odd characters of base64, and
                retyping it is how the challenge expires. */}
            <div className="flex items-start gap-2">
              <code className="block min-w-0 flex-1 rounded-md border bg-muted p-3 text-xs break-all select-all">
                {challenge.data.command}
              </code>
              <CopyButton value={challenge.data.command} />
            </div>
          </div>

          <div>
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              2. Paste the signature and the account to assume
            </p>
            <div className="space-y-2">
              <Input
                value={signature}
                onChange={(event) => { setSignature(event.target.value) }}
                placeholder="Signature"
                aria-label="Signature"
                autoComplete="off"
                spellCheck={false}
              />
              <Input
                value={login}
                onChange={(event) => { setLogin(event.target.value) }}
                placeholder="Account login"
                aria-label="Account login"
                autoComplete="off"
                spellCheck={false}
              />
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              type="submit"
              variant="destructive"
              disabled={finish.isPending || signature === '' || login === ''}
            >
              {finish.isPending ? 'Verifying…' : 'Open emergency session'}
            </Button>
            <Button type="button" variant="ghost" onClick={onClose}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      <ErrorMessage error={begin.error ?? finish.error} />
    </div>
  )
}

/**
 * How long the challenge has left.
 *
 * Shown because the alternative is what it replaced: a challenge that silently
 * stops working, an error that says "expired", and no way to have known. A
 * ceremony that involves walking to a safe should say how long you have before
 * you set off.
 */
function Countdown({
  expiresAt,
  onExpired,
}: {
  expiresAt: string
  onExpired: () => void
}) {
  const [remaining, setRemaining] = useState(() => secondsUntil(expiresAt))

  // Held in a ref because the caller passes an inline arrow, so its identity
  // changes every render. As an effect dependency that would tear down and
  // recreate the interval on every tick — which happens to still count, but
  // only by accident.
  const expired = useRef(onExpired)
  expired.current = onExpired

  useEffect(() => {
    const timer = setInterval(() => {
      const left = secondsUntil(expiresAt)
      setRemaining(left)
      if (left <= 0) {
        clearInterval(timer)
        // Back to the request button rather than leaving a dead command on
        // screen for someone to paste and be refused by.
        expired.current()
      }
    }, 1000)
    return () => { clearInterval(timer) }
  }, [expiresAt])

  const minutes = Math.floor(remaining / 60)
  const seconds = remaining % 60

  return (
    <span
      className={
        remaining <= 60
          ? 'shrink-0 text-xs font-medium text-destructive tabular-nums'
          : 'shrink-0 text-xs text-muted-foreground tabular-nums'
      }
    >
      {minutes}:{seconds.toString().padStart(2, '0')} left
    </span>
  )
}

function secondsUntil(iso: string): number {
  return Math.max(0, Math.floor((new Date(iso).getTime() - Date.now()) / 1000))
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      aria-label="Copy the command"
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => {
          setCopied(true)
          setTimeout(() => { setCopied(false) }, 2000)
        })
      }}
    >
      {copied ? <CheckIcon /> : <CopyIcon />}
      {copied ? 'Copied' : 'Copy'}
    </Button>
  )
}
