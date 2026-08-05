import { useState } from 'react'
import { ShieldAlertIcon } from 'lucide-react'
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
            <p className="mb-1 text-xs font-medium text-muted-foreground">
              1. Sign this challenge on the machine holding the offline key
            </p>
            {/* Selectable and wrapped rather than truncated: this gets copied
                into a terminal, often under pressure. */}
            <code className="block w-full rounded-md border bg-muted p-3 text-xs break-all select-all">
              {challenge.data.command}
            </code>
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
