import { useState, type SyntheticEvent } from 'react'
import { AlertTriangle, KeyRound } from 'lucide-react'
import { api, ApiError } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Alert, AlertDescription } from '@/components/ui/alert'

/**
 * Getting back in without a passkey.
 *
 * The screen a person reaches on their worst day: the laptop is gone, or the
 * phone is, and what they have is a sheet of paper. So it asks for two things
 * and explains the one consequence, and does not otherwise get in the way.
 *
 * On success it sends them to the enrollment page — the same one an invitation
 * leads to. That is deliberate rather than convenient: a recovery code buys the
 * chance to register a credential, not the ability to act as the account, and
 * the enrollment path is the tested way to do exactly that.
 */
export function RecoverPage() {
  const [login, setLogin] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(event: SyntheticEvent) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const { token } = await api.redeemRecoveryCode(login.trim(), code.trim())
      // Replace rather than push: the code is spent, so going back to this form
      // and submitting it again can only fail, and confusingly.
      window.location.replace(`/enroll?token=${encodeURIComponent(token)}`)
    } catch (err) {
      setError(
        err instanceof ApiError
          ? err.message
          : 'Could not check that code. Try again in a moment.',
      )
      setBusy(false)
    }
  }

  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <form
        onSubmit={(e) => void submit(e)}
        className="w-full max-w-sm space-y-5 rounded-lg border p-6"
      >
        <div className="space-y-1">
          <h1 className="flex items-center gap-2 text-lg font-semibold">
            <KeyRound className="size-5" />
            Use a recovery code
          </h1>
          <p className="text-sm text-muted-foreground">
            For when you cannot use your passkey. You will set up a new one
            straight after.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="login">Your login</Label>
          <Input
            id="login"
            autoComplete="username"
            autoFocus
            value={login}
            onChange={(e) => {
              setLogin(e.target.value)
            }}
            required
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="code">Recovery code</Label>
          <Input
            id="code"
            className="font-mono"
            placeholder="XXXXX-XXXXX-XXXXX"
            value={code}
            onChange={(e) => {
              setCode(e.target.value)
            }}
            required
          />
          <p className="text-xs text-muted-foreground">
            Each code works once. Cross it off the sheet after using it.
          </p>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="size-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Button type="submit" className="w-full" disabled={busy}>
          {busy ? 'Checking…' : 'Continue'}
        </Button>

        <p className="text-xs text-muted-foreground">
          Out of codes? An administrator can restore your account, and it takes
          two of them to agree.
        </p>
      </form>
    </div>
  )
}

/** True when the browser is on the recovery page. */
export function isRecoveryPath(): boolean {
  return window.location.pathname === '/recover'
}
