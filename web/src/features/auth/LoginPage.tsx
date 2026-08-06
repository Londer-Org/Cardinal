import { useState } from 'react'
import { KeyRoundIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { ErrorMessage } from '@/components/ErrorMessage'
import { isSupported } from '@/lib/webauthn'
import { BreakGlassDialog } from './BreakGlassDialog'
import { useLogin } from './useAuth'

export function LoginPage({
  continuingToApplication = false,
}: {
  /** True when an application sent the user here to sign in. */
  continuingToApplication?: boolean
}) {
  const login = useLogin()
  const [emergency, setEmergency] = useState(false)

  if (!isSupported()) {
    return (
      <Shell>
        <Card>
          <CardHeader>
            <CardTitle>Cardinal</CardTitle>
          </CardHeader>
          <CardContent>
            <Alert variant="destructive">
              <ShieldAlertIcon />
              <AlertTitle>Passkeys are not available</AlertTitle>
              <AlertDescription>
                Cardinal has no passwords, so a browser supporting WebAuthn is
                required to sign in.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </Shell>
    )
  }

  return (
    <Shell>
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Cardinal</CardTitle>
          <CardDescription>
            {continuingToApplication
              ? 'An application needs you to sign in. Use your passkey — there is nothing to type.'
              : 'Sign in with your passkey. There is nothing to type.'}
          </CardDescription>
        </CardHeader>

        <CardContent>
          <Button
            className="w-full"
            size="lg"
            onClick={() => { login.mutate() }}
            disabled={login.isPending}
          >
            <KeyRoundIcon />
            {login.isPending ? 'Waiting for your device…' : 'Sign in'}
          </Button>

          <ErrorMessage error={login.error} />

          {emergency ? (
            <BreakGlassDialog onClose={() => { setEmergency(false) }} />
          ) : (
            <button
              type="button"
              onClick={() => { setEmergency(true) }}
              className="mt-6 w-full text-center text-xs text-muted-foreground underline-offset-4 hover:underline"
            >
              Emergency access
            </button>
          )}
        </CardContent>
      </Card>
    </Shell>
  )
}

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
