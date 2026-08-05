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
import { useLogin } from './useAuth'

export function LoginPage() {
  const login = useLogin()

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
            Sign in with your passkey. There is nothing to type.
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
