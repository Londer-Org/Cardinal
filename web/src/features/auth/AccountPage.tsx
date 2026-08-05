import { LogOutIcon, ShieldAlertIcon, ShieldQuestionIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { CredentialList } from '@/features/credentials/CredentialList'
import { RecoveryCodes } from '@/features/recovery/RecoveryCodes'
import type { Me } from '@/lib/api'
import { useLogout } from './useAuth'

export function AccountPage({ session }: { session: Me }) {
  const logout = useLogout()

  return (
    <div className="min-h-dvh bg-background p-6">
      <div className="mx-auto max-w-2xl space-y-4">
        <header className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <h1 className="truncate text-xl font-semibold">
              {session.displayName || session.login}
            </h1>
            <p className="text-sm text-muted-foreground">{session.login}</p>
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => { logout.mutate() }}
            disabled={logout.isPending}
          >
            <LogOutIcon />
            Sign out
          </Button>
        </header>

        {session.emergency && (
          <Alert variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>Emergency access in progress</AlertTitle>
            <AlertDescription>
              This session was opened with the break-glass key and is being
              audited. Restore normal access and sign out as soon as you can.
            </AlertDescription>
          </Alert>
        )}

        {/* A nudge, not a failure — hence warning rather than destructive.
            Colouring routine advice as an error trains people to ignore the
            colour that actually matters. */}
        {!session.fullyEnrolled && (
          <Alert className="border-warning/50 text-warning-foreground [&>svg]:text-warning">
            <ShieldQuestionIcon />
            <AlertTitle>Register a second passkey</AlertTitle>
            <AlertDescription>
              With only one, losing that device means losing the account. A
              hardware key kept somewhere else is the usual second.
            </AlertDescription>
          </Alert>
        )}

        <CredentialList />
        <RecoveryCodes remaining={session.recoveryCodesRemaining} />
      </div>
    </div>
  )
}
