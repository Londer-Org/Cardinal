import { LogOutIcon, ShieldQuestionIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ErrorMessage } from '@/components/ErrorMessage'
import { CardinalMark } from '@/components/CardinalMark'
import { ApplicationList } from '@/features/applications/ApplicationList'
import { ConnectedApplications } from '@/features/consent/ConnectedApplications'
import { CredentialList } from '@/features/credentials/CredentialList'
import { DecisionExplorer } from '@/features/decisions/DecisionExplorer'
import { RecoveryCodes } from '@/features/recovery/RecoveryCodes'
import type { Me } from '@/lib/api'
import { ProfileCard } from './ProfileCard'
import { useLogout } from './useAuth'

export function AccountPage({ session }: { session: Me }) {
  const logout = useLogout()

  return (
    <div className="min-h-dvh bg-background p-6">
      <div className="mx-auto max-w-3xl space-y-4">
        <header className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <CardinalMark className="size-9 shrink-0 text-foreground" />
            <div className="min-w-0">
              <h1 className="truncate text-xl font-semibold">
                {session.displayName || session.login}
              </h1>
              <p className="text-sm text-muted-foreground">{session.login}</p>
            </div>
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

        {/* A sign-out that fails leaves the session live, and the button
            simply re-enabling says nothing. Silence here is how "sign out did
            nothing" gets mistaken for "sign out worked". */}
        {logout.error !== null && <ErrorMessage error={logout.error} />}

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

        {/* Local tab state rather than a router.
            Two views do not justify a routing dependency; one arrives when
            deep-linking to a specific decision is actually wanted, which is the
            first thing that genuinely needs URLs. */}
        <Tabs defaultValue="account">
          <TabsList>
            <TabsTrigger value="account">Account</TabsTrigger>
            <TabsTrigger value="access">Access</TabsTrigger>
            {/* Hidden for everyone else, but that is presentation only: the
                endpoints behind it evaluate AdministerDirectory themselves. */}
            {session.canAdminister && (
              <TabsTrigger value="admin">Applications</TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="account" className="mt-4 space-y-4">
            <ProfileCard session={session} />
            <CredentialList />
            <RecoveryCodes remaining={session.recoveryCodesRemaining} />
          </TabsContent>

          <TabsContent value="access" className="mt-4 space-y-4">
            <ConnectedApplications />
            <DecisionExplorer />
          </TabsContent>

          {session.canAdminister && (
            <TabsContent value="admin" className="mt-4">
              <ApplicationList />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </div>
  )
}
