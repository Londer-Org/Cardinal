import { useParams } from '@tanstack/react-router'
import { useState } from 'react'
import { CircleSlashIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { GrantForm } from '@/features/directory/GrantForm'
import { GrantPeriod } from '@/features/directory/GrantPeriod'
import { InvitationPanel } from '@/features/directory/InvitationPanel'
import {
  useDisableUser,
  useEnableUser,
  useRevokeMembership,
  useUser,
} from '@/features/directory/useDirectory'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

function UserDetailViewBody() {
  const { login } = useParams({ from: '/directory/people/$login' })
  const { data: user, isPending, error } = useUser(login)
  const disable = useDisableUser()
  const enable = useEnableUser()
  const revoke = useRevokeMembership()
  const [confirming, setConfirming] = useState(false)

  if (error) {
    return <ErrorMessage error={error} />
  }
  if (isPending) {
    return <Skeleton className="h-64 w-full" />
  }

  return (
    <div className="space-y-4">
      <ViewHeader
        title={user.displayName || user.login}
        description={user.email === '' ? user.login : `${user.login} · ${user.email}`}
      />

      {/* Said at the top, not only in the card that offers the reverse. Every
          control below — granting a group, issuing an enrollment link — still
          works on a disabled account and none of it takes effect while they
          cannot sign in, which is confusing to discover afterwards.

          The border and the icon carry the colour and the text does not: in
          dark mode --destructive as text is 4.20:1 against the card, below AA,
          and an alert whose every word is red is shouting anyway. */}
      {user.disabled && (
        <Alert className="border-destructive/50 [&>svg]:text-destructive">
          <CircleSlashIcon />
          <AlertTitle>This account is disabled</AlertTitle>
          <AlertDescription>
            Nobody can sign in to it, and nothing granted below applies until it
            is enabled again.
          </AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Groups</CardTitle>
            <CardDescription>
              Direct memberships. What policy reads.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {user.memberships.length === 0 ? (
              <p className="text-sm text-muted-foreground">None.</p>
            ) : (
              <ul className="divide-y">
                {user.memberships.map((grant) => (
                  <li
                    key={grant.group}
                    className="flex items-center justify-between gap-2 py-2"
                  >
                    <span className="min-w-0 text-sm">
                      <span className="font-medium">{grant.group}</span>
                      <GrantPeriod grant={grant} />
                    </span>
                    <Button
                      variant="ghost"
                      size="sm"
                      disabled={revoke.isPending}
                      onClick={() => {
                        revoke.mutate({ group: grant.group, member: login })
                      }}
                    >
                      Revoke
                    </Button>
                  </li>
                ))}
              </ul>
            )}

            <ErrorMessage error={revoke.error} />
            <GrantForm
              member={login}
              alreadyIn={user.memberships.map((m) => m.group)}
            />
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Sign-in</CardTitle>
              <CardDescription>
                {user.credentials === 0
                  ? 'Nobody can sign in to this account yet.'
                  : `${String(user.credentials)} ${user.credentials === 1 ? 'passkey' : 'passkeys'} registered.`}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {user.credentials > 0 && !user.fullyEnrolled && (
                <Badge variant="secondary" className="font-normal">
                  One passkey — losing that device loses the account
                </Badge>
              )}
              <InvitationPanel user={user} />
            </CardContent>
          </Card>

          <Card className={user.disabled ? 'border-destructive/50' : undefined}>
            <CardHeader>
              <CardTitle>{user.disabled ? 'Account status' : 'Danger zone'}</CardTitle>
            </CardHeader>
            <CardContent>
              <ErrorMessage error={disable.error} />
              <ErrorMessage error={enable.error} />
              {user.disabled ? (
                // Not a danger zone any more: this account is already cut off,
                // and the only thing left to do here is the reverse. Offering
                // "Disable" against a disabled account was the shape this had
                // before there was a way back at all.
                <div className="space-y-3">
                  <p className="text-sm text-muted-foreground">
                    Disabled. They cannot sign in, and nothing they hold applies.
                    History and past grants are kept.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={enable.isPending}
                    onClick={() => { enable.mutate(login) }}
                  >
                    {enable.isPending ? 'Enabling…' : 'Enable account'}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    Sessions and access tokens were revoked when this was
                    disabled and do not come back — they will sign in again.
                  </p>
                </div>
              ) : confirming ? (
                <div className="rounded-md border border-destructive/50 p-3">
                  <p className="text-sm font-medium">Disable {user.login}?</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    They can no longer sign in, and their sessions and access
                    tokens end immediately. The account is kept so past grants
                    and audit records still resolve, and this can be undone —
                    though those credentials do not come back.
                  </p>
                  <div className="mt-3 flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => { setConfirming(false) }}
                    >
                      Cancel
                    </Button>
                    <Button
                      variant="destructive"
                      size="sm"
                      disabled={disable.isPending}
                      onClick={() => {
                        disable.mutate(login, {
                          onSuccess: () => { setConfirming(false) },
                        })
                      }}
                    >
                      {disable.isPending ? 'Disabling…' : 'Disable'}
                    </Button>
                  </div>
                </div>
              ) : (
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-destructive"
                  onClick={() => { setConfirming(true) }}
                >
                  Disable account
                </Button>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}

/**
 * Guarded, so arriving here with a stale session shows what is needed rather
 * than firing requests that will be refused — which produced an empty table
 * under the words "Nobody yet.", a statement about the directory and a false
 * one.
 */
export function UserDetailView() {
  return (
    <RequiresFreshAuth>
      <UserDetailViewBody />
    </RequiresFreshAuth>
  )
}
