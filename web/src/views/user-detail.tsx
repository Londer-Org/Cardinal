import { useNavigate, useParams } from '@tanstack/react-router'
import { useState } from 'react'
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
  useRevokeMembership,
  useUser,
} from '@/features/directory/useDirectory'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

function UserDetailViewBody() {
  const { login } = useParams({ from: '/directory/people/$login' })
  const { data: user, isPending, error } = useUser(login)
  const disable = useDisableUser()
  const revoke = useRevokeMembership()
  const navigate = useNavigate()
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

          <Card>
            <CardHeader>
              <CardTitle>Danger zone</CardTitle>
            </CardHeader>
            <CardContent>
              <ErrorMessage error={disable.error} />
              {confirming ? (
                <div className="rounded-md border border-destructive/50 p-3">
                  <p className="text-sm font-medium">Disable {user.login}?</p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    They can no longer sign in, and their sessions end
                    immediately. The account is kept so past grants and audit
                    records still resolve.
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
                          onSuccess: () => {
                            void navigate({ to: '/directory/people' })
                          },
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
