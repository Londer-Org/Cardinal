import { Link } from '@tanstack/react-router'
import { useQuery } from '@tanstack/react-query'
import { MailIcon, TriangleAlertIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { api, queryKeys } from '@/lib/api'

function hoursLeft(iso: string): number {
  return Math.round((new Date(iso).getTime() - Date.now()) / 3_600_000)
}

/**
 * Every outstanding enrollment link, in one place.
 *
 * The endpoint existed and only the per-account view used it, so the question
 * this answers had no answer: which invitations are outstanding across the
 * fleet, and which have been sitting there long enough to suggest they never
 * arrived.
 *
 * That matters more than it sounds. An invitation is the one credential that
 * grants a passkey on an account, it is single-use and short-lived, and an
 * unredeemed one is either a person who cannot start work or a link sitting in
 * a mailbox somebody else can read.
 */
export function PendingInvitations() {
  const { data, isPending, error } = useQuery({
    queryKey: queryKeys.invitations,
    queryFn: api.invitations.list,
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Outstanding invitations</CardTitle>
        <CardDescription>
          Enrollment links nobody has used yet. Each grants one passkey on one
          account and expires on its own; issuing another supersedes it.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <ErrorMessage error={error} />

        {error !== null ? null : isPending ? (
          <Skeleton className="h-12 w-full" />
        ) : data.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            None outstanding — everybody invited has enrolled.
          </p>
        ) : (
          <ul>
            {data.map((invitation) => {
              const left = hoursLeft(invitation.expiresAt)
              return (
                <li
                  key={invitation.login}
                  className="flex flex-wrap items-center justify-between gap-2 border-b py-2 text-sm last:border-b-0"
                >
                  <span className="flex items-center gap-2">
                    <MailIcon className="size-4 shrink-0 text-muted-foreground" />
                    <Link
                      to="/directory/people/$login"
                      params={{ login: invitation.login }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {invitation.login}
                    </Link>
                    {invitation.displayName !== '' && (
                      <span className="text-muted-foreground">
                        {invitation.displayName}
                      </span>
                    )}
                  </span>

                  {left <= 2 ? (
                    // Near expiry is the actionable state: the person is about
                    // to need another link, and nobody finds out unless they
                    // ask. Two hours rather than "expired", because an expired
                    // one is no longer in this list at all.
                    <Badge variant="outline" className="font-normal text-destructive">
                      <TriangleAlertIcon />
                      {left <= 0 ? 'expiring now' : `${String(left)}h left`}
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      {left}h left
                    </span>
                  )}
                </li>
              )
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}
