import { Link, useParams } from '@tanstack/react-router'
import { ShieldIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import { GrantPeriod } from '@/features/directory/GrantPeriod'
import { useGroup, useRevokeMembership } from '@/features/directory/useDirectory'
import { ViewHeader } from '@/views/ViewHeader'

export function GroupDetailView() {
  const { name } = useParams({ from: '/admin/groups/$name' })
  const { data: group, isPending, error } = useGroup(name)
  const revoke = useRevokeMembership()

  if (error) {
    return <ErrorMessage error={error} />
  }
  if (isPending) {
    return <Skeleton className="h-64 w-full" />
  }

  return (
    <div className="space-y-4">
      <ViewHeader
        title={group.name}
        description={group.displayName === '' ? undefined : group.displayName}
      />

      {group.system && (
        <Alert>
          <ShieldIcon />
          <AlertTitle>System group</AlertTitle>
          <AlertDescription>
            Membership confers authority within Cardinal, so changing it needs
            full directory administration — managing people is not enough to
            make somebody an administrator.
          </AlertDescription>
        </Alert>
      )}

      {group.owner !== '' && (
        <p className="text-sm text-muted-foreground">
          Exists for the <span className="font-medium">{group.owner}</span>{' '}
          application. Cardinal treats it like any other group and sends it in
          that application's groups claim.
        </p>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Members</CardTitle>
          <CardDescription>
            As of now. A grant that has run out stops counting without anything
            having run.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <ErrorMessage error={revoke.error} />

          {group.members.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              {/* Distinguished from "never had any": an expired grant leaves no
                  member but does leave history. */}
              Nobody is a member right now. Expired grants keep their history.
            </p>
          ) : (
            <ul className="divide-y">
              {group.members.map((grant) => (
                <li
                  key={grant.member}
                  className="flex items-center justify-between gap-2 py-2"
                >
                  <span className="min-w-0 text-sm">
                    <Link
                      to="/admin/users/$login"
                      params={{ login: grant.member }}
                      className="font-medium hover:underline"
                    >
                      {grant.member}
                    </Link>
                    <GrantPeriod grant={grant} />
                    {grant.reason !== '' && (
                      <span className="ml-2 text-muted-foreground">
                        · {grant.reason}
                      </span>
                    )}
                  </span>
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={revoke.isPending}
                    onClick={() => {
                      revoke.mutate({ group: name, member: grant.member })
                    }}
                  >
                    Revoke
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
