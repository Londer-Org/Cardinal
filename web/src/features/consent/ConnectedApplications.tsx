import { AppWindowIcon } from 'lucide-react'
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
import type { Consent } from '@/lib/api'
import { useConsents, useRevokeConsent } from './useConsents'

/**
 * What the user has agreed to, and how to take it back.
 *
 * Consent without this screen is a click that cannot be undone, which makes the
 * prompt theatre. Withdrawal here also revokes the application's tokens
 * server-side — otherwise it would keep working for the rest of their lifetime,
 * which is precisely what the user just asked it not to do.
 */
export function ConnectedApplications() {
  const { data: consents, isPending, error } = useConsents()
  const revoke = useRevokeConsent()

  const items = consents ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Connected applications</CardTitle>
        <CardDescription>
          Applications you have allowed to see your account details.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {error !== null && <ErrorMessage error={error} />}

        {isPending ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">
            {/* Empty is the normal state, not a problem. Most applications here
                are run by the same organisation and never ask. */}
            None yet. Applications run internally sign you in without asking.
          </p>
        ) : (
          <ul className="divide-y">
            {items.map((consent) => (
              <ApplicationRow
                key={consent.clientId}
                consent={consent}
                isRevoking={revoke.isPending}
                onRevoke={() => { revoke.mutate(consent.clientId) }}
              />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function ApplicationRow({
  consent,
  isRevoking,
  onRevoke,
}: {
  consent: Consent
  isRevoking: boolean
  onRevoke: () => void
}) {
  return (
    <li className="flex items-start justify-between gap-4 py-3">
      <div className="flex min-w-0 gap-3">
        <AppWindowIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{consent.application}</p>
          <p className="text-xs text-muted-foreground">
            Allowed{' '}
            {new Date(consent.grantedAt).toLocaleDateString(undefined, {
              year: 'numeric',
              month: 'short',
              day: 'numeric',
            })}
          </p>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {consent.scopes.map((scope) => (
              <Badge key={scope.scope} variant="secondary" className="font-normal">
                {scope.description}
              </Badge>
            ))}
          </div>
        </div>
      </div>

      <Button
        variant="ghost"
        size="sm"
        onClick={onRevoke}
        disabled={isRevoking}
      >
        Withdraw
      </Button>
    </li>
  )
}
