import { useState } from 'react'
import { Link } from '@tanstack/react-router'
import {
  ShieldAlertIcon,
  ShieldCheckIcon,
  UserXIcon,
} from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useAuditEvents, useVerifyChain } from '@/features/audit/useAudit'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'
import type { AuditEvent, AuditParty } from '@/lib/api'

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'medium',
  })
}

/**
 * One side of an entry — what it was about, or who caused it.
 *
 * Links where it can. The journal stores identifiers and nothing else, so the
 * name here comes from the directory at read time; for a user or a host that
 * means the page about them is one click away, which is the question somebody
 * reading a journal entry usually has next.
 */
function Party({ party }: { party: AuditParty | null }) {
  if (party === null) {
    return <span className="text-muted-foreground">—</span>
  }
  if (party.redacted) {
    return (
      <span className="inline-flex items-center gap-1 text-muted-foreground">
        <UserXIcon className="size-3.5" />
        erased
      </span>
    )
  }

  if (party.type === 'user') {
    return (
      <Link
        to="/directory/people/$login"
        params={{ login: party.name }}
        className="underline-offset-4 hover:underline"
      >
        {party.name}
      </Link>
    )
  }
  if (party.type === 'host') {
    return (
      <Link
        to="/directory/hosts/$name"
        params={{ name: party.name }}
        className="underline-offset-4 hover:underline"
      >
        {party.name}
      </Link>
    )
  }
  return <span>{party.name}</span>
}

function Entry({ event }: { event: AuditEvent }) {
  const payload = Object.entries(event.payload)

  return (
    <li className="border-b py-3 last:border-b-0">
      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1 text-sm">
        <code className="font-mono text-xs text-muted-foreground">
          #{event.seq}
        </code>
        <span className="font-medium">{event.action}</span>
        <span className="text-muted-foreground">
          <Party party={event.subject} />
          {event.actor !== null &&
            event.actor.id !== event.subject?.id && (
              <>
                {' by '}
                <Party party={event.actor} />
              </>
            )}
        </span>
      </div>

      <p className="mt-0.5 text-xs text-muted-foreground">{when(event.occurredAt)}</p>

      {payload.length > 0 && (
        <dl className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted-foreground">
          {payload.map(([key, value]) => (
            <div key={key} className="flex gap-1">
              <dt className="font-medium">{key}</dt>
              <dd className="font-mono">{String(value)}</dd>
            </div>
          ))}
        </dl>
      )}
    </li>
  )
}

/**
 * Chain verification, on demand.
 *
 * The thing that makes this a journal rather than a log. A PostgreSQL restore
 * tells you the data came back; this tells you nobody altered it — which is
 * worth having in front of whoever has just restored from backup, rather than
 * only in a CLI they would have to find a shell for.
 */
function Chain() {
  const verify = useVerifyChain()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Integrity</CardTitle>
        <CardDescription>
          Every entry carries the hash of the one before it, so altering or
          removing any of them breaks the chain detectably. The journal is
          append-only and enforced as such by database rules — a broken chain
          means something wrote to it outside Cardinal.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-3">
        <ErrorMessage error={verify.error} />

        {verify.data === undefined ? (
          <>
            <Button
              size="sm"
              variant="outline"
              data-action="verify"
              disabled={verify.isPending}
              onClick={() => { verify.mutate() }}
            >
              <ShieldCheckIcon />
              {verify.isPending ? 'Recomputing…' : 'Verify the chain'}
            </Button>
            <p className="text-xs text-muted-foreground">
              Reads every entry, so it is not run automatically. Worth doing
              after any restore.
            </p>
          </>
        ) : verify.data.valid ? (
          <Alert>
            <ShieldCheckIcon />
            <AlertTitle>Intact</AlertTitle>
            <AlertDescription>
              {verify.data.eventsChecked.toLocaleString()} entries recomputed
              from the first forward, and every hash matched.
            </AlertDescription>
          </Alert>
        ) : (
          <Alert variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>Broken at entry {verify.data.brokenAtSeq}</AlertTitle>
            <AlertDescription>
              {verify.data.reason}. Treat this as a security incident rather
              than a data problem: the journal is append-only and protected by
              database rules, so this means something wrote to it outside the
              application.
            </AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  )
}

function AuditViewBody() {
  const [action, setAction] = useState('')
  const [pages, setPages] = useState<number[]>([0])

  const cursor = pages[pages.length - 1] ?? 0
  const { data, isPending, error } = useAuditEvents({ action, subject: '', before: cursor })

  return (
    <div className="space-y-4">
      <ViewHeader
        title="Audit journal"
        description="Every change, in order, hash-chained so it cannot be altered without trace."
      />

      <Chain />

      <Card>
        <CardHeader>
          <CardTitle>Entries</CardTitle>
          <CardDescription>
            Newest first. Entries carry identifiers and enumerations only —
            never free text — so the journal holds nothing that would ever need
            erasing (ADR 0010). Names are read from the directory now, which is
            why an erased account shows as erased rather than as a name.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-4">
          <div className="max-w-xs space-y-1.5">
            <Label htmlFor="audit-action">Action</Label>
            <Input
              id="audit-action"
              value={action}
              placeholder="membership.granted"
              onChange={(event) => {
                setAction(event.target.value)
                // A new filter is a new sequence, so paging starts over.
                // Keeping the cursor would page into a position that means
                // nothing under the new filter.
                setPages([0])
              }}
            />
            <p className="text-xs text-muted-foreground">
              {/* Not a search box. The payload allowlist refuses free text, so
                  there is nothing here to search — a box that never matched
                  would teach people the journal was empty. */}
              An exact action, such as <code className="font-mono">session.created</code>.
            </p>
          </div>

          <ErrorMessage error={error} />

          {error !== null ? null : isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
              <Skeleton className="h-14 w-full" />
            </div>
          ) : data.events.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing matches. Cardinal appends an entry in the same transaction
              as every change it makes, so an empty journal means the filter,
              not a quiet system.
            </p>
          ) : (
            <ul>
              {data.events.map((event) => (
                <Entry key={event.id} event={event} />
              ))}
            </ul>
          )}

          <div className="flex gap-2">
            {pages.length > 1 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => { setPages(pages.slice(0, -1)) }}
              >
                Newer
              </Button>
            )}
            {data !== undefined && data.before !== 0 && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => { setPages([...pages, data.before]) }}
              >
                Older
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * The journal, behind the broad administration tier.
 *
 * It is the record of everything anybody did — including who read it — and is
 * not something to hold by virtue of managing accounts. Distinct from the
 * decision explorer, which answers "why was I denied" from the decision log;
 * this answers "what happened".
 */
export function AuditView() {
  return (
    <RequiresFreshAuth>
      <AuditViewBody />
    </RequiresFreshAuth>
  )
}
