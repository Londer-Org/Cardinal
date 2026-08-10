import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { PauseIcon, PlayIcon, PlusIcon, Trash2Icon, TriangleAlertIcon } from 'lucide-react'
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
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'
import { api, queryKeys, type SSFStream } from '@/lib/api'

/**
 * Who is told when access changes.
 *
 * Revoking a session ends it in Cardinal. An application that issued its own
 * session from an OIDC login learns nothing until its token expires — so
 * "signed out everywhere" was true here and not true of the things Cardinal
 * signed you into. This page is the list of receivers that close that gap, and
 * whether they are actually being reached.
 *
 * Configuring them was a CLI command and nothing else, which made the whole
 * subsystem invisible: an operator could not see whether anybody was listening
 * or whether delivery had been failing for a week. A transmitter nobody watches
 * is one that stops working quietly, which is the failure this exists to
 * prevent.
 */

/** Enough applications that the picker is not a paginated control. */
const APPLICATION_PAGE = { q: '', limit: 200, offset: 0 }

/** The tail of a CAEP event type URI, which is the part worth reading. */
function eventLabel(uri: string): string {
  const tail = uri.split('/').pop() ?? uri
  return tail.replace(/-/g, ' ')
}

function when(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function StreamRow({
  stream,
  onChanged,
}: {
  stream: SSFStream
  onChanged: () => void
}) {
  const [error, setError] = useState<string | null>(null)

  const setEnabled = useMutation({
    mutationFn: (enabled: boolean) => api.ssfStreams.setEnabled(stream.application, enabled),
    onSuccess: () => {
      setError(null)
      onChanged()
    },
    onError: (e: Error) => { setError(e.message); },
  })

  const remove = useMutation({
    mutationFn: () => api.ssfStreams.remove(stream.application),
    onSuccess: () => {
      setError(null)
      onChanged()
    },
    onError: (e: Error) => { setError(e.message); },
  })

  return (
    <li className="border-b py-4 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
            {stream.application}
            {stream.enabled ? (
              <Badge variant="secondary">Delivering</Badge>
            ) : (
              // Paused, not broken. Worth distinguishing: a paused stream is a
              // decision somebody made, and a failing one is not.
              <Badge variant="outline" className="font-normal">
                Paused
              </Badge>
            )}
          </p>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {stream.endpoint}
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            Audience <span className="font-mono">{stream.clientId}</span> · updated{' '}
            {when(stream.updatedAt)}
          </p>
          <div className="mt-2 flex flex-wrap gap-1">
            {stream.events.map((event) => (
              <Badge key={event} variant="outline" className="font-normal">
                {eventLabel(event)}
              </Badge>
            ))}
          </div>
        </div>

        <div className="flex shrink-0 gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={setEnabled.isPending}
            onClick={() => { setEnabled.mutate(!stream.enabled); }}
          >
            {stream.enabled ? <PauseIcon /> : <PlayIcon />}
            {stream.enabled ? 'Pause' : 'Resume'}
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-destructive"
            disabled={remove.isPending}
            onClick={() => { remove.mutate(); }}
          >
            <Trash2Icon />
            Remove
          </Button>
        </div>
      </div>

      <ErrorMessage error={error} />
    </li>
  )
}

function AddStream({
  knownEvents,
  taken,
  onAdded,
}: {
  knownEvents: string[]
  taken: string[]
  onAdded: () => void
}) {
  const [application, setApplication] = useState('')
  const [endpoint, setEndpoint] = useState('')
  // Everything, to begin with. A receiver that wants less can say so, but the
  // default that silently omits an event is the one that produces a gap
  // nobody notices.
  const [events, setEvents] = useState<string[]>(knownEvents)
  const [error, setError] = useState<string | null>(null)

  const applications = useQuery({
    queryKey: queryKeys.refApplications(APPLICATION_PAGE),
    queryFn: () => api.directory.applications(APPLICATION_PAGE),
  })

  const save = useMutation({
    mutationFn: () => api.ssfStreams.save(application, { endpoint, events }),
    onSuccess: () => {
      setError(null)
      setApplication('')
      setEndpoint('')
      setEvents(knownEvents)
      onAdded()
    },
    onError: (e: Error) => { setError(e.message); },
  })

  // Only applications without a stream. There is one per receiver, enforced by
  // the schema, so offering a name that already has one would be offering to
  // overwrite it from a form labelled "add".
  const available = (applications.data?.items ?? []).filter(
    (app) => !taken.includes(app.name),
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle>Add a receiver</CardTitle>
        <CardDescription>
          Events are pushed to the endpoint as signed tokens. It must be https:
          a receiver accepting security events over cleartext is one anybody on
          the path can feed.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="ssf-application">Application</Label>
            <Select value={application} onValueChange={setApplication}>
              <SelectTrigger id="ssf-application">
                <SelectValue placeholder="Choose an application" />
              </SelectTrigger>
              <SelectContent>
                {available.map((app) => (
                  <SelectItem key={app.name} value={app.name}>
                    {app.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="space-y-2">
            <Label htmlFor="ssf-endpoint">Endpoint</Label>
            <Input
              id="ssf-endpoint"
              placeholder="https://app.example.com/events"
              value={endpoint}
              onChange={(e) => { setEndpoint(e.target.value); }}
            />
          </div>
        </div>

        <fieldset className="space-y-2">
          <legend className="text-sm font-medium">Events</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {knownEvents.map((event) => (
              <label key={event} className="flex items-center gap-2 text-sm">
                <Checkbox
                  checked={events.includes(event)}
                  onCheckedChange={(checked) =>
                    { setEvents((current) =>
                      checked === true
                        ? [...current, event]
                        : current.filter((e) => e !== event),
                    ); }
                  }
                />
                {eventLabel(event)}
              </label>
            ))}
          </div>
        </fieldset>

        <ErrorMessage error={error} />

        <Button
          disabled={application === '' || endpoint === '' || save.isPending}
          onClick={() => { save.mutate(); }}
        >
          <PlusIcon />
          Add receiver
        </Button>
      </CardContent>
    </Card>
  )
}

function SecurityEventsViewBody() {
  const queryClient = useQueryClient()
  const { data, isPending, error } = useQuery({
    queryKey: queryKeys.ssfStreams,
    queryFn: () => api.ssfStreams.get(),
  })

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.ssfStreams })
  }

  if (isPending) return <Skeleton className="h-64 w-full" />
  if (error) return <ErrorMessage error={error} />

  return (
    <div className="space-y-6">
      <ViewHeader
        title="Security events"
        description="Who is told when a session is revoked, an account is disabled, or a credential changes."
      />

      {data.failing > 0 && (
        <Alert variant="destructive">
          <TriangleAlertIcon />
          <AlertTitle>
            {data.failing} event{data.failing === 1 ? '' : 's'} could not be delivered
          </AlertTitle>
          <AlertDescription>
            They have exhausted their attempts. Until the receiver accepts them
            it believes access that has been revoked is still good.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Receivers</CardTitle>
          <CardDescription>
            {data.streams.length === 0
              ? 'Nothing is listening. Revoking a session ends it here and tells nobody, so an application keeps honouring its own session until the token expires.'
              : `${data.pending} event${data.pending === 1 ? '' : 's'} waiting to be delivered.`}
          </CardDescription>
        </CardHeader>
        {data.streams.length > 0 && (
          <CardContent>
            <ul>
              {data.streams.map((stream) => (
                <StreamRow key={stream.application} stream={stream} onChanged={refresh} />
              ))}
            </ul>
          </CardContent>
        )}
      </Card>

      <AddStream
        knownEvents={data.knownEvents}
        taken={data.streams.map((s) => s.application)}
        onAdded={refresh}
      />

      <Card>
        <CardHeader>
          <CardTitle>What a receiver needs</CardTitle>
          <CardDescription>
            Tokens are signed with the OIDC signing key, so a receiver verifies
            them against the JWKS it already fetches. There is nothing new to
            distribute.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <p>
            Issuer <span className="font-mono text-xs">{data.issuer}</span>
          </p>
          <p>
            JWKS <span className="font-mono text-xs">{data.jwksUri}</span>
          </p>
          <p className="text-muted-foreground">
            A receiver must check both, and that the audience is its own client
            id — one that accepts any audience cannot tell a token meant for it
            from one replayed from elsewhere.
          </p>
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * Behind the same tier as applications, and behind a fresh credential.
 *
 * Deciding who hears that access was revoked is deciding whether a revocation
 * takes effect anywhere but here, so it is administration rather than
 * configuration.
 */
export function SecurityEventsView() {
  return (
    <RequiresFreshAuth>
      <SecurityEventsViewBody />
    </RequiresFreshAuth>
  )
}
