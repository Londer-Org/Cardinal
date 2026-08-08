import { useState } from 'react'
import {
  CheckIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  KeyRoundIcon,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { Application } from '@/lib/api'
import { RegisterApplication } from './RegisterApplication'
import {
  useApplication,
  useApplications,
  useDisableApplication,
  useRotateSecret,
} from './useApplications'

/**
 * Registered relying parties.
 *
 * Visible only to directory admins, and every endpoint behind it evaluates the
 * policy itself — hiding the section is a courtesy, not the control.
 */
export function ApplicationList() {
  const { data: applications, isPending, error } = useApplications()
  const [expanded, setExpanded] = useState<string | null>(null)

  const items = applications ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Applications</CardTitle>
        <CardDescription>
          Relying parties that can sign users in through Cardinal.
        </CardDescription>
        <CardAction>
          <RegisterApplication />
        </CardAction>
      </CardHeader>

      <CardContent>
        {error !== null && <ErrorMessage error={error} />}

        {isPending ? (
          <div className="space-y-3">
            <Skeleton className="h-14 w-full" />
            <Skeleton className="h-14 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">
            None registered yet.
          </p>
        ) : (
          <ul className="divide-y">
            {items.map((application) => (
              <ApplicationRow
                key={application.clientId}
                application={application}
                expanded={expanded === application.clientId}
                onToggle={() => {
                  setExpanded((current) =>
                    current === application.clientId ? null : application.clientId,
                  )
                }}
              />
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function ApplicationRow({
  application,
  expanded,
  onToggle,
}: {
  application: Application
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <li className="py-3">
      <button
        type="button"
        className="flex w-full items-start gap-3 text-left"
        // A hook for the contrast sweep, which has to expand a row before
        // anything inside it exists to measure.
        data-action="expand"
        // Named, so a sweep can reach a specific application rather than
        // whichever happens to sort first — a public client has no secret to
        // rotate, so "the first row" is not a stable way to find the control.
        data-app={application.name}
        onClick={onToggle}
        aria-expanded={expanded}
      >
        {expanded ? (
          <ChevronDownIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRightIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">{application.name}</p>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {application.clientId}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1">
          <Badge variant="secondary" className="font-normal">
            {application.public ? 'Public' : 'Confidential'}
          </Badge>
          {application.requireConsent && (
            <Badge variant="secondary" className="font-normal">
              Asks consent
            </Badge>
          )}
          {/* Loud on purpose. A development-mode client in a production listing
              accepts plain http redirects, and that should be the first thing
              anyone scanning this list notices. */}
          {application.devMode && <Badge variant="destructive">Dev mode</Badge>}
          {!application.requirePkce && <Badge variant="destructive">No PKCE</Badge>}
        </div>
      </button>

      {expanded && <ApplicationDetail application={application} />}
    </li>
  )
}

/**
 * Replacing a leaked secret.
 *
 * There was no way to do this. A secret that got into a repository or a log
 * could only be dealt with by disabling the application and registering a new
 * one — which changes the client id, so it is a reconfiguration of the
 * application anyway: a migration in response to an incident, at the worst
 * possible moment.
 */
function RotateSecret({ application }: { application: Application }) {
  const rotate = useRotateSecret()
  const [confirming, setConfirming] = useState(false)
  const [copied, setCopied] = useState(false)

  // A public client has no secret and must not be given one: PKCE is its
  // protection, and a registration that suddenly carried a secret would no
  // longer describe the application it belongs to.
  if (application.public) {
    return (
      <Detail label="Secret">
        <p className="text-xs text-muted-foreground">
          A public client — no secret, protected by PKCE instead.
        </p>
      </Detail>
    )
  }

  if (rotate.data !== undefined) {
    return (
      <Alert className="border-primary/50">
        <KeyRoundIcon />
        <AlertTitle>New secret for {application.name}</AlertTitle>
        <AlertDescription className="space-y-2">
          <p>
            Copy it now — only a hash is stored. The old one stopped working the
            moment this was issued, along with every token it had obtained, so
            the application is signing nobody in until it is reconfigured.
          </p>
          <div className="flex w-full items-center gap-2">
            <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 font-mono text-xs">
              {rotate.data.secret}
            </code>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                void navigator.clipboard.writeText(rotate.data.secret).then(() => {
                  setCopied(true)
                  setTimeout(() => { setCopied(false) }, 2000)
                })
              }}
            >
              {copied ? <CheckIcon /> : <CopyIcon />}
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>
        </AlertDescription>
      </Alert>
    )
  }

  return (
    <Detail label="Secret">
      <ErrorMessage error={rotate.error} />
      {confirming ? (
        <div className="rounded-md border border-destructive/50 p-3">
          <p className="text-xs text-muted-foreground">
            The current secret stops working immediately and every token it
            obtained is revoked. {application.name} will sign nobody in until it
            is reconfigured with the new one. There is no grace period, on
            purpose: this is what you press when you believe somebody else has
            it.
          </p>
          <div className="mt-3 flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setConfirming(false) }}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={rotate.isPending}
              onClick={() => { rotate.mutate(application.clientId) }}
            >
              {rotate.isPending ? 'Rotating…' : 'Rotate now'}
            </Button>
          </div>
        </div>
      ) : (
        <Button
          variant="outline"
          size="sm"
          data-action="rotate-secret"
          onClick={() => { setConfirming(true) }}
        >
          Rotate the secret
        </Button>
      )}
    </Detail>
  )
}

function ApplicationDetail({ application }: { application: Application }) {
  const { data: detail, isPending } = useApplication(application.clientId)
  const disable = useDisableApplication()
  const [confirming, setConfirming] = useState(false)

  return (
    <div className="mt-3 ml-7 space-y-3 border-l pl-4">
      <Detail label="Redirect URIs">
        <ul className="space-y-0.5">
          {application.redirectUris.map((uri) => (
            <li key={uri} className="truncate font-mono text-xs">
              {uri}
            </li>
          ))}
        </ul>
      </Detail>

      <Detail label="Scopes">
        <p className="font-mono text-xs">{application.scopes.join(' ')}</p>
      </Detail>

      <Detail label="Access token lifetime">
        <p className="text-xs">{application.accessTokenLifetime}</p>
      </Detail>

      <Detail label="In use">
        {isPending || detail === undefined ? (
          <Skeleton className="h-4 w-40" />
        ) : (
          <p className="text-xs">
            {detail.activeTokens} active {detail.activeTokens === 1 ? 'token' : 'tokens'}
            {detail.standingGrants > 0 &&
              `, ${String(detail.standingGrants)} standing consent${detail.standingGrants === 1 ? '' : 's'}`}
            {detail.lastIssuedAt !== null &&
              `, last issued ${new Date(detail.lastIssuedAt).toLocaleString()}`}
          </p>
        )}
      </Detail>

      <RotateSecret application={application} />

      <ErrorMessage error={disable.error} />

      {confirming ? (
        <div className="rounded-md border border-destructive/50 p-3">
          <p className="text-sm font-medium">Disable {application.name}?</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {/* The consequence stated before the button, not after. Disabling
                revokes tokens, so an application mid-session stops working
                immediately rather than at the next expiry. */}
            It can no longer sign anyone in, and its issued tokens and standing
            consents are revoked — anything using it now will stop. The
            registration is kept so past audit records stay explicable.
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
              onClick={() => { disable.mutate(application.clientId) }}
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
          Disable
        </Button>
      )}
    </div>
  )
}

function Detail({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <div className="mt-0.5">{children}</div>
    </div>
  )
}
