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
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { Application, ApplicationSummary } from '@/lib/api'
import { RegisterApplication } from './RegisterApplication'
import {
  useAddHostname,
  useApplication,
  useApplications,
  useRemoveHostname,
  useRotateSecret,
  useSetApplicationEnabled,
} from './useApplications'

/**
 * Everything Cardinal protects.
 *
 * This used to list OIDC relying parties, which made an entire category
 * invisible: an application behind the proxy speaks no OIDC, has no client id,
 * and appeared nowhere — while being precisely the kind that needs a hostname
 * adding before anything can reach it.
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
          Everything Cardinal protects: relying parties that sign users in, and
          sites behind the proxy that do not. Both are directory entities, which
          is what policy names.
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
                key={application.name}
                application={application}
                expanded={expanded === application.name}
                onToggle={() => {
                  setExpanded((current) =>
                    current === application.name ? null : application.name,
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
  application: ApplicationSummary
  expanded: boolean
  onToggle: () => void
}) {
  const { oidc } = application

  // What identifies this row underneath the name. A relying party has a client
  // id; something behind the proxy has the addresses it answers to, which is
  // the equivalent fact — it is how forwardAuth finds it.
  const subtitle =
    oidc !== null
      ? oidc.clientId
      : application.hostnames.length > 0
        ? application.hostnames.join(', ')
        : 'no hostname yet — unreachable'

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
          <p className="truncate font-mono text-xs text-muted-foreground">{subtitle}</p>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1">
          {application.disabled && <Badge variant="outline">Retired</Badge>}
          {oidc === null ? (
            <Badge variant="secondary" className="font-normal">
              Behind the proxy
            </Badge>
          ) : (
            <>
              <Badge variant="secondary" className="font-normal">
                {oidc.public ? 'Public' : 'Confidential'}
              </Badge>
              {oidc.requireConsent && (
                <Badge variant="secondary" className="font-normal">
                  Asks consent
                </Badge>
              )}
              {/* Loud on purpose. A development-mode client in a production
                  listing accepts plain http redirects, and that should be the
                  first thing anyone scanning this list notices. */}
              {oidc.devMode && <Badge variant="destructive">Dev mode</Badge>}
              {!oidc.requirePkce && <Badge variant="destructive">No PKCE</Badge>}
            </>
          )}
        </div>
      </button>

      {expanded && <ApplicationDetail application={application} />}
    </li>
  )
}

/**
 * The addresses forwardAuth resolves to this application.
 *
 * The console had no way to set these, and an application with none is refused
 * before policy is even consulted — so a site could be registered here and
 * remain unreachable with nothing on screen saying why. The empty state says
 * it now.
 */
function Hostnames({ application }: { application: ApplicationSummary }) {
  const add = useAddHostname()
  const remove = useRemoveHostname()
  const [value, setValue] = useState('')

  return (
    <Detail label="Hostnames">
      {application.hostnames.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          None. Nothing reaches this application through the proxy until one is
          added — a hostname no application claims is refused before policy is
          consulted.
        </p>
      ) : (
        <ul className="space-y-1">
          {application.hostnames.map((hostname) => (
            <li key={hostname} className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate font-mono text-xs">
                {hostname}
              </code>
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive"
                disabled={remove.isPending}
                onClick={() => {
                  remove.mutate({ name: application.name, hostname })
                }}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}

      <ErrorMessage error={add.error ?? remove.error} />

      <form
        className="mt-2 flex gap-2"
        onSubmit={(event) => {
          event.preventDefault()
          add.mutate(
            { name: application.name, hostname: value },
            { onSuccess: () => { setValue('') } },
          )
        }}
      >
        <Input
          value={value}
          placeholder="app.example.com"
          aria-label={`Hostname for ${application.name}`}
          onChange={(event) => { setValue(event.target.value) }}
        />
        <Button type="submit" variant="outline" size="sm" disabled={add.isPending || value === ''}>
          Add
        </Button>
      </form>
      <p className="mt-1 text-xs text-muted-foreground">
        One application per hostname. Adding it makes this application findable,
        not reachable — what makes it reachable is a group the policy set names.
      </p>
    </Detail>
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
function RotateSecret({
  application,
  oidc,
}: {
  application: ApplicationSummary
  oidc: Application
}) {
  const rotate = useRotateSecret()
  const [confirming, setConfirming] = useState(false)
  const [copied, setCopied] = useState(false)

  // A public client has no secret and must not be given one: PKCE is its
  // protection, and a registration that suddenly carried a secret would no
  // longer describe the application it belongs to.
  if (oidc.public) {
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
              onClick={() => { rotate.mutate(oidc.clientId) }}
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

function ApplicationDetail({ application }: { application: ApplicationSummary }) {
  const { oidc } = application
  const setEnabled = useSetApplicationEnabled()
  const [confirming, setConfirming] = useState(false)

  return (
    <div className="mt-3 ml-7 space-y-3 border-l pl-4">
      <Hostnames application={application} />

      {oidc !== null && <OIDCDetail application={application} oidc={oidc} />}

      <ErrorMessage error={setEnabled.error} />

      {application.disabled ? (
        <Detail label="Retired">
          <p className="text-xs text-muted-foreground">
            Nothing reaches it and it signs nobody in. Bringing it back does not
            restore the tokens and consents that were revoked with it.
          </p>
          <Button
            variant="outline"
            size="sm"
            className="mt-2"
            disabled={setEnabled.isPending}
            onClick={() => {
              setEnabled.mutate({ name: application.name, enabled: true })
            }}
          >
            {setEnabled.isPending ? 'Restoring…' : 'Bring it back'}
          </Button>
        </Detail>
      ) : confirming ? (
        <div className="rounded-md border border-destructive/50 p-3">
          <p className="text-sm font-medium">Retire {application.name}?</p>
          <p className="mt-1 text-xs text-muted-foreground">
            {/* The consequence stated before the button, not after. Disabling
                revokes tokens, so an application mid-session stops working
                immediately rather than at the next expiry. */}
            Requests through the proxy are refused, it can sign nobody in, and
            its issued tokens and standing consents are revoked — anything using
            it now will stop. It is kept rather than deleted, so past audit
            records stay explicable.
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
              disabled={setEnabled.isPending}
              onClick={() => {
                setEnabled.mutate({ name: application.name, enabled: false })
              }}
            >
              {setEnabled.isPending ? 'Retiring…' : 'Retire'}
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
          Retire
        </Button>
      )}
    </div>
  )
}

/** The half that only exists when the application speaks OpenID Connect. */
function OIDCDetail({
  application,
  oidc,
}: {
  application: ApplicationSummary
  oidc: Application
}) {
  const { data: detail, isPending } = useApplication(oidc.clientId)

  return (
    <>
      <Detail label="Redirect URIs">
        <ul className="space-y-0.5">
          {oidc.redirectUris.map((uri) => (
            <li key={uri} className="truncate font-mono text-xs">
              {uri}
            </li>
          ))}
        </ul>
      </Detail>

      <Detail label="Scopes">
        <p className="font-mono text-xs">{oidc.scopes.join(' ')}</p>
      </Detail>

      <Detail label="Access token lifetime">
        <p className="text-xs">{oidc.accessTokenLifetime}</p>
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

      <RotateSecret application={application} oidc={oidc} />
    </>
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
