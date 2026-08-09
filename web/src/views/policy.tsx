import { useState } from 'react'
import {
  CheckCircle2Icon,
  FileWarningIcon,
  TriangleAlertIcon,
} from 'lucide-react'
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
import {
  useActivatePolicy,
  usePolicyDocument,
  usePolicyVersions,
} from '@/features/policy/usePolicyVersions'
import { PolicyRules } from '@/features/policy/PolicyRules'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'
import type { PolicyVersion } from '@/lib/api'

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

/** The document, read-only, for checking a version before making it govern. */
function Document({ version }: { version: number }) {
  const { data, isPending, error } = usePolicyDocument(version)

  if (error) return <ErrorMessage error={error} />
  if (isPending) return <Skeleton className="h-40 w-full" />

  return (
    <pre className="max-h-96 overflow-auto rounded-md bg-muted p-3 font-mono text-xs">
      {data.document}
    </pre>
  )
}

function VersionRow({
  version,
  onRead,
  reading,
}: {
  version: PolicyVersion
  onRead: () => void
  reading: boolean
}) {
  const activate = useActivatePolicy()
  const [confirming, setConfirming] = useState(false)

  return (
    <li className="border-b py-3 last:border-b-0">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
            Version {version.version}
            {version.live && (
              <Badge variant="secondary">
                <CheckCircle2Icon />
                Live
              </Badge>
            )}
            {version.active && !version.live && (
              // The database says activated and this server is not serving it.
              // A few seconds after an activation that is normal; longer than
              // that means a node could not load it, and saying so beats
              // showing two ticks and letting somebody assume.
              <Badge variant="outline" className="font-normal">
                Activated, not yet loaded here
              </Badge>
            )}
            {version.invalid && (
              <Badge variant="outline" className="font-normal text-destructive">
                <FileWarningIcon />
                Does not compile
              </Badge>
            )}
          </p>
          <p className="mt-0.5 text-xs text-muted-foreground">
            {version.description === '' ? 'No description' : version.description}
            {' · '}published {when(version.publishedAt)}
            {' · '}
            {version.invalid ? 'unreadable' : `${String(version.policyCount)} rules`}
          </p>
          <p className="truncate font-mono text-xs text-muted-foreground">
            {version.digest.slice(0, 16)}…
          </p>
        </div>

        <div className="flex shrink-0 flex-wrap gap-2">
          <Button variant="outline" size="sm" onClick={onRead}>
            {reading ? 'Hide' : 'Read'}
          </Button>

          {!version.live && !version.invalid && (
            confirming ? (
              <>
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
                  disabled={activate.isPending}
                  onClick={() => { activate.mutate(version.version) }}
                >
                  {activate.isPending ? 'Activating…' : 'Make this live'}
                </Button>
              </>
            ) : (
              <Button
                size="sm"
                // A stable hook for the contrast sweep, which has to reach the
                // confirmation state: it is where the destructive button and
                // the warning live, and neither exists on the page as it
                // loads. Matching on the label would break the moment the
                // wording changes.
                data-action="activate"
                onClick={() => { setConfirming(true) }}
              >
                Make this live
              </Button>
            )
          )}
        </div>
      </div>

      {confirming && !version.live && (
        <Alert variant="destructive" className="mt-3">
          <TriangleAlertIcon />
          <AlertTitle>This decides everything, immediately</AlertTitle>
          <AlertDescription>
            Every question Cardinal answers is answered by this set: web access,
            SSH certificates, sudo, and who may change the policy next. Read it
            first — and if it does not contain a rule granting you
            administration, this is the last thing you will be able to do here.{' '}
            <code className="font-mono">cardinal policy activate</code> on the
            server remains the way back.
          </AlertDescription>
        </Alert>
      )}

      <ErrorMessage error={activate.error} />
    </li>
  )
}

function PolicyViewBody() {
  const { data, isPending, error } = usePolicyVersions()
  const [reading, setReading] = useState<number | null>(null)

  if (error) return <ErrorMessage error={error} />
  if (isPending) return <Skeleton className="h-64 w-full" />

  const versions = data.versions

  return (
    <div className="space-y-4">
      <ViewHeader
        title="Policy"
        description="Every published set, and the one being enforced right now."
      />

      <Alert>
        <FileWarningIcon />
        <AlertTitle>Rules here, whole sets from git</AlertTitle>
        <AlertDescription>
          There is still no editor for the policy document on this page, and
          that is deliberate: a set typed into a browser is one nobody reviewed,
          and the argument for policy-as-code is that it is diffable and
          testable before it governs anything —{' '}
          <code className="font-mono">cardinal policy test</code> compiles one
          without touching the database, and{' '}
          <code className="font-mono">cardinal policy publish</code> loads it.
          Composing a single rule below is a different thing: it names a group
          and a resource that have to exist, says in a sentence what it will
          mean before you press the button, and lands as an ordinary version
          that rolls back like any other. The forbids and the administration
          tiers stay hand-written, because those are the guardrails.
        </AlertDescription>
      </Alert>

      <PolicyRules />

      <Card>
        <CardHeader>
          <CardTitle>Versions</CardTitle>
          <CardDescription>
            Newest first. Activating one takes effect on this server at once and
            on every other within ten seconds.
          </CardDescription>
        </CardHeader>

        <CardContent>
          {versions.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Nothing published. Cedar is default-deny, so every authorization
              is being refused — publish{' '}
              <code className="font-mono">policies/cardinal.cedar</code>.
            </p>
          ) : (
            <ul>
              {versions.map((version) => (
                <div key={version.version}>
                  <VersionRow
                    version={version}
                    reading={reading === version.version}
                    onRead={() => {
                      setReading(reading === version.version ? null : version.version)
                    }}
                  />
                  {reading === version.version && (
                    <div className="pb-3">
                      <Document version={version.version} />
                    </div>
                  )}
                </div>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}

/**
 * Policy versions, behind the broad administration tier.
 *
 * Not the people or applications tier: activating a set decides every question
 * Cardinal answers, including who may activate the next one, so it is not
 * something to hold by virtue of managing accounts.
 */
export function PolicyView() {
  return (
    <RequiresFreshAuth>
      <PolicyViewBody />
    </RequiresFreshAuth>
  )
}
