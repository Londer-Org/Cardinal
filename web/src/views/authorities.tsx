import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CheckIcon, CopyIcon, TriangleAlertIcon } from 'lucide-react'
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
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'
import { api, queryKeys, type Authority, type AuthorityKey } from '@/lib/api'

/** How close to expiry is worth saying something about. */
const EXPIRY_WARNING_DAYS = 90

function when(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function daysUntil(iso: string): number {
  return Math.floor((new Date(iso).getTime() - Date.now()) / 86_400_000)
}

function StateBadge({ state }: { state: string }) {
  if (state === 'signing') return <Badge variant="secondary">Signing</Badge>
  if (state === 'retired') {
    return (
      <Badge variant="outline" className="font-normal">
        Retired
      </Badge>
    )
  }
  return (
    // Trusted and not yet signing. The interesting state: it means a rotation
    // has been started and is waiting on the distribution step.
    <Badge variant="outline" className="font-normal">
      Published, not signing
    </Badge>
  )
}

function KeyRow({ authorityKey }: { authorityKey: AuthorityKey }) {
  const expiring =
    authorityKey.expiresAt !== null &&
    authorityKey.state !== 'retired' &&
    daysUntil(authorityKey.expiresAt) < EXPIRY_WARNING_DAYS

  return (
    <li className="border-b py-3 last:border-b-0">
      <p className="flex flex-wrap items-center gap-2 text-sm font-medium">
        {authorityKey.subject === '' ? authorityKey.algorithm : authorityKey.subject}
        <StateBadge state={authorityKey.state} />
        {expiring && (
          <Badge variant="outline" className="font-normal text-destructive">
            <TriangleAlertIcon />
            Expires soon
          </Badge>
        )}
      </p>
      <p className="truncate font-mono text-xs text-muted-foreground">
        {authorityKey.fingerprint}
      </p>
      <p className="mt-0.5 text-xs text-muted-foreground">
        Created {when(authorityKey.createdAt)}
        {authorityKey.expiresAt !== null && ` · expires ${when(authorityKey.expiresAt)}`}
      </p>
    </li>
  )
}

/**
 * The thing that has to reach every machine.
 *
 * Copyable rather than merely displayed, because the operation this exists for
 * is moving it somewhere else — into a configuration management repository, a
 * container image, a trust store.
 */
function Bundle({ bundle, label }: { bundle: string; label: string }) {
  const [copied, setCopied] = useState(false)

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium">{label}</p>
        <Button
          variant="outline"
          size="sm"
          data-action="copy-bundle"
          onClick={() => {
            void navigator.clipboard.writeText(bundle).then(() => {
              setCopied(true)
              setTimeout(() => { setCopied(false) }, 2000)
            })
          }}
        >
          {copied ? <CheckIcon /> : <CopyIcon />}
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <pre className="max-h-48 overflow-auto rounded-md bg-muted p-3 font-mono text-xs">
        {bundle}
      </pre>
    </div>
  )
}

function AuthorityCard({
  authority,
  title,
  description,
  bundleLabel,
  instructions,
  disabledNote,
}: {
  authority: Authority
  title: string
  description: string
  bundleLabel: string
  instructions: React.ReactNode
  disabledNote: string
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        {!authority.enabled ? (
          <p className="text-sm text-muted-foreground">{disabledNote}</p>
        ) : authority.keys.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Enabled, but no key exists yet — nothing can be signed until one is
            created.
          </p>
        ) : (
          <>
            <ul>
              {authority.keys.map((key) => (
                <KeyRow key={key.id} authorityKey={key} />
              ))}
            </ul>

            <Bundle bundle={authority.bundle} label={bundleLabel} />

            <div className="text-xs text-muted-foreground">{instructions}</div>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function AuthoritiesViewBody() {
  const { data, isPending, error } = useQuery({
    queryKey: queryKeys.authorities,
    queryFn: api.authorities.get,
  })

  if (error) return <ErrorMessage error={error} />
  if (isPending) return <Skeleton className="h-64 w-full" />

  return (
    <div className="space-y-4">
      <ViewHeader
        title="Certificate authorities"
        description="What machines trust, and what has to be distributed for them to."
      />

      <Alert>
        <TriangleAlertIcon />
        <AlertTitle>Distribution is the work</AlertTitle>
        <AlertDescription>
          Getting these into every trust store — system stores, container
          images, JVM keystores, browsers — is the part that takes the time, and
          no software does it for you. An internal authority is worthless until
          it is done, and that is the reason people give up on one. Rotation
          lives in the CLI for the same reason: publish, distribute, then
          activate, and the middle step happens outside Cardinal.
        </AlertDescription>
      </Alert>

      <AuthorityCard
        authority={data.ssh}
        title="SSH"
        description="Signs the short-lived certificates people log in with, and the host certificates that let them verify a machine is what it claims."
        bundleLabel="TrustedUserCAKeys"
        disabledNote="Host access is not configured, so no SSH certificates are issued."
        instructions={
          <>
            Every trusted key, signing or not — a host trusting only the signing
            key rejects certificates issued in the minutes before a rotation.
            Goes in the file named by <code className="font-mono">TrustedUserCAKeys</code>{' '}
            in <code className="font-mono">sshd_config</code>; the agent writes it
            for you on enrolled hosts. Prefix a line with{' '}
            <code className="font-mono">@cert-authority *</code> in{' '}
            <code className="font-mono">known_hosts</code> to verify host
            certificates too.
          </>
        }
      />

      <AuthorityCard
        authority={data.x509}
        title="X.509"
        description="Issues TLS certificates over ACME, so internal services get one the same way they would from a public authority."
        bundleLabel="Root certificates, PEM"
        disabledNote="X.509 issuance is not configured. A deployment that already has an authority keeps it — nothing else in Cardinal depends on this."
        instructions={
          <>
            Every trusted root, so a certificate issued moments before a
            rotation still verifies. Cardinal&apos;s own ACME endpoint cannot get
            its certificate from Cardinal&apos;s ACME — the first one always
            comes from somewhere else.
          </>
        }
      />
    </div>
  )
}

/**
 * The authorities, behind the broad administration tier.
 *
 * The bundles themselves are public by construction — they are what every
 * machine holds — but which key is signing, and when it expires, is operational
 * detail worth the same tier as the rest. An authority whose key expires
 * unnoticed takes the fleet with it, and nothing surfaced that date before.
 */
export function AuthoritiesView() {
  return (
    <RequiresFreshAuth>
      <AuthoritiesViewBody />
    </RequiresFreshAuth>
  )
}
