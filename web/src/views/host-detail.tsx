import { useState } from 'react'
import { Link, useParams } from '@tanstack/react-router'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import {
  CheckIcon,
  CopyIcon,
  KeyRoundIcon,
  ShieldAlertIcon,
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
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { GrantPeriod } from '@/features/directory/GrantPeriod'
import {
  useAddHostAlias,
  useEnrollHost,
  useHost,
  useRemoveHostAlias,
} from '@/features/directory/useDirectory'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { RenameDialog } from '@/features/directory/RenameDialog'
import { ViewHeader } from '@/views/ViewHeader'
import { hostAliasRequest, type HostAliasRequest, type HostDetail } from '@/lib/api'

function when(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

/**
 * Who may log into this machine, as whom.
 *
 * The question the page exists to answer, and the one neither FreeIPA nor
 * Keycloak can. It is the same evaluation the agent receives every five
 * minutes — the handler calls the same two functions — so this cannot drift
 * from what the machine is actually told. A console that disagreed with the
 * sudoers file would be worse than no console, because somebody would trust it.
 */
function Access({ host }: { host: HostDetail }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Who can log in</CardTitle>
        <CardDescription>
          Worked out from the live policy, exactly as the agent on this machine
          is told. Nobody here holds a standing credential — a certificate is
          issued per login and expires in minutes.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {host.accessUnavailable ? (
          <Alert variant="destructive">
            <ShieldAlertIcon />
            <AlertTitle>Could not be worked out</AlertTitle>
            <AlertDescription>
              No policy is active, so this is unanswerable rather than empty.
              The agent is refused an assignment in the same situation, which
              means logins keep working from cached policy and nothing new is
              granted.
            </AlertDescription>
          </Alert>
        ) : host.access.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Nobody. A host in no group is a host no rule reaches — put it in one
            the policy names, or nothing can log in but local root.
          </p>
        ) : (
          <ul className="space-y-2">
            {host.access.map((entry) => (
              <li
                key={entry.login}
                className="flex flex-wrap items-center justify-between gap-2 border-b pb-2 text-sm last:border-b-0 last:pb-0"
              >
                <span className="flex flex-wrap items-center gap-2">
                  <Link
                    to="/directory/people/$login"
                    params={{ login: entry.login }}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    {entry.login}
                  </Link>
                  <span className="text-muted-foreground">
                    as <code className="font-mono">{entry.localAccount}</code>
                    {' · '}uid {entry.uid}
                  </span>
                </span>
                {entry.sudo && (
                  <Badge variant="outline" className="font-normal">
                    <TriangleAlertIcon />
                    {/* Not "sudo": the rendered sudoers file grants this
                        without a password, because nobody has authenticated at
                        render time and the rule's freshness condition cannot
                        survive into a file. Saying so is the point. */}
                    root, no password
                  </Badge>
                )}
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

/** The command, shown once, because the token in it is shown once. */
function Enrollment({ name }: { name: string }) {
  const enroll = useEnrollHost(name)
  const [copied, setCopied] = useState(false)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Enrollment</CardTitle>
        <CardDescription>
          Run this on the machine. It generates a keypair there and registers
          the public half — Cardinal never holds the private key, which is what
          makes the machine's identity its own rather than a shared secret.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-3">
        <ErrorMessage error={enroll.error} />

        {enroll.data === undefined ? (
          <Button
            size="sm"
            disabled={enroll.isPending}
            onClick={() => { enroll.mutate() }}
          >
            <KeyRoundIcon />
            {enroll.isPending ? 'Issuing…' : 'Issue an enrollment token'}
          </Button>
        ) : (
          <>
            <div className="flex w-full items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 font-mono text-xs">
                {enroll.data.command}
              </code>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  void navigator.clipboard.writeText(enroll.data.command).then(() => {
                    setCopied(true)
                    setTimeout(() => { setCopied(false) }, 2000)
                  })
                }}
              >
                {copied ? <CheckIcon /> : <CopyIcon />}
                {copied ? 'Copied' : 'Copy'}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Single use, expires {when(enroll.data.expiresAt)}. Only its hash is
              stored, so this cannot be shown again — issue another if it is
              lost, which supersedes this one.
            </p>
          </>
        )}
      </CardContent>
    </Card>
  )
}

function Aliases({ host }: { host: HostDetail }) {
  const add = useAddHostAlias(host.name)
  const remove = useRemoveHostAlias(host.name)

  const form = useForm<HostAliasRequest>({
    resolver: zodResolver(hostAliasRequest),
    defaultValues: { alias: '' },
  })

  return (
    <Card>
      <CardHeader>
        <CardTitle>Names it may prove</CardTitle>
        <CardDescription>
          Every name this machine can hold a certificate for. Each one is the
          power to <em>be</em> that name to anything trusting the authority, so
          a machine quietly holding four is worth asking about.
        </CardDescription>
      </CardHeader>

      <CardContent className="space-y-4">
        <ErrorMessage error={add.error ?? remove.error} />

        <ul className="space-y-1">
          <li className="flex items-center justify-between gap-2 text-sm">
            <code className="font-mono">{host.name}</code>
            <span className="text-xs text-muted-foreground">
              its own name, never removable
            </span>
          </li>
          {host.aliasNames.map((alias) => (
            <li key={alias} className="flex items-center justify-between gap-2 text-sm">
              <code className="font-mono">{alias}</code>
              <Button
                variant="ghost"
                size="sm"
                className="text-destructive"
                disabled={remove.isPending}
                onClick={() => { remove.mutate(alias) }}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>

        <Form {...form}>
          <form
            className="flex items-start gap-2"
            onSubmit={(event) => {
              void form.handleSubmit(({ alias }) => {
                add.mutate(alias, { onSuccess: () => { form.reset() } })
              })(event)
            }}
          >
            <FormField
              control={form.control}
              name="alias"
              render={({ field }) => (
                <FormItem className="flex-1 gap-1">
                  <FormLabel className="sr-only">Another name</FormLabel>
                  <FormControl>
                    <Input placeholder="web-01.example.com" {...field} />
                  </FormControl>
                  <FormDescription className="text-xs">
                    A name another host already holds is refused, and the
                    refusal says which host holds it.
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />
            <Button type="submit" size="sm" disabled={add.isPending}>
              Add
            </Button>
          </form>
        </Form>
      </CardContent>
    </Card>
  )
}

function Credentials({ host }: { host: HostDetail }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Keys</CardTitle>
        <CardDescription>
          What the machine authenticates with. Generated on the host during
          enrollment and never transmitted.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {host.credentials.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            Never enrolled. The directory record exists; the machine cannot yet
            prove it is this host.
          </p>
        ) : (
          <ul className="space-y-2">
            {host.credentials.map((credential) => (
              <li key={credential.fingerprint} className="border-b pb-2 last:border-b-0 last:pb-0">
                <p className="flex items-center gap-2 text-sm">
                  <code className="min-w-0 truncate font-mono text-xs">
                    {credential.fingerprint}
                  </code>
                  {credential.live ? (
                    <Badge variant="secondary">Current</Badge>
                  ) : (
                    <Badge variant="outline" className="font-normal">
                      Retired
                    </Badge>
                  )}
                </p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  Enrolled {when(credential.enrolledAt)}
                  {' · '}
                  {credential.lastSeenAt === null
                    ? 'never used'
                    : `last seen ${when(credential.lastSeenAt)}`}
                </p>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function HostDetailViewBody() {
  const { name } = useParams({ from: '/directory/hosts/$name' })
  const { data: host, isPending, error } = useHost(name)

  if (error) return <ErrorMessage error={error} />
  if (isPending) return <Skeleton className="h-64 w-full" />

  return (
    <div className="space-y-4">
      <ViewHeader
        title={host.name}
        description={host.displayName === '' ? undefined : host.displayName}
        action={<RenameDialog kind="hosts" current={host.name} />}
      />

      {host.disabled && (
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>Disabled</AlertTitle>
          <AlertDescription>
            This host cannot authenticate. Its agent will keep serving the
            assignment it last cached, which is deliberate — a directory outage
            must not lock anybody out of a machine.
          </AlertDescription>
        </Alert>
      )}

      <Access host={host} />

      <div className="grid gap-4 lg:grid-cols-2">
        <Aliases host={host} />
        <Credentials host={host} />
        <Enrollment name={host.name} />

        <Card>
          <CardHeader>
            <CardTitle>Groups</CardTitle>
            <CardDescription>
              What policy matches on. A host in no group is one no rule reaches.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {host.memberships.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                In no groups. Add it to one from that group&apos;s page.
              </p>
            ) : (
              <ul className="space-y-2">
                {host.memberships.map((grant) => (
                  <li key={grant.group} className="text-sm">
                    <Link
                      to="/directory/groups/$name"
                      params={{ name: grant.group }}
                      className="font-medium underline-offset-4 hover:underline"
                    >
                      {grant.group}
                    </Link>
                    <GrantPeriod grant={grant} />
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export function HostDetailView() {
  return (
    <RequiresFreshAuth>
      <HostDetailViewBody />
    </RequiresFreshAuth>
  )
}
