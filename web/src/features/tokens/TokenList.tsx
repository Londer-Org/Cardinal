import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { CheckIcon, CopyIcon, KeyIcon } from 'lucide-react'
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useCreateToken, useRevokeToken, useTokens } from '@/features/tokens/useTokens'
import { createTokenRequest, type CreateTokenRequest } from '@/lib/api'
import type { AccessToken, CreatedToken } from '@/lib/api'

const LIFETIMES = [
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
  { days: 180, label: '180 days' },
  { days: 365, label: 'A year' },
]

function when(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

/**
 * The value, shown once.
 *
 * Deliberately loud and deliberately not dismissible by accident: this is the
 * only moment it exists anywhere outside the holder's hands, and a person who
 * navigates away without copying it has to issue another and revoke this one.
 */
function TokenSecret({ created }: { created: CreatedToken }) {
  const [copied, setCopied] = useState(false)

  return (
    <Alert className="border-primary/50">
      <KeyIcon />
      <AlertTitle>{created.name}</AlertTitle>
      <AlertDescription className="space-y-3">
        <p>
          Copy it now. It is not stored — Cardinal keeps only a hash, so this
          cannot be shown again.
        </p>
        <div className="flex w-full items-center gap-2">
          <code className="min-w-0 flex-1 truncate rounded bg-muted px-2 py-1.5 font-mono text-xs">
            {created.token}
          </code>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void navigator.clipboard.writeText(created.token).then(() => {
                setCopied(true)
                // Back to "Copy" after a moment, so the button does not sit
                // claiming success for the rest of the session.
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

function TokenRow({ token }: { token: AccessToken }) {
  const revoke = useRevokeToken()
  const [confirming, setConfirming] = useState(false)

  return (
    <li className="flex items-start justify-between gap-3 border-b py-3 last:border-b-0">
      <div className="min-w-0">
        <p className="flex items-center gap-2 truncate text-sm font-medium">
          <span className={token.expired ? 'line-through' : undefined}>
            {token.name}
          </span>
          {token.expired && (
            <Badge variant="secondary" className="font-normal">
              Expired
            </Badge>
          )}
        </p>
        <p className="truncate font-mono text-xs text-muted-foreground">
          {token.prefix}…
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {token.expired ? 'Expired' : 'Expires'} {when(token.expiresAt)}
          {' · '}
          {/* Last used is what tells somebody whether a token they have
              forgotten about is actually in something. "Never" a month after
              issuing it is a token to revoke. */}
          {token.lastUsedAt === null
            ? 'never used'
            : `last used ${when(token.lastUsedAt)}`}
        </p>
      </div>

      {!token.expired &&
        (confirming ? (
          <div className="flex shrink-0 gap-2">
            <Button variant="outline" size="sm" onClick={() => { setConfirming(false) }}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={revoke.isPending}
              onClick={() => { revoke.mutate(token.id) }}
            >
              Revoke
            </Button>
          </div>
        ) : (
          <Button
            variant="ghost"
            size="sm"
            className="shrink-0 text-destructive"
            onClick={() => { setConfirming(true) }}
          >
            Revoke
          </Button>
        ))}
    </li>
  )
}

/**
 * Access tokens, for their owner.
 *
 * There is no administrative version of this page, on purpose: a credential
 * that authenticates as a person should be created by that person. An
 * administrator able to mint one could act as them, and nothing in any log
 * would distinguish it from the person themselves.
 */
export function TokenList() {
  const { data, isPending, error } = useTokens()
  const create = useCreateToken()

  const [created, setCreated] = useState<CreatedToken | null>(null)

  const form = useForm<CreateTokenRequest>({
    resolver: zodResolver(createTokenRequest),
    defaultValues: { name: '', days: 90 },
  })

  const tokens = data?.tokens ?? []

  return (
    <div className="space-y-4">
      {created && <TokenSecret created={created} />}

      <Card>
        <CardHeader>
          <CardTitle>Your tokens</CardTitle>
          <CardDescription>
            For scripts and automation. A token is you, with one difference: it
            is never device-bound, so policy refuses it administrative actions
            and SSH certificates however privileged you are.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <ErrorMessage error={error} />
          <ErrorMessage error={create.error} />

          {isPending ? (
            <div className="space-y-2">
              <Skeleton className="h-12 w-full" />
              <Skeleton className="h-12 w-full" />
            </div>
          ) : tokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No tokens. Create one below when a script needs to act as you.
            </p>
          ) : (
            <ul>
              {tokens.map((t) => (
                <TokenRow key={t.id} token={t} />
              ))}
            </ul>
          )}

          <Form {...form}>
            <form
              className="space-y-3 rounded-md border p-3"
              onSubmit={(event) => {
                void form.handleSubmit((values) => {
                  create.mutate(values, {
                    onSuccess: (result) => {
                      setCreated(result)
                      // The lifetime stays — somebody issuing a second token
                      // usually wants the same one — but the name must not, or
                      // the next submission silently reuses it.
                      form.reset({ name: '', days: values.days })
                    },
                  })
                })(event)
              }}
            >
              <p className="text-sm font-medium">New token</p>

              <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
                <FormField
                  control={form.control}
                  name="name"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Name</FormLabel>
                      <FormControl>
                        <Input placeholder="nightly export" {...field} />
                      </FormControl>
                      <FormDescription>
                        How you tell four of them apart in six months.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="days"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Expires</FormLabel>
                      <Select
                        value={String(field.value)}
                        onValueChange={(value) => { field.onChange(Number(value)) }}
                      >
                        <FormControl>
                          <SelectTrigger className="w-[130px]">
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {LIFETIMES.map((l) => (
                            <SelectItem key={l.days} value={String(l.days)}>
                              {l.label}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <Button type="submit" size="sm" disabled={create.isPending}>
                {create.isPending ? 'Creating…' : 'Create token'}
              </Button>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  )
}
