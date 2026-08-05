import { useState } from 'react'
import { CloudIcon, KeyRoundIcon, PlusIcon, UsbIcon } from 'lucide-react'
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
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { Credential } from '@/lib/api'
import {
  useCredentials,
  useRegisterCredential,
  useRevokeCredential,
} from './useCredentials'

export function CredentialList() {
  const { data: credentials, isPending } = useCredentials()
  const register = useRegisterCredential()
  const revoke = useRevokeCredential()
  const [name, setName] = useState('')

  const items = credentials ?? []
  // Revoking the last credential would be a self-inflicted lockout. The server
  // refuses it too; disabling the control here just avoids offering an action
  // that cannot succeed.
  const isOnlyCredential = items.length <= 1

  return (
    <Card>
      <CardHeader>
        <CardTitle>Passkeys</CardTitle>
        <CardDescription>
          Keep at least two, ideally on separate devices.
        </CardDescription>
      </CardHeader>

      <CardContent>
        {isPending ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">
            No passkeys registered yet.
          </p>
        ) : (
          <ul className="divide-y">
            {items.map((credential) => (
              <CredentialRow
                key={credential.id}
                credential={credential}
                canRevoke={!isOnlyCredential}
                isRevoking={revoke.isPending}
                onRevoke={() => { revoke.mutate(credential.id) }}
              />
            ))}
          </ul>
        )}

        <Separator className="my-4" />

        <form
          className="flex gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            register.mutate(name, { onSuccess: () => { setName('') } })
          }}
        >
          <Input
            value={name}
            onChange={(event) => { setName(event.target.value) }}
            placeholder="Name this device"
            maxLength={64}
            aria-label="Name for the new passkey"
          />
          <Button type="submit" disabled={register.isPending}>
            <PlusIcon />
            {register.isPending ? 'Waiting…' : 'Add'}
          </Button>
        </form>

        <ErrorMessage error={register.error ?? revoke.error} />
      </CardContent>
    </Card>
  )
}

function CredentialRow({
  credential,
  canRevoke,
  isRevoking,
  onRevoke,
}: {
  credential: Credential
  canRevoke: boolean
  isRevoking: boolean
  onRevoke: () => void
}) {
  return (
    <li className="flex items-center justify-between gap-3 py-3">
      <div className="flex min-w-0 items-center gap-3">
        <KeyRoundIcon className="size-4 shrink-0 text-muted-foreground" />
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{credential.name}</p>
          <p className="text-xs text-muted-foreground">
            Added {formatDate(credential.createdAt)}
            {credential.lastUsedAt !== null &&
              ` · last used ${formatDate(credential.lastUsedAt)}`}
          </p>
        </div>
      </div>

      <div className="flex shrink-0 items-center gap-2">
        {/* A synced passkey is more recoverable but less hardware-bound. Only
            device-bound credentials can satisfy the highest assurance level, so
            the distinction is worth surfacing rather than hiding. */}
        <Badge variant={credential.deviceBound ? 'default' : 'secondary'}>
          {credential.deviceBound ? <UsbIcon /> : <CloudIcon />}
          {credential.deviceBound ? 'Device-bound' : 'Synced'}
        </Badge>

        <Button
          variant="ghost"
          size="sm"
          disabled={!canRevoke || isRevoking}
          title={canRevoke ? undefined : 'You cannot remove your only passkey'}
          onClick={onRevoke}
        >
          Remove
        </Button>
      </div>
    </li>
  )
}

function formatDate(iso: string): string {
  const date = new Date(iso)
  return Number.isNaN(date.getTime()) ? 'unknown' : date.toLocaleDateString()
}
