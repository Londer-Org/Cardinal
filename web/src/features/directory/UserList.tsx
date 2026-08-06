import { useState } from 'react'
import {
  ChevronDownIcon,
  ChevronRightIcon,
  CopyIcon,
  MailIcon,
  PlusIcon,
  TriangleAlertIcon,
} from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
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
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { CreatedUser, DirectoryUser, Grant } from '@/lib/api'
import { GrantForm } from './GrantForm'
import { InvitationPanel } from './InvitationPanel'
import {
  useCreateUser,
  useDisableUser,
  useRevokeMembership,
  useUser,
  useUsers,
} from './useDirectory'

/**
 * The people in the directory.
 *
 * Shows enrollment state alongside each name, because an account nobody can
 * sign in to looks identical to a working one until someone tries — and the
 * difference between "waiting for an invitation" and "abandoned" is the whole
 * of an administrator's follow-up list.
 */
export function UserList() {
  const { data: users, isPending, error } = useUsers()
  const [expanded, setExpanded] = useState<string | null>(null)

  const items = users ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>People</CardTitle>
        <CardDescription>
          Everyone in the directory, and whether they can actually sign in.
        </CardDescription>
        <CardAction>
          <CreateUser />
        </CardAction>
      </CardHeader>

      <CardContent>
        {error !== null && <ErrorMessage error={error} />}

        {isPending ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
            <Skeleton className="h-12 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">Nobody yet.</p>
        ) : (
          <ul className="divide-y">
            {items.map((user) => (
              <UserRow
                key={user.login}
                user={user}
                expanded={expanded === user.login}
                onToggle={() => {
                  setExpanded((current) =>
                    current === user.login ? null : user.login,
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

function UserRow({
  user,
  expanded,
  onToggle,
}: {
  user: DirectoryUser
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <li className="py-3">
      <button
        type="button"
        className="flex w-full items-start gap-3 text-left"
        onClick={onToggle}
        aria-expanded={expanded}
      >
        {expanded ? (
          <ChevronDownIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRightIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
        )}
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium">
            {user.displayName || user.login}
          </p>
          <p className="truncate text-xs text-muted-foreground">
            {user.login}
            {user.email && ` · ${user.email}`}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap justify-end gap-1">
          <Badge variant="secondary" className="font-normal">
            {user.groups} {user.groups === 1 ? 'group' : 'groups'}
          </Badge>
          {user.credentials === 0 ? (
            user.invitationPending ? (
              <Badge variant="secondary" className="font-normal">
                <MailIcon className="size-3" />
                Invited
              </Badge>
            ) : (
              // Not destructive — it is a to-do, not a fault. Colouring routine
              // follow-up as an error trains people to ignore the colour that
              // actually matters.
              <Badge variant="secondary" className="font-normal">
                No passkey
              </Badge>
            )
          ) : (
            !user.fullyEnrolled && (
              <Badge variant="secondary" className="font-normal">
                One passkey
              </Badge>
            )
          )}
        </div>
      </button>

      {expanded && <UserDetail login={user.login} />}
    </li>
  )
}

function UserDetail({ login }: { login: string }) {
  const { data: user, isPending } = useUser(login)
  const disable = useDisableUser()
  const revoke = useRevokeMembership()
  const [confirming, setConfirming] = useState(false)

  if (isPending || user === undefined) {
    return (
      <div className="mt-3 ml-7 border-l pl-4">
        <Skeleton className="h-20 w-full" />
      </div>
    )
  }

  return (
    <div className="mt-3 ml-7 space-y-4 border-l pl-4">
      <div>
        <p className="text-xs font-medium text-muted-foreground">Groups</p>
        {user.memberships.length === 0 ? (
          <p className="mt-1 text-xs text-muted-foreground">None.</p>
        ) : (
          <ul className="mt-1 space-y-1">
            {user.memberships.map((grant) => (
              <li
                key={grant.group}
                className="flex items-center justify-between gap-2"
              >
                <span className="min-w-0 text-xs">
                  <span className="font-medium">{grant.group}</span>
                  <GrantPeriod grant={grant} />
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-6 shrink-0 text-xs"
                  disabled={revoke.isPending}
                  onClick={() => {
                    revoke.mutate({ group: grant.group, member: login })
                  }}
                >
                  Revoke
                </Button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <InvitationPanel user={user} />

      <GrantForm member={login} />

      <ErrorMessage error={revoke.error ?? disable.error} />

      {confirming ? (
        <div className="rounded-md border border-destructive/50 p-3">
          <p className="text-sm font-medium">Disable {user.login}?</p>
          <p className="mt-1 text-xs text-muted-foreground">
            They can no longer sign in, and their sessions end immediately. The
            account is kept so past grants and audit records still resolve.
          </p>
          <div className="mt-3 flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setConfirming(false) }}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={disable.isPending}
              onClick={() => { disable.mutate(login) }}
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
          Disable account
        </Button>
      )}
    </div>
  )
}

/** When a grant ends, in words rather than a raw timestamp. */
export function GrantPeriod({ grant }: { grant: Grant }) {
  if (grant.until === null) {
    return (
      <span className="ml-2 text-muted-foreground">
        {/* Named, not left blank. An unbounded grant is the one that gets
            forgotten, and it should be visible as a choice someone made. */}
        no end date
      </span>
    )
  }

  const until = new Date(grant.until)
  const days = Math.round((until.getTime() - Date.now()) / 86_400_000)

  return (
    <span className="ml-2 text-muted-foreground">
      until {until.toLocaleDateString()}
      {days >= 0 && ` · ${days === 0 ? 'today' : `${String(days)}d left`}`}
    </span>
  )
}

function CreateUser() {
  const [open, setOpen] = useState(false)
  const [login, setLogin] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [invite, setInvite] = useState(true)
  const [created, setCreated] = useState<CreatedUser | null>(null)
  const create = useCreateUser()

  function reset() {
    setLogin('')
    setDisplayName('')
    setInvite(true)
    setCreated(null)
    create.reset()
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) reset()
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm">
          <PlusIcon />
          Add person
        </Button>
      </DialogTrigger>

      <DialogContent className="sm:max-w-lg">
        {created === null ? (
          <>
            <DialogHeader>
              <DialogTitle>Add a person</DialogTitle>
              <DialogDescription>
                Creates the account. Nobody can sign in to it until a passkey is
                registered.
              </DialogDescription>
            </DialogHeader>

            <form
              className="space-y-4"
              onSubmit={(event) => {
                event.preventDefault()
                create.mutate(
                  {
                    login: login.trim(),
                    displayName: displayName.trim(),
                    invite,
                  },
                  { onSuccess: setCreated },
                )
              }}
            >
              <div className="space-y-1.5">
                <Label htmlFor="user-login">Username</Label>
                <Input
                  id="user-login"
                  value={login}
                  onChange={(event) => { setLogin(event.target.value) }}
                  placeholder="jdoe"
                  required
                />
                <p className="text-xs text-muted-foreground">
                  Appears in policy and in the audit trail. They cannot change it.
                </p>
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="user-display">Name</Label>
                <Input
                  id="user-display"
                  value={displayName}
                  onChange={(event) => { setDisplayName(event.target.value) }}
                  placeholder="J Doe"
                />
                <p className="text-xs text-muted-foreground">
                  Optional — they set their own when they enrol.
                </p>
              </div>

              <div className="flex items-start gap-3">
                <Switch
                  id="user-invite"
                  checked={invite}
                  onCheckedChange={setInvite}
                  className="mt-0.5"
                />
                <div className="min-w-0">
                  <Label htmlFor="user-invite">Send an enrollment link</Label>
                  <p className="text-xs text-muted-foreground">
                    {/* On by default: an account created without one is an
                        account nobody can use, and the second step is the one
                        that gets forgotten. */}
                    Single use, expires in 24 hours. Without it the account
                    exists but nobody can sign in to it.
                  </p>
                </div>
              </div>

              <ErrorMessage error={create.error} />

              <DialogFooter>
                <Button type="submit" disabled={create.isPending}>
                  {create.isPending ? 'Creating…' : 'Create'}
                </Button>
              </DialogFooter>
            </form>
          </>
        ) : (
          <Created
            user={created}
            onDone={() => { setOpen(false); reset() }}
          />
        )}
      </DialogContent>
    </Dialog>
  )
}

function Created({ user, onDone }: { user: CreatedUser; onDone: () => void }) {
  const [copied, setCopied] = useState(false)

  return (
    <>
      <DialogHeader>
        <DialogTitle>{user.login} is ready</DialogTitle>
        <DialogDescription>
          {user.invitationUrl === undefined
            ? 'No enrollment link was issued — nobody can sign in to this account yet.'
            : 'Send this link however you like.'}
        </DialogDescription>
      </DialogHeader>

      {user.invitationUrl !== undefined && (
        <div className="space-y-3">
          <div className="flex gap-2">
            <code className="min-w-0 flex-1 truncate rounded-md border bg-muted px-3 py-2 font-mono text-xs">
              {user.invitationUrl}
            </code>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => {
                const url = user.invitationUrl
                if (url === undefined) return
                void navigator.clipboard.writeText(url).then(() => {
                  setCopied(true)
                })
              }}
            >
              <CopyIcon />
              {copied ? 'Copied' : 'Copy'}
            </Button>
          </div>

          <Alert>
            <TriangleAlertIcon />
            <AlertTitle>Shown once</AlertTitle>
            <AlertDescription>
              Only its hash is stored. If you lose it, issue another from the
              account — it supersedes this one.
            </AlertDescription>
          </Alert>
        </div>
      )}

      <DialogFooter>
        <Button onClick={onDone}>Done</Button>
      </DialogFooter>
    </>
  )
}
