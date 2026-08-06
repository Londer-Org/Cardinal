import { useState } from 'react'
import { ChevronDownIcon, ChevronRightIcon, PlusIcon } from 'lucide-react'
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
import { Skeleton } from '@/components/ui/skeleton'
import { ErrorMessage } from '@/components/ErrorMessage'
import type { DirectoryGroup } from '@/lib/api'
import { GrantPeriod } from './UserList'
import {
  useCreateGroup,
  useGroup,
  useGroups,
  useRevokeMembership,
} from './useDirectory'

/**
 * Groups, and who is in them right now.
 *
 * "Right now" is load-bearing: a grant that has expired stops counting without
 * anything having run, so a member list is an answer about this moment rather
 * than a stored flag someone has to remember to clear.
 */
export function GroupList() {
  const { data: groups, isPending, error } = useGroups()
  const [expanded, setExpanded] = useState<string | null>(null)

  const items = groups ?? []

  return (
    <Card>
      <CardHeader>
        <CardTitle>Groups</CardTitle>
        <CardDescription>
          What policy reads. Membership is temporal — counts are as of now.
        </CardDescription>
        <CardAction>
          <CreateGroup />
        </CardAction>
      </CardHeader>

      <CardContent>
        {error !== null && <ErrorMessage error={error} />}

        {isPending ? (
          <div className="space-y-3">
            <Skeleton className="h-12 w-full" />
          </div>
        ) : items.length === 0 ? (
          <p className="py-2 text-sm text-muted-foreground">No groups yet.</p>
        ) : (
          <ul className="divide-y">
            {items.map((group) => (
              <GroupRow
                key={group.name}
                group={group}
                expanded={expanded === group.name}
                onToggle={() => {
                  setExpanded((current) =>
                    current === group.name ? null : group.name,
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

function GroupRow({
  group,
  expanded,
  onToggle,
}: {
  group: DirectoryGroup
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
          <p className="truncate text-sm font-medium">{group.name}</p>
          {group.displayName && (
            <p className="truncate text-xs text-muted-foreground">
              {group.displayName}
            </p>
          )}
        </div>
        <Badge variant="secondary" className="shrink-0 font-normal">
          {group.members} {group.members === 1 ? 'member' : 'members'}
        </Badge>
      </button>

      {expanded && <GroupDetail name={group.name} />}
    </li>
  )
}

function GroupDetail({ name }: { name: string }) {
  const { data: group, isPending } = useGroup(name)
  const revoke = useRevokeMembership()

  if (isPending || group === undefined) {
    return (
      <div className="mt-3 ml-7 border-l pl-4">
        <Skeleton className="h-16 w-full" />
      </div>
    )
  }

  return (
    <div className="mt-3 ml-7 space-y-3 border-l pl-4">
      {group.members.length === 0 ? (
        <p className="text-xs text-muted-foreground">
          {/* Distinguished from "never had any": an expired grant leaves no
              member but does leave history, and saying so avoids the reading
              that something was lost. */}
          Nobody is a member right now. Expired grants keep their history.
        </p>
      ) : (
        <ul className="space-y-1">
          {group.members.map((grant) => (
            <li key={grant.member} className="flex items-center justify-between gap-2">
              <span className="min-w-0 text-xs">
                <span className="font-medium">{grant.member}</span>
                <GrantPeriod grant={grant} />
                {grant.reason && (
                  <span className="ml-2 text-muted-foreground">· {grant.reason}</span>
                )}
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 shrink-0 text-xs"
                disabled={revoke.isPending}
                onClick={() => { revoke.mutate({ group: name, member: grant.member }) }}
              >
                Revoke
              </Button>
            </li>
          ))}
        </ul>
      )}

      <ErrorMessage error={revoke.error} />
    </div>
  )
}

function CreateGroup() {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [displayName, setDisplayName] = useState('')
  const create = useCreateGroup()

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setOpen(next)
        if (!next) {
          setName('')
          setDisplayName('')
          create.reset()
        }
      }}
    >
      <DialogTrigger asChild>
        <Button size="sm" variant="outline">
          <PlusIcon />
          New group
        </Button>
      </DialogTrigger>

      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create a group</DialogTitle>
          <DialogDescription>
            Groups are what policy references, so the name matters.
          </DialogDescription>
        </DialogHeader>

        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault()
            create.mutate(
              { name: name.trim(), displayName: displayName.trim() },
              { onSuccess: () => { setOpen(false) } },
            )
          }}
        >
          <div className="space-y-1.5">
            <Label htmlFor="group-name">Name</Label>
            <Input
              id="group-name"
              value={name}
              onChange={(event) => { setName(event.target.value) }}
              placeholder="engineers"
              required
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="group-display">Description</Label>
            <Input
              id="group-display"
              value={displayName}
              onChange={(event) => { setDisplayName(event.target.value) }}
              placeholder="Engineering"
            />
          </div>

          <ErrorMessage error={create.error} />

          <DialogFooter>
            <Button type="submit" disabled={create.isPending}>
              {create.isPending ? 'Creating…' : 'Create'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
