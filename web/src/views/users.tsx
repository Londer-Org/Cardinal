import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { CircleSlashIcon, MailIcon } from 'lucide-react'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Badge } from '@/components/ui/badge'
import { ErrorMessage } from '@/components/ErrorMessage'
import { DataTable, type Column } from '@/components/DataTable'
import { CreateUser } from '@/features/directory/CreateUser'
import { useUsers } from '@/features/directory/useDirectory'
import { usePageState } from '@/features/directory/usePageState'
import type { UserStatus } from '@/lib/api'
import type { DirectoryUser } from '@/lib/api'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { PendingInvitations } from '@/features/directory/PendingInvitations'
import { ViewHeader } from '@/views/ViewHeader'

/** Enrollment state, at a glance. */
function EnrollmentBadge({ user }: { user: DirectoryUser }) {
  if (user.credentials === 0) {
    return user.invitationPending ? (
      <Badge variant="secondary" className="font-normal">
        <MailIcon className="size-3" />
        Invited
      </Badge>
    ) : (
      // Not destructive — a to-do, not a fault. Colouring routine follow-up as
      // an error trains people to ignore the colour that matters.
      <Badge variant="secondary" className="font-normal">
        No passkey
      </Badge>
    )
  }
  if (!user.fullyEnrolled) {
    return (
      <Badge variant="secondary" className="font-normal">
        One passkey
      </Badge>
    )
  }
  return <span className="text-muted-foreground">—</span>
}

const STATUSES: { value: UserStatus; label: string }[] = [
  { value: '', label: 'Active' },
  { value: 'disabled', label: 'Disabled' },
  { value: 'all', label: 'Everyone' },
]

function UsersViewBody() {
  const { page, setSearch, setOffset, setLimit } = usePageState()
  const [status, setStatus] = useState<UserStatus>('')
  const { data, isPending, error } = useUsers(page, status)
  const navigate = useNavigate()

  const columns: Column<DirectoryUser>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (u) => (
        <div className="min-w-0">
          <p className="flex items-center gap-2 truncate font-medium">
            <span className={u.disabled ? 'line-through' : undefined}>
              {u.displayName || u.login}
            </span>
            {u.disabled && (
              <Badge variant="secondary" className="font-normal">
                <CircleSlashIcon className="size-3" />
                Disabled
              </Badge>
            )}
          </p>
          <p className="truncate text-xs text-muted-foreground">{u.login}</p>
        </div>
      ),
    },
    {
      key: 'email',
      header: 'Email',
      secondary: true,
      cell: (u) =>
        u.email === '' ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          <span className="truncate">{u.email}</span>
        ),
    },
    {
      key: 'groups',
      header: 'Groups',
      width: '6rem',
      secondary: true,
      cell: (u) => u.groups,
    },
    {
      key: 'enrollment',
      header: 'Enrollment',
      width: '9rem',
      cell: (u) => <EnrollmentBadge user={u} />,
    },
  ]

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <ViewHeader
        title="People"
        description="Everyone in the directory, and whether they can actually sign in."
        action={<CreateUser />}
      />

      <ErrorMessage error={error} />

      {/* Above the table, because an outstanding invitation is a person who
          cannot start work yet — the one thing on this page that needs doing
          rather than merely being true. */}
      <PendingInvitations />

      <DataTable
        columns={columns}
        rows={data?.items ?? []}
        rowKey={(u) => u.login}
        total={data?.total ?? 0}
        offset={page.offset}
        limit={page.limit}
        onPage={setOffset}
        onLimit={setLimit}
        search={page.q}
        onSearch={setSearch}
        searchPlaceholder="Search name, username or email"
        isPending={isPending}
        empty={
          status === 'disabled'
            ? 'Nobody is disabled.'
            : 'Nobody yet.'
        }
        filters={
          <Select
            value={status === '' ? 'active' : status}
            onValueChange={(value) => {
              setStatus(value === 'active' ? '' : (value as UserStatus))
              // Back to the first page: filtering while on page four shows an
              // empty table and reads as "nothing matches".
              setOffset(0)
            }}
          >
            <SelectTrigger className="w-[150px]" aria-label="Filter by status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {STATUSES.map((s) => (
                <SelectItem key={s.label} value={s.value === '' ? 'active' : s.value}>
                  {s.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
        onRowClick={(u) => {
          void navigate({ to: '/directory/people/$login', params: { login: u.login } })
        }}
      />
    </div>
  )
}

/**
 * Guarded, so arriving here with a stale session shows what is needed rather
 * than firing requests that will be refused — which produced an empty table
 * under the words "Nobody yet.", a statement about the directory and a false
 * one.
 */
export function UsersView() {
  return (
    <RequiresFreshAuth>
      <UsersViewBody />
    </RequiresFreshAuth>
  )
}
