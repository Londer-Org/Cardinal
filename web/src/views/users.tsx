import { useNavigate } from '@tanstack/react-router'
import { MailIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ErrorMessage } from '@/components/ErrorMessage'
import { DataTable, type Column } from '@/components/DataTable'
import { CreateUser } from '@/features/directory/CreateUser'
import { useUsers } from '@/features/directory/useDirectory'
import { usePageState } from '@/features/directory/usePageState'
import type { DirectoryUser } from '@/lib/api'
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

export function UsersView() {
  const { page, setSearch, setOffset, setLimit } = usePageState()
  const { data, isPending, error } = useUsers(page)
  const navigate = useNavigate()

  const columns: Column<DirectoryUser>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (u) => (
        <div className="min-w-0">
          <p className="truncate font-medium">{u.displayName || u.login}</p>
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
        empty="Nobody yet."
        onRowClick={(u) => {
          void navigate({ to: '/admin/users/$login', params: { login: u.login } })
        }}
      />
    </div>
  )
}
