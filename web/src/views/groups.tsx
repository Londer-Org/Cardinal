import { useNavigate } from '@tanstack/react-router'
import { ShieldIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ErrorMessage } from '@/components/ErrorMessage'
import { DataTable, type Column } from '@/components/DataTable'
import { CreateGroup } from '@/features/directory/CreateGroup'
import { useGroups } from '@/features/directory/useDirectory'
import { usePageState } from '@/features/directory/usePageState'
import type { DirectoryGroup } from '@/lib/api'
import { ViewHeader } from '@/views/ViewHeader'

export function GroupsView() {
  const { page, setSearch, setOffset, setLimit } = usePageState()
  const { data, isPending, error } = useGroups(page)
  const navigate = useNavigate()

  const columns: Column<DirectoryGroup>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (g) => (
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-medium">{g.name}</span>
          {/* Two kinds of group share this table, and only one of them hands
              out administrative power. Saying which is the difference between
              a list and a list you can act on safely. */}
          {g.system && (
            <Badge variant="secondary" className="shrink-0 font-normal">
              <ShieldIcon className="size-3" />
              System
            </Badge>
          )}
          {g.owner !== '' && (
            <Badge variant="secondary" className="shrink-0 font-normal">
              {g.owner}
            </Badge>
          )}
        </span>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      secondary: true,
      cell: (g) =>
        g.displayName === '' ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          g.displayName
        ),
    },
    {
      key: 'members',
      header: 'Members',
      width: '7rem',
      cell: (g) => g.members,
    },
  ]

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <ViewHeader
        title="Groups"
        description="What policy reads. System groups confer authority inside Cardinal; the rest are for applications."
        action={<CreateGroup />}
      />

      <ErrorMessage error={error} />

      <DataTable
        columns={columns}
        rows={data?.items ?? []}
        rowKey={(g) => g.name}
        total={data?.total ?? 0}
        offset={page.offset}
        limit={page.limit}
        onPage={setOffset}
        onLimit={setLimit}
        search={page.q}
        onSearch={setSearch}
        searchPlaceholder="Search groups"
        isPending={isPending}
        empty="No groups yet."
        onRowClick={(g) => {
          void navigate({ to: '/admin/groups/$name', params: { name: g.name } })
        }}
      />
    </div>
  )
}
