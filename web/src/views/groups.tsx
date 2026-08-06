import { useNavigate } from '@tanstack/react-router'
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
      cell: (g) => <span className="font-medium">{g.name}</span>,
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
        description="What policy reads. Membership is temporal — counts are as of now."
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
