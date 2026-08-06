import { useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { ShieldIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { ErrorMessage } from '@/components/ErrorMessage'
import { DataTable, type Column } from '@/components/DataTable'
import { CreateGroup } from '@/features/directory/CreateGroup'
import { useGroups } from '@/features/directory/useDirectory'
import { usePageState } from '@/features/directory/usePageState'
import type { DirectoryGroup, GroupKind } from '@/lib/api'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

const KINDS: { value: GroupKind; label: string }[] = [
  { value: '', label: 'All groups' },
  { value: 'system', label: 'System' },
  { value: 'application', label: 'For an application' },
  { value: 'plain', label: 'Other' },
]

/** What kind of group this is, in one cell. */
function Category({ group }: { group: DirectoryGroup }) {
  if (group.system) {
    return (
      <Badge variant="secondary" className="font-normal">
        <ShieldIcon className="size-3" />
        System
      </Badge>
    )
  }
  if (group.owner !== '') {
    return (
      <Badge variant="secondary" className="font-normal">
        {group.owner}
      </Badge>
    )
  }
  return <span className="text-muted-foreground">—</span>
}

function GroupsViewBody() {
  const { page, setSearch, setOffset, setLimit } = usePageState()
  const [kind, setKind] = useState<GroupKind>('')
  const { data, isPending, error } = useGroups(page, kind)
  const navigate = useNavigate()

  const columns: Column<DirectoryGroup>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (g) => <span className="font-medium">{g.name}</span>,
    },
    {
      key: 'category',
      header: 'Category',
      width: '11rem',
      // Its own column rather than a badge tacked onto the name: this is what
      // you scan when looking for the group an application uses, and a name
      // with something appended is not something you can scan.
      cell: (g) => <Category group={g} />,
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
        description="System groups confer authority inside Cardinal; the rest are for applications."
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
        filters={
          <Select
            value={kind === '' ? 'all' : kind}
            onValueChange={(value) => {
              setKind(value === 'all' ? '' : (value as GroupKind))
              // Back to the first page. Filtering while on page four shows an
              // empty table and reads as "nothing matches".
              setOffset(0)
            }}
          >
            <SelectTrigger className="w-[190px]" aria-label="Filter by category">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {KINDS.map((k) => (
                <SelectItem key={k.label} value={k.value === '' ? 'all' : k.value}>
                  {k.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        }
        onRowClick={(g) => {
          void navigate({ to: '/directory/groups/$name', params: { name: g.name } })
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
export function GroupsView() {
  return (
    <RequiresFreshAuth>
      <GroupsViewBody />
    </RequiresFreshAuth>
  )
}
