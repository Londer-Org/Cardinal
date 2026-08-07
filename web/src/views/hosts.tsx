import { Link } from '@tanstack/react-router'
import { CircleSlashIcon, TagIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { ErrorMessage } from '@/components/ErrorMessage'
import { DataTable, type Column } from '@/components/DataTable'
import { useHosts } from '@/features/directory/useDirectory'
import { usePageState } from '@/features/directory/usePageState'
import type { DirectoryHost } from '@/lib/api'
import { CreateHost } from '@/features/directory/CreateHost'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

/**
 * How long since an agent checked in before it is worth looking at.
 *
 * The agent refreshes every five minutes by default, so an hour is twelve
 * missed attempts — comfortably past a restart or a network blip, and well
 * short of raising an alarm about a machine that was simply rebooting.
 */
const STALE_AFTER_MS = 60 * 60 * 1000

/** How long ago, in the roughest useful terms. */
function ago(iso: string): string {
  const elapsed = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(elapsed / 60_000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

/**
 * The column the page exists for.
 *
 * Three states that need to look different, because they call for different
 * things. Never enrolled is a machine nobody has set up. Silent is one that was
 * working and stopped — decommissioned, or broken, and either is worth knowing
 * before somebody tries to log into it. Recent is the boring case and should
 * look boring.
 */
function LastSeen({ host }: { host: DirectoryHost }) {
  if (!host.enrolled) {
    return <span className="text-muted-foreground">never enrolled</span>
  }
  if (host.lastSeen === '') {
    return <span className="text-muted-foreground">not yet</span>
  }

  const stale = Date.now() - new Date(host.lastSeen).getTime() > STALE_AFTER_MS
  return (
    <span
      className={stale ? 'text-amber-600 dark:text-amber-500' : undefined}
      title={new Date(host.lastSeen).toLocaleString()}
    >
      {ago(host.lastSeen)}
    </span>
  )
}

function HostsViewBody() {
  const { page, setSearch, setOffset, setLimit } = usePageState()
  const { data, isPending, error } = useHosts(page)

  const columns: Column<DirectoryHost>[] = [
    {
      key: 'name',
      header: 'Name',
      cell: (h) => (
        <span className="flex items-center gap-2">
          <Link
            to="/directory/hosts/$name"
            params={{ name: h.name }}
            className={
              h.disabled
                ? 'font-medium line-through underline-offset-4 hover:underline'
                : 'font-medium underline-offset-4 hover:underline'
            }
          >
            {h.name}
          </Link>
          {h.disabled && (
            <Badge variant="secondary" className="font-normal">
              <CircleSlashIcon className="size-3" />
              Disabled
            </Badge>
          )}
        </span>
      ),
    },
    {
      key: 'lastSeen',
      header: 'Last seen',
      width: '9rem',
      cell: (h) => <LastSeen host={h} />,
    },
    {
      key: 'groups',
      header: 'Groups',
      width: '7rem',
      // A host in no group is one no policy rule can reach, so it resolves
      // nobody and grants nobody — which looks like the agent being broken.
      cell: (h) =>
        h.groups === 0 ? (
          <span className="text-muted-foreground" title="No policy rule can reach this host">
            none
          </span>
        ) : (
          h.groups
        ),
    },
    {
      key: 'aliases',
      header: 'Extra names',
      width: '8rem',
      secondary: true,
      cell: (h) =>
        h.aliases === 0 ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          <Badge variant="secondary" className="font-normal">
            <TagIcon className="size-3" />
            {h.aliases}
          </Badge>
        ),
    },
    {
      key: 'displayName',
      header: 'Description',
      secondary: true,
      cell: (h) =>
        h.displayName === '' ? (
          <span className="text-muted-foreground">—</span>
        ) : (
          h.displayName
        ),
    },
  ]

  return (
    <div className="flex h-full min-h-0 flex-col gap-4">
      <ViewHeader
        title="Hosts"
        description="Machines that run cardinal-agent. Last seen is when each one last asked what it should serve."
        action={<CreateHost />}
      />

      <ErrorMessage error={error} />

      <DataTable
        columns={columns}
        rows={data?.items ?? []}
        rowKey={(h) => h.name}
        total={data?.total ?? 0}
        offset={page.offset}
        limit={page.limit}
        onPage={setOffset}
        onLimit={setLimit}
        search={page.q}
        onSearch={setSearch}
        searchPlaceholder="Search hosts and their names"
        isPending={isPending}
        empty="No hosts yet. Add one, then enrol the machine from its page."
      />
    </div>
  )
}

/**
 * Hosts are read behind the same tier as people and groups: whoever decides who
 * may reach a machine needs to see which machines exist.
 */
export function HostsView() {
  return (
    <RequiresFreshAuth>
      <HostsViewBody />
    </RequiresFreshAuth>
  )
}
