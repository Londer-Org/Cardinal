import { useState } from 'react'
import { CheckIcon, ChevronsUpDownIcon, SearchIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from '@/components/ui/popover'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { useGroups } from './useDirectory'

/**
 * Picks a group from the ones that exist.
 *
 * This was a text input with a `datalist`, which is not a list anybody can
 * browse: the suggestions only appear once you start typing something that
 * matches, so knowing what to type was a prerequisite for finding out what to
 * type. Granting access is exactly the moment you want to see the options.
 *
 * Search runs on the server, so this works on a directory with hundreds of
 * groups rather than only on one small enough to send whole.
 *
 * Groups the member already belongs to are listed and disabled rather than
 * hidden. Hiding them turns "where is engineers?" into a mystery; showing them
 * greyed out with a reason answers it.
 */
export function GroupPicker({
  value,
  onChange,
  alreadyIn,
  id,
}: {
  value: string
  onChange: (group: string) => void
  alreadyIn: string[]
  id: string
}) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')

  const { data, isPending } = useGroups({ q: search, limit: 50, offset: 0 })
  const groups = data?.items ?? []
  const total = data?.total ?? 0

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          id={id}
          type="button"
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between font-normal"
        >
          {value === '' ? (
            <span className="text-muted-foreground">Select a group</span>
          ) : (
            value
          )}
          <ChevronsUpDownIcon className="size-4 opacity-50" />
        </Button>
      </PopoverTrigger>

      <PopoverContent className="w-(--radix-popover-trigger-width) p-0">
        <div className="relative border-b">
          <SearchIcon className="absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(event) => { setSearch(event.target.value) }}
            placeholder="Search groups"
            aria-label="Search groups"
            className="border-0 pl-9 shadow-none focus-visible:ring-0"
          />
        </div>

        <div className="max-h-64 overflow-y-auto p-1">
          {isPending ? (
            <div className="space-y-2 p-2">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
            </div>
          ) : groups.length === 0 ? (
            <p className="p-3 text-sm text-muted-foreground">
              {search === ''
                ? 'No groups yet.'
                : `Nothing matches “${search}”.`}
            </p>
          ) : (
            groups.map((group) => {
              const member = alreadyIn.includes(group.name)

              return (
                <button
                  key={group.name}
                  type="button"
                  disabled={member}
                  onClick={() => {
                    onChange(group.name)
                    setOpen(false)
                  }}
                  className={cn(
                    'flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm',
                    member
                      ? 'cursor-not-allowed opacity-50'
                      : 'hover:bg-accent hover:text-accent-foreground',
                  )}
                >
                  <CheckIcon
                    className={cn(
                      'size-4 shrink-0',
                      value === group.name ? 'opacity-100' : 'opacity-0',
                    )}
                  />
                  <span className="min-w-0 flex-1 truncate">
                    {group.name}
                    {group.displayName !== '' && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {group.displayName}
                      </span>
                    )}
                  </span>
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {member ? 'already a member' : `${group.members}`}
                  </span>
                </button>
              )
            })
          )}
        </div>

        {total > groups.length && (
          <p className="border-t px-3 py-2 text-xs text-muted-foreground">
            {/* Said plainly rather than silently truncating. A list that stops
                at fifty without saying so is one where the group you wanted
                simply is not there, for no visible reason. */}
            Showing {groups.length} of {total}. Search to narrow.
          </p>
        )}
      </PopoverContent>
    </Popover>
  )
}
