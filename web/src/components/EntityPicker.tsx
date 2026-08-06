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

export interface PickerOption {
  value: string
  label: string

  /** Shown greyed after the label, e.g. a display name or a member count. */
  hint?: string

  /** Why this one cannot be chosen. Present means disabled. */
  unavailable?: string
}

/**
 * Picks one named thing from the ones that exist.
 *
 * The search runs wherever the caller's query runs — which for every current
 * use is the server, so this works on a directory with hundreds of entries
 * rather than only on one small enough to send whole. When the list is
 * truncated it says so: one that silently stops at fifty is one where the thing
 * you wanted is absent for no visible reason.
 *
 * Options that cannot be chosen are shown disabled with a reason rather than
 * filtered out. Hiding them turns "where is engineers?" into a mystery.
 */
export function EntityPicker({
  id,
  value,
  onChange,
  options,
  total,
  isPending,
  search,
  onSearch,
  placeholder,
  searchPlaceholder,
  emptyLabel,
}: {
  id: string
  value: string
  onChange: (value: string) => void
  options: PickerOption[]
  total: number
  isPending: boolean
  search: string
  onSearch: (value: string) => void
  placeholder: string
  searchPlaceholder: string
  emptyLabel: string
}) {
  const [open, setOpen] = useState(false)

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
            <span className="text-muted-foreground">{placeholder}</span>
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
            onChange={(event) => { onSearch(event.target.value) }}
            placeholder={searchPlaceholder}
            aria-label={searchPlaceholder}
            className="border-0 pl-9 shadow-none focus-visible:ring-0"
          />
        </div>

        <div className="max-h-64 overflow-y-auto p-1">
          {isPending ? (
            <div className="space-y-2 p-2">
              <Skeleton className="h-5 w-full" />
              <Skeleton className="h-5 w-full" />
            </div>
          ) : options.length === 0 ? (
            <p className="p-3 text-sm text-muted-foreground">
              {search === '' ? emptyLabel : `Nothing matches “${search}”.`}
            </p>
          ) : (
            options.map((option) => (
              <button
                key={option.value}
                type="button"
                disabled={option.unavailable !== undefined}
                onClick={() => {
                  onChange(option.value)
                  setOpen(false)
                }}
                className={cn(
                  'flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm',
                  option.unavailable === undefined
                    ? 'hover:bg-accent hover:text-accent-foreground'
                    : 'cursor-not-allowed opacity-50',
                )}
              >
                <CheckIcon
                  className={cn(
                    'size-4 shrink-0',
                    value === option.value ? 'opacity-100' : 'opacity-0',
                  )}
                />
                <span className="min-w-0 flex-1 truncate">
                  {option.label}
                  {option.hint !== undefined && option.hint !== '' && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      {option.hint}
                    </span>
                  )}
                </span>
                {option.unavailable !== undefined && (
                  <span className="shrink-0 text-xs text-muted-foreground">
                    {option.unavailable}
                  </span>
                )}
              </button>
            ))
          )}
        </div>

        {total > options.length && (
          <p className="border-t px-3 py-2 text-xs text-muted-foreground">
            Showing {options.length} of {total}. Search to narrow.
          </p>
        )}
      </PopoverContent>
    </Popover>
  )
}
