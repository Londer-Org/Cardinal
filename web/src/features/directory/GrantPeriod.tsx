import type { Grant } from '@/lib/api'

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
