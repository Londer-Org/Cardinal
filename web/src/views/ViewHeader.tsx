/**
 * A page's title and its one primary action.
 *
 * Its own component so every view puts them in the same place — the thing a
 * console loses first when each screen is laid out by hand.
 */
export function ViewHeader({
  title,
  description,
  action,
}: {
  title: string
  description?: string | undefined
  action?: React.ReactNode | undefined
}) {
  return (
    <div className="flex shrink-0 flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {description !== undefined && (
          <p className="mt-1 text-sm text-muted-foreground">{description}</p>
        )}
      </div>
      {action}
    </div>
  )
}
