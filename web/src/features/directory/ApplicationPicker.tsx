import { useState } from 'react'
import { EntityPicker } from '@/components/EntityPicker'
import { useApplicationRefs } from './useDirectory'

/**
 * Picks the application a group exists for.
 *
 * Backed by a names-only endpoint readable by whoever manages groups. Typing
 * the name was the previous answer, and a typo produced a group owned by
 * nothing with no indication that anything had gone wrong.
 */
export function ApplicationPicker({
  id,
  value,
  onChange,
}: {
  id: string
  value: string
  onChange: (application: string) => void
}) {
  const [search, setSearch] = useState('')
  const { data, isPending } = useApplicationRefs({ q: search, limit: 50, offset: 0 })

  return (
    <EntityPicker
      id={id}
      value={value}
      onChange={onChange}
      search={search}
      onSearch={setSearch}
      isPending={isPending}
      total={data?.total ?? 0}
      placeholder="No application"
      searchPlaceholder="Search applications"
      emptyLabel="No applications registered."
      options={(data?.items ?? []).map((app) => ({
        value: app.name,
        label: app.name,
        hint: app.displayName,
      }))}
    />
  )
}
