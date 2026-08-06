import { useState } from 'react'
import { EntityPicker } from '@/components/EntityPicker'
import { useGroups } from './useDirectory'

/** Picks a group to grant. */
export function GroupPicker({
  id,
  value,
  onChange,
  alreadyIn,
}: {
  id: string
  value: string
  onChange: (group: string) => void
  /** Groups this person already belongs to, shown disabled with a reason. */
  alreadyIn: string[]
}) {
  const [search, setSearch] = useState('')
  const { data, isPending } = useGroups({ q: search, limit: 50, offset: 0 })

  return (
    <EntityPicker
      id={id}
      value={value}
      onChange={onChange}
      search={search}
      onSearch={setSearch}
      isPending={isPending}
      total={data?.total ?? 0}
      placeholder="Select a group"
      searchPlaceholder="Search groups"
      emptyLabel="No groups yet."
      options={(data?.items ?? []).map((group) => ({
        value: group.name,
        label: group.name,
        hint: group.displayName,
        ...(alreadyIn.includes(group.name)
          ? { unavailable: 'already a member' }
          : {}),
      }))}
    />
  )
}
