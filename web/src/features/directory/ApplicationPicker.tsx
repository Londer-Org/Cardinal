import { useState } from 'react'
import { EntityPicker } from '@/components/EntityPicker'
import { useApplicationRefs } from './useDirectory'

/**
 * Picks an application: the one a group exists for, or the one to send
 * security events to.
 *
 * Backed by a names-only endpoint readable by whoever manages groups. Typing
 * the name was the previous answer, and a typo produced a group owned by
 * nothing with no indication that anything had gone wrong.
 *
 * `unavailable` marks the ones that exist but cannot be chosen here, and
 * returns why. Callers that filtered such entries out of the list instead
 * produced the question this cannot answer: an operator who knows `web-app` is
 * registered, and finds it missing from the picker, has no way to learn that it
 * is missing because it already has what they were about to add.
 */
export function ApplicationPicker({
  id,
  value,
  onChange,
  unavailable,
  placeholder = 'No application',
}: {
  id: string
  value: string
  onChange: (application: string) => void
  unavailable?: (application: string) => string | undefined
  placeholder?: string
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
      placeholder={placeholder}
      searchPlaceholder="Search applications"
      emptyLabel="No applications registered."
      options={(data?.items ?? []).map((app) => {
        const why = unavailable?.(app.name)
        return {
          value: app.name,
          label: app.name,
          hint: app.displayName,
          // Spread rather than `unavailable: why`, because
          // exactOptionalPropertyTypes distinguishes an absent property from
          // one present and undefined, and PickerOption treats present as
          // disabled.
          ...(why === undefined ? {} : { unavailable: why }),
        }
      })}
    />
  )
}
