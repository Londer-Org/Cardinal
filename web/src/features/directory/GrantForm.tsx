import { useState } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useGrantMembership, useGroups } from './useDirectory'

/** How long a grant lasts. */
const DURATIONS = [
  { label: '1 day', days: 1 },
  { label: '1 week', days: 7 },
  { label: '30 days', days: 30 },
  { label: '90 days', days: 90 },
  // Last, and named plainly. Offering "permanent" first is how every directory
  // ends up full of access nobody remembers granting.
  { label: 'No end date', days: null },
] as const

/**
 * Adding someone to a group, for a period.
 *
 * The temporal model is the flagship of the data model (ADR 0001) and was
 * reachable only from the CLI — so in practice every grant made through the
 * product was unbounded. Putting the duration in front of whoever is granting,
 * with a bounded option selected by default, is the difference between a
 * feature existing and a feature being used.
 */
export function GrantForm({ member }: { member: string }) {
  const { data: groups } = useGroups()
  const grant = useGrantMembership()

  const [group, setGroup] = useState('')
  const [days, setDays] = useState<number | null>(30)
  const [reason, setReason] = useState('')

  const available = (groups ?? []).map((g) => g.name)

  return (
    <form
      className="space-y-3 rounded-md border p-3"
      onSubmit={(event) => {
        event.preventDefault()
        if (group === '') return

        const until =
          days === null
            ? undefined
            : new Date(Date.now() + days * 86_400_000).toISOString()

        grant.mutate(
          { group, member, ...(until === undefined ? {} : { until }), reason: reason.trim() },
          {
            onSuccess: () => {
              setGroup('')
              setReason('')
            },
          },
        )
      }}
    >
      <p className="text-xs font-medium text-muted-foreground">Add to a group</p>

      <div className="grid gap-2 sm:grid-cols-2">
        <div className="space-y-1">
          <Label htmlFor={`grant-group-${member}`} className="text-xs">
            Group
          </Label>
          <Input
            id={`grant-group-${member}`}
            list={`groups-${member}`}
            value={group}
            onChange={(event) => { setGroup(event.target.value) }}
            placeholder="engineers"
            required
          />
          {/* A datalist rather than a select: the list can be long, and typing
              a name you already know beats scrolling to it. */}
          <datalist id={`groups-${member}`}>
            {available.map((name) => (
              <option key={name} value={name} />
            ))}
          </datalist>
        </div>

        <div className="space-y-1">
          <Label htmlFor={`grant-until-${member}`} className="text-xs">
            Expires
          </Label>
          <select
            id={`grant-until-${member}`}
            className="h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30"
            value={days === null ? 'none' : String(days)}
            onChange={(event) => {
              setDays(event.target.value === 'none' ? null : Number(event.target.value))
            }}
          >
            {DURATIONS.map((d) => (
              <option key={d.label} value={d.days === null ? 'none' : String(d.days)}>
                {d.label}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="space-y-1">
        <Label htmlFor={`grant-reason-${member}`} className="text-xs">
          Reason
        </Label>
        <Input
          id={`grant-reason-${member}`}
          value={reason}
          onChange={(event) => { setReason(event.target.value) }}
          placeholder="Ticket, incident, or why"
        />
        <p className="text-xs text-muted-foreground">
          {/* Kept when the grant is revoked, because revocation truncates the
              period rather than deleting the row. It is what an auditor reads. */}
          Survives revocation — this is what someone reads six months from now.
        </p>
      </div>

      <ErrorMessage error={grant.error} />

      <Button type="submit" size="sm" disabled={grant.isPending || group === ''}>
        {grant.isPending ? 'Granting…' : 'Grant'}
      </Button>
    </form>
  )
}
