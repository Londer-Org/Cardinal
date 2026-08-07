import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { z } from 'zod'
import { Button } from '@/components/ui/button'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { ErrorMessage } from '@/components/ErrorMessage'
import { GroupPicker } from './GroupPicker'
import { useGrantMembership } from './useDirectory'

/**
 * What this form holds, which is not what the API takes.
 *
 * The wire wants an absolute `until` timestamp; a person picks "30 days". The
 * conversion happens on submit, so the schema describes the fields as typed
 * rather than as sent — `grantRequest` in lib/api/requests.ts is the other end
 * and checks the result.
 */
const grantForm = z.object({
  group: z.string().min(1, 'Choose a group.'),
  // null is "no end date", which is a real choice and not a missing value.
  days: z.number().int().positive().nullable(),
  reason: z
    .string()
    .trim()
    .min(1, 'Say why — this is what someone reads six months from now.')
    .max(500, 'At most 500 characters.'),
})
type GrantForm = z.infer<typeof grantForm>

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
export function GrantForm({
  member,
  alreadyIn,
}: {
  member: string
  /** Groups this person is already in, so the picker can say why one is not
   *  selectable rather than leaving it looking broken. */
  alreadyIn: string[]
}) {
  const grant = useGrantMembership()

  const form = useForm<GrantForm>({
    resolver: zodResolver(grantForm),
    defaultValues: { group: '', days: 30, reason: '' },
  })

  return (
    <Form {...form}>
      <form
        className="space-y-3 rounded-md border p-3"
        onSubmit={(event) => {
          void form.handleSubmit(({ group, days, reason }) => {
            const until =
              days === null
                ? undefined
                : new Date(Date.now() + days * 86_400_000).toISOString()

            grant.mutate(
              { group, member, ...(until === undefined ? {} : { until }), reason },
              {
                onSuccess: () => {
                  // The duration stays: granting two people the same access is
                  // the common case, and re-picking it every time is how people
                  // end up leaving it on "No end date".
                  form.reset({ group: '', days, reason: '' })
                },
              },
            )
          })(event)
        }}
      >
        <p className="text-xs font-medium text-muted-foreground">Add to a group</p>

        <div className="grid gap-2 sm:grid-cols-2">
          <FormField
            control={form.control}
            name="group"
            render={({ field }) => (
              <FormItem className="gap-1">
                <FormLabel className="text-xs">Group</FormLabel>
                <GroupPicker
                  id={`grant-group-${member}`}
                  value={field.value}
                  onChange={field.onChange}
                  alreadyIn={alreadyIn}
                />
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name="days"
            render={({ field }) => (
              <FormItem className="gap-1">
                <FormLabel className="text-xs">Expires</FormLabel>
                <FormControl>
                  <select
                    className="h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs outline-none focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 dark:bg-input/30"
                    value={field.value === null ? 'none' : String(field.value)}
                    onChange={(event) => {
                      field.onChange(
                        event.target.value === 'none'
                          ? null
                          : Number(event.target.value),
                      )
                    }}
                  >
                    {DURATIONS.map((d) => (
                      <option
                        key={d.label}
                        value={d.days === null ? 'none' : String(d.days)}
                      >
                        {d.label}
                      </option>
                    ))}
                  </select>
                </FormControl>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <FormField
          control={form.control}
          name="reason"
          render={({ field }) => (
            <FormItem className="gap-1">
              <FormLabel className="text-xs">Reason</FormLabel>
              <FormControl>
                <Input placeholder="Ticket, incident, or why" {...field} />
              </FormControl>
              <FormDescription className="text-xs">
                {/* Kept when the grant is revoked, because revocation truncates
                    the period rather than deleting the row. It is what an
                    auditor reads. */}
                Survives revocation — this is what someone reads six months from
                now.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <ErrorMessage error={grant.error} />

        <Button type="submit" size="sm" disabled={grant.isPending}>
          {grant.isPending ? 'Granting…' : 'Grant'}
        </Button>
      </form>
    </Form>
  )
}
