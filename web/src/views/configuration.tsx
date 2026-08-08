import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, EyeOff } from 'lucide-react'
import { api, queryKeys, type Setting } from '@/lib/api'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { ViewHeader } from '@/views/ViewHeader'

/**
 * What this deployment is configured to do.
 *
 * Read-only, and that is the design rather than a first step. Most of
 * cardinal.toml cannot move into the database — the connection string is what
 * reads it, and the encryption keys decrypt what is stored there — and of the
 * rest, changing the relying-party id stops every registered passkey working.
 * Those should be hard to change, and a form is not hard.
 *
 * The value this adds is seeing, not editing. Two settings in that file were
 * parsed, validated, and read by nothing; it took an audit to notice, and this
 * page would have said so on the day.
 */
export function ConfigurationView() {
  const { data, isPending, error } = useQuery({
    queryKey: queryKeys.config(),
    queryFn: () => api.config(),
  })

  if (isPending) return <Skeleton className="h-64 w-full" />
  if (error) {
    return (
      <Alert variant="destructive">
        <AlertTriangle className="size-4" />
        <AlertDescription>Could not read the configuration.</AlertDescription>
      </Alert>
    )
  }

  const ignored = data.settings.filter((s) => s.ignored)
  const sections = [...new Set(data.settings.map((s) => s.section))]

  return (
    <div className="space-y-6">
      <ViewHeader
        title="Configuration"
        description="What this server is running with, and where each value came from."
      />

      {ignored.length > 0 && (
        <Alert variant="destructive">
          <AlertTriangle className="size-4" />
          <AlertTitle>
            {ignored.length} setting{ignored.length === 1 ? '' : 's'} nothing
            reads
          </AlertTitle>
          <AlertDescription>
            These are accepted and validated, and then used by nothing. Setting
            one changes no behaviour, which is worse than it being absent —
            absent is obvious.
          </AlertDescription>
        </Alert>
      )}

      <p className="max-w-2xl text-sm text-muted-foreground">
        Read-only. Most of this cannot live anywhere but the file — the
        connection string is what reads the database, and the encryption keys
        decrypt what is in it. Of the rest, changing the relying-party id stops
        every registered passkey working, which is a thing that should be hard.
      </p>

      {sections.map((section) => (
        <section key={section} className="space-y-2">
          <h2 className="font-mono text-sm font-semibold">[{section}]</h2>
          <div className="overflow-x-auto rounded-lg border">
            <table className="w-full text-sm">
              <tbody>
                {data.settings
                  .filter((s) => s.section === section)
                  .map((s) => (
                    <Row key={s.name} setting={s} />
                  ))}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  )
}

function Row({ setting }: { setting: Setting }) {
  return (
    <tr className="border-b last:border-0">
      <td className="w-64 px-4 py-2 align-top font-mono text-xs">
        {setting.name}
      </td>
      <td className="px-4 py-2 align-top">
        <span className="font-mono text-xs">{setting.value || '—'}</span>
        {setting.secret && (
          <span className="ml-2 inline-flex items-center gap-1 text-xs text-muted-foreground">
            <EyeOff className="size-3" />
            withheld
          </span>
        )}
        {setting.ignored && (
          <p className="mt-1 max-w-xl text-xs text-destructive">
            {setting.ignored}
          </p>
        )}
      </td>
      <td className="w-40 px-4 py-2 text-right align-top">
        <Source source={setting.source} />
      </td>
    </tr>
  )
}

/**
 * Where the value came from.
 *
 * "default" is the one worth noticing: it means nobody decided, and the
 * deployment is relying on a number this project happened to pick.
 */
function Source({ source }: { source: Setting['source'] }) {
  if (source === 'default') {
    return (
      <Badge variant="outline" className="text-muted-foreground">
        default
      </Badge>
    )
  }
  return <Badge variant="secondary">{source}</Badge>
}
