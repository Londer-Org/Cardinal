import { useQuery } from '@tanstack/react-query'
import { api, queryKeys } from '@/lib/api'

/**
 * Which build is serving this console.
 *
 * Asked of the server rather than compiled into the bundle. The UI is embedded
 * in the binary, so the two cannot normally disagree — and if they ever did,
 * the number worth showing is the one the thing answering requests reports,
 * not the one this JavaScript was built with.
 *
 * Small and quiet on purpose. It is the first thing anybody needs during an
 * incident and the last thing they need any other time.
 */
export function BuildVersion() {
  const { data } = useQuery({
    queryKey: queryKeys.health,
    queryFn: api.health,
    // It cannot change without the process restarting, and a restart drops
    // this browser's connection anyway.
    staleTime: Infinity,
  })

  if (data === undefined) return null

  return (
    <p
      className="px-2 pb-1 text-center font-mono text-[0.65rem] text-muted-foreground group-data-[collapsible=icon]:hidden"
      title="The version this server reports"
    >
      {data.version}
    </p>
  )
}
