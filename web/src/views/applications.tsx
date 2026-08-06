import { ApplicationList } from '@/features/applications/ApplicationList'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

function ApplicationsViewBody() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Applications"
        description="Relying parties that can sign users in through Cardinal."
      />
      <ApplicationList />
    </div>
  )
}

/**
 * Guarded, so arriving here with a stale session shows what is needed rather
 * than firing requests that will be refused — which produced an empty table
 * under the words "Nobody yet.", a statement about the directory and a false
 * one.
 */
export function ApplicationsView() {
  return (
    <RequiresFreshAuth>
      <ApplicationsViewBody />
    </RequiresFreshAuth>
  )
}
