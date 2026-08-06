import { RecoveryRequests } from '@/features/recovery/RecoveryRequests'
import { RequiresFreshAuth } from '@/features/auth/RequiresFreshAuth'
import { ViewHeader } from '@/views/ViewHeader'

function RecoveryViewBody() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Recovery"
        description="Restoring access to an account that can already sign in takes two administrators."
      />
      <div className="max-w-3xl">
        <RecoveryRequests />
      </div>
    </div>
  )
}

/**
 * Guarded, so arriving here with a stale session shows what is needed rather
 * than firing requests that will be refused — which produced an empty table
 * under the words "Nobody yet.", a statement about the directory and a false
 * one.
 */
export function RecoveryView() {
  return (
    <RequiresFreshAuth>
      <RecoveryViewBody />
    </RequiresFreshAuth>
  )
}
