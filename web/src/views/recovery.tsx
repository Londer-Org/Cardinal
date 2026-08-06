import { RecoveryRequests } from '@/features/recovery/RecoveryRequests'
import { ViewHeader } from '@/views/ViewHeader'

export function RecoveryView() {
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
