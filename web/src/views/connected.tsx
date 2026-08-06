import { ConnectedApplications } from '@/features/consent/ConnectedApplications'
import { ViewHeader } from '@/views/ViewHeader'

export function ConnectedView() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Connected applications"
        description="Applications you have allowed to see your account details."
      />
      <div className="max-w-2xl">
        <ConnectedApplications />
      </div>
    </div>
  )
}
