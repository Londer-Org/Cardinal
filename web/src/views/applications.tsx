import { ApplicationList } from '@/features/applications/ApplicationList'
import { ViewHeader } from '@/views/ViewHeader'

export function ApplicationsView() {
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
