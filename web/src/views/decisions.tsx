import { DecisionExplorer } from '@/features/decisions/DecisionExplorer'
import { ViewHeader } from '@/views/ViewHeader'

export function DecisionsView() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Decisions"
        description="Why access was allowed or refused, and which rule decided."
      />
      <DecisionExplorer />
    </div>
  )
}
