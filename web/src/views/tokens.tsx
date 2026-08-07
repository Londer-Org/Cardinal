import { TokenList } from '@/features/tokens/TokenList'
import { ViewHeader } from '@/views/ViewHeader'

export function TokensView() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Access tokens"
        description="For scripts and automation, when a passkey cannot be used."
      />
      <div className="max-w-3xl">
        <TokenList />
      </div>
    </div>
  )
}
