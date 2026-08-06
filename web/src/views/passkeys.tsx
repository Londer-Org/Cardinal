import { CredentialList } from '@/features/credentials/CredentialList'
import { ViewHeader } from '@/views/ViewHeader'

export function PasskeysView() {
  return (
    <div className="space-y-4">
      <ViewHeader
        title="Passkeys"
        description="Keep at least two, ideally on separate devices."
      />
      <div className="max-w-2xl">
        <CredentialList />
      </div>
    </div>
  )
}
