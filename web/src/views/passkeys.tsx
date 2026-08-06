import { CredentialList } from '@/features/credentials/CredentialList'
import { StepUpPrompt } from '@/features/auth/StepUpPrompt'
import { useSession } from '@/features/auth/useAuth'
import { ViewHeader } from '@/views/ViewHeader'

export function PasskeysView() {
  const { session } = useSession()

  return (
    <div className="space-y-4">
      <ViewHeader
        title="Passkeys"
        description="Keep at least two, ideally on separate devices."
      />
      <div className="max-w-2xl space-y-4">
        <CredentialList />
        {/* Offered here as well as in the admin section: someone whose session
            has gone stale may be here precisely to fix that. */}
        {session?.adminNeedsReauth === true && <StepUpPrompt />}
      </div>
    </div>
  )
}
