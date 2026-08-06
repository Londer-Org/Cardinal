import { ProfileCard } from '@/features/auth/ProfileCard'
import { RecoveryCodes } from '@/features/recovery/RecoveryCodes'
import { useSession } from '@/features/auth/useAuth'
import { Skeleton } from '@/components/ui/skeleton'
import { ViewHeader } from '@/views/ViewHeader'

export function AccountView() {
  const { session } = useSession()
  if (session === null) return <Skeleton className="h-64 w-full" />

  return (
    <div className="space-y-4">
      <ViewHeader
        title="Your account"
        description="What applications see when they ask who you are."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <ProfileCard session={session} />
        <RecoveryCodes remaining={session.recoveryCodesRemaining} />
      </div>
    </div>
  )
}
