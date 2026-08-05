import { Skeleton } from '@/components/ui/skeleton'
import { AccountPage } from '@/features/auth/AccountPage'
import { LoginPage } from '@/features/auth/LoginPage'
import { useSession } from '@/features/auth/useAuth'

/**
 * Routing is a single branch on session state, deliberately.
 *
 * Adding a router before there is more than one authenticated view would be
 * machinery without a purpose; it arrives in Phase 2 with the policy and
 * decision-explorer screens.
 */
export function App() {
  const { session, isLoading } = useSession()

  if (isLoading) {
    return (
      <div className="grid min-h-dvh place-items-center bg-background p-6">
        <Skeleton className="h-48 w-full max-w-sm" />
      </div>
    )
  }

  return session === null ? <LoginPage /> : <AccountPage session={session} />
}
