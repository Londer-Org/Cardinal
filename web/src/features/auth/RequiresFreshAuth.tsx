import { KeyRoundIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { ErrorMessage } from '@/components/ErrorMessage'
import { useSession } from './useAuth'
import { useStepUp } from './useStepUp'

/**
 * Guards a view that needs a recently-used key.
 *
 * Whether the request will be refused is known before making it — /api/auth/me
 * says so — and asking anyway produced the worst possible screen: an empty
 * table under the words "Nobody yet.", which is not "you were refused" but a
 * statement about the directory, and a false one.
 *
 * So the view does not run its queries at all until the session is fresh. What
 * replaces them says why, and offers the fix in the place the user is already
 * looking. That is also what makes "Not now" a reasonable answer rather than a
 * way to get stuck: dismissing the dialog leaves this, not a fabrication.
 */
export function RequiresFreshAuth({ children }: { children: React.ReactNode }) {
  const { session } = useSession()
  const stepUp = useStepUp()

  if (session === null || !session.adminNeedsReauth) {
    return <>{children}</>
  }

  return (
    <Card className="max-w-lg">
      <CardHeader>
        <CardTitle>Confirm it is you</CardTitle>
        <CardDescription>
          Changing who can reach what needs a security key used in the last five
          minutes.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {/* Asks the device directly. This used to open the dialog, which put
            the same words and the same button in front of somebody who had just
            read them and pressed it — two clicks for one decision. */}
        <Button
          onClick={() => { stepUp.mutate() }}
          disabled={stepUp.isPending}
        >
          <KeyRoundIcon />
          {stepUp.isPending ? 'Waiting for your device…' : 'Use my security key'}
        </Button>

        <ErrorMessage error={stepUp.error} />
        <p className="mt-4 text-xs text-muted-foreground">
          {/* Said once, plainly. A step-up nobody understands is one they
              resent, and a rule people resent is one that gets removed. */}
          A long-running session is fine for reading and not for changing who
          can reach what. Your session stays as it is — this only re-proves the
          key.
        </p>
      </CardContent>
    </Card>
  )
}
