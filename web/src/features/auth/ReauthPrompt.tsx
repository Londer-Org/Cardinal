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
import { useStepUp } from './useStepUp'

/**
 * Asks for the security key because an application asked for one.
 *
 * Distinct from the step-up dialog, which appears when Cardinal's own policy
 * refuses something. Here nothing has been refused and the session is fine: a
 * relying party sent `prompt=login`, or a `max_age` this session no longer
 * satisfies, and it is entitled to an answer about how the person in front of
 * it authenticated rather than an answer about a session from this morning.
 *
 * Says which application asked, because otherwise this is a security-key prompt
 * appearing for no visible reason during what looked like an ordinary sign-in —
 * and a credential prompt nobody can account for is one people learn to click
 * through.
 */
export function ReauthPrompt({
  application,
  onAuthenticated,
}: {
  application: string
  onAuthenticated: () => void
}) {
  const stepUp = useStepUp()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Confirm it is you</CardTitle>
        <CardDescription>
          {application} asked for a fresh sign-in rather than an existing
          session. Use your security key and you will be sent straight back.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <ErrorMessage error={stepUp.error} />
        <Button
          className="w-full"
          disabled={stepUp.isPending}
          onClick={() => {
            stepUp.mutate(undefined, { onSuccess: onAuthenticated })
          }}
        >
          <KeyRoundIcon />
          {stepUp.isPending ? 'Waiting for your device…' : 'Use my security key'}
        </Button>
      </CardContent>
    </Card>
  )
}
