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
import { useReAuth } from './useReAuth'

/**
 * Asks for the security key again, so administration can proceed.
 *
 * Shown in place of the admin section when membership is fine and only
 * freshness is missing. The alternative — and what happened before this
 * existed — is the section quietly disappearing five minutes after sign-in,
 * with nothing to indicate that tapping a key would bring it back.
 */
export function StepUpPrompt() {
  const reauth = useReAuth()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Confirm it is you</CardTitle>
        <CardDescription>
          Administering the directory needs a security key used in the last five
          minutes.
        </CardDescription>
      </CardHeader>

      <CardContent>
        <Button onClick={() => { reauth.mutate() }} disabled={reauth.isPending}>
          <KeyRoundIcon />
          {reauth.isPending ? 'Waiting for your device…' : 'Use my security key'}
        </Button>

        <ErrorMessage error={reauth.error} />

        <p className="mt-4 text-xs text-muted-foreground">
          {/* The reason, stated once. A step-up people do not understand is one
              they resent, and a rule people resent is one that gets removed. */}
          A long-running session is fine for reading and not for changing who can
          reach what. This keeps your session — it only re-proves the key.
        </p>
      </CardContent>
    </Card>
  )
}
