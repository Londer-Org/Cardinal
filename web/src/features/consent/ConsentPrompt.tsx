import { CheckIcon } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { CardinalMark } from '@/components/CardinalMark'
import type { Me, PendingAuthorization } from '@/lib/api'

/**
 * Asks whether an application may have the claims it requested.
 *
 * Shown only for applications registered with `-consent` — a third party, not
 * something the organisation runs itself. A prompt in front of every internal
 * application is one more thing people learn to click through without reading,
 * which leaves a record of agreement nobody actually gave.
 */
export function ConsentPrompt({
  pending,
  session,
  onDecide,
  deciding,
}: {
  pending: PendingAuthorization
  session: Me
  onDecide: (approve: boolean) => void
  deciding: boolean
}) {
  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardinalMark className="size-8 text-foreground" />
          <CardTitle className="pt-2">
            {/* The application name is the load-bearing word on this screen, so
                it is the thing emphasised. Someone skimming should still come
                away knowing who is asking. */}
            Allow <span className="font-semibold">{pending.application}</span> to
            access your account?
          </CardTitle>
          <CardDescription>
            You are signed in as {session.displayName || session.login}.
          </CardDescription>
        </CardHeader>

        <CardContent>
          <p className="text-sm font-medium">This will let it see:</p>
          <ul className="mt-3 space-y-2">
            {pending.scopes.map((scope) => (
              <li key={scope.scope} className="flex items-start gap-2 text-sm">
                <CheckIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <span>
                  {scope.description}
                  {/* The raw scope stays visible next to its description.
                      Someone who knows OIDC can check the wording is honest,
                      and someone who does not can ignore it. */}
                  <span className="ml-1.5 text-xs text-muted-foreground">
                    {scope.scope}
                  </span>
                </span>
              </li>
            ))}
          </ul>

          <p className="mt-4 text-xs text-muted-foreground">
            You can withdraw this at any time from Connected applications, which
            also signs the application out.
          </p>
        </CardContent>

        <CardFooter className="gap-2">
          {/* Refusal first in the DOM and given equal weight. Burying it, or
              styling it as the lesser option, makes the prompt a formality. */}
          <Button
            variant="outline"
            className="flex-1"
            onClick={() => { onDecide(false) }}
            disabled={deciding}
          >
            Cancel
          </Button>
          <Button
            className="flex-1"
            onClick={() => { onDecide(true) }}
            disabled={deciding}
          >
            {deciding ? 'Continuing…' : 'Allow'}
          </Button>
        </CardFooter>
      </Card>
    </div>
  )
}
