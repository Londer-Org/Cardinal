import { KeyRoundIcon, ShieldAlertIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { CardinalMark } from '@/components/CardinalMark'
import { ErrorMessage } from '@/components/ErrorMessage'
import { isSupported } from '@/lib/webauthn'
import { useLogin } from './useAuth'

/**
 * The sign-in page.
 *
 * Deliberately not a form in a box. There is nothing to fill in — no username,
 * no password, no second factor to fetch — so a card with one button in it
 * looks like a form someone forgot to finish. What the page has to do instead
 * is be obviously Cardinal, obviously legitimate, and obviously finished.
 *
 * That last one matters more here than anywhere else in the product. This is
 * the page an attacker would clone, so the moment it looks improvised is the
 * moment a real one stops being distinguishable from a fake.
 */
export function LoginPage({
  continuingToApplication = false,
}: {
  /** True when an application sent the user here to sign in. */
  continuingToApplication?: boolean
}) {
  const login = useLogin()

  if (!isSupported()) {
    return (
      <Shell>
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertTitle>Passkeys are not available</AlertTitle>
          <AlertDescription>
            Cardinal has no passwords, so a browser supporting WebAuthn is
            required to sign in.
          </AlertDescription>
        </Alert>
      </Shell>
    )
  }

  return (
    <Shell>
      <div className="flex flex-col items-center text-center">
        <CardinalMark className="size-20 text-foreground" />

        <h1 className="mt-6 text-3xl font-semibold tracking-tight">Cardinal</h1>

        {/* Wide enough that the sentence does not orphan its last word,
            which reads as a rendering fault rather than a line break. */}
        <p className="mt-3 max-w-[22rem] text-sm text-muted-foreground">
          {continuingToApplication
            ? 'An application needs you to sign in. Use your passkey — there is nothing to type.'
            : 'Sign in with your passkey. There is nothing to type.'}
        </p>

        <Button
          className="mt-8 w-full"
          size="lg"
          onClick={() => { login.mutate() }}
          disabled={login.isPending}
        >
          <KeyRoundIcon />
          {login.isPending ? 'Waiting for your device…' : 'Sign in'}
        </Button>

        <div className="w-full text-left">
          <ErrorMessage error={login.error} />
        </div>

        <p className="mt-10 text-xs text-muted-foreground">
          {/* No emergency entry point. Recovery is an administrator issuing an
              enrollment invitation (ADR 0014), which needs access to the server
              rather than a second internet-facing credential. */}
          Lost your device? Ask an administrator for a new enrollment link.
        </p>
      </div>
    </Shell>
  )
}

/**
 * The page around it.
 *
 * The wash behind the mark is the brand blue at a few percent, positioned where
 * the compass sits. It is doing one job: making a screenshot of this page
 * recognisably Cardinal rather than recognisably a login page. Kept subtle
 * enough to survive both themes and to stay out of the way of the only control
 * that matters.
 */
function Shell({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-dvh place-items-center overflow-hidden bg-background p-6">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-[60vh] bg-[radial-gradient(60%_60%_at_50%_0%,var(--primary)_0%,transparent_70%)] opacity-[0.10] dark:opacity-[0.14]"
      />
      <div className="relative w-full max-w-sm">{children}</div>
    </div>
  )
}
