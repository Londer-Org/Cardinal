import { AlertCircleIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { Skeleton } from '@/components/ui/skeleton'
import { AccountPage } from '@/features/auth/AccountPage'
import { LoginPage } from '@/features/auth/LoginPage'
import { useSession } from '@/features/auth/useAuth'
import { pendingAuthorizationID, useOIDCResume } from '@/features/auth/useOIDCResume'
import { ConsentPrompt } from '@/features/consent/ConsentPrompt'
import { EnrollPage, invitationToken } from '@/features/enroll/EnrollPage'

/**
 * Routing is a branch on session state plus one special case: an OIDC
 * authorization parked mid-flow.
 *
 * Still no router. The OIDC case is not a route — it is a redirect the browser
 * passes through — so adding one would be machinery without a purpose. It
 * arrives when deep-linking to a specific decision is wanted.
 */
export function App() {
  // Enrollment is checked before anything else, and before the session query
  // has said anything. Someone following an invitation has no session by
  // definition, and making them wait for a request that is certain to 401 —
  // or worse, briefly showing them a sign-in page they cannot use — is a poor
  // first impression of the system they are joining.
  const token = invitationToken()
  if (token !== null) {
    return <EnrollPage token={token} />
  }

  return <AuthenticatedApp />
}

function AuthenticatedApp() {
  const { session, isLoading } = useSession()

  // An application may have sent the user here to sign in. If so, the
  // authorization is completed and the browser handed back the moment a session
  // exists — the hook navigates away itself, so nothing below renders. The one
  // exception is an application that requires consent, which stops to ask.
  const { state: resume, decide, deciding } = useOIDCResume(session !== null)

  if (isLoading) {
    return (
      <div className="grid min-h-dvh place-items-center bg-background p-6">
        <Skeleton className="h-48 w-full max-w-sm" />
      </div>
    )
  }

  if (session === null) {
    // Tell them why they are being asked to sign in. Arriving at a bare login
    // page after clicking something in another application is disorienting,
    // and the usual reaction is to assume it is a phishing page.
    return <LoginPage continuingToApplication={pendingAuthorizationID() !== null} />
  }

  if (resume.status === 'consent') {
    return (
      <ConsentPrompt
        pending={resume.pending}
        session={session}
        onDecide={decide}
        deciding={deciding}
      />
    )
  }

  if (resume.status === 'denied') {
    return (
      <Centered>
        <Alert variant="destructive">
          <AlertCircleIcon />
          <AlertTitle>No access to {resume.application}</AlertTitle>
          <AlertDescription>
            <p>{resume.reason}</p>
            {resume.policies.length > 0 && (
              // The deciding rule, named. Neither FreeIPA nor Keycloak can tell
              // you which policy refused you, and being able to quote it is the
              // difference between a useful support request and a shrug.
              <p className="mt-2 text-xs">
                Decided by <code>{resume.policies.join(', ')}</code>
              </p>
            )}
          </AlertDescription>
        </Alert>
      </Centered>
    )
  }

  if (resume.status === 'refused') {
    return (
      <Centered>
        <Alert>
          <AlertCircleIcon />
          <AlertTitle>Access not granted</AlertTitle>
          <AlertDescription>
            {resume.application} was not given access to your account, and has
            been sent nothing. You can close this tab, or carry on below.
          </AlertDescription>
        </Alert>
        {/* Deliberately not an automatic redirect back to the application.
            Bouncing someone straight back to the thing they just declined
            reads as the refusal not having worked. */}
      </Centered>
    )
  }

  if (resume.status === 'resuming') {
    return (
      <Centered>
        <p className="text-sm text-muted-foreground">
          Returning you to the application…
        </p>
      </Centered>
    )
  }

  if (resume.status === 'failed') {
    // Deliberately not silent. Someone who arrived from an application and
    // ends up on their account page would otherwise have no idea the thing
    // they were trying to reach is still waiting.
    return (
      <Centered>
        <Alert variant="destructive">
          <AlertCircleIcon />
          <AlertTitle>Could not return you to the application</AlertTitle>
          <AlertDescription>
            {resume.message} Start again from the application.
          </AlertDescription>
        </Alert>
      </Centered>
    )
  }

  return <AccountPage session={session} />
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
