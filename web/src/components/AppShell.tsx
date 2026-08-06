import { Outlet, useRouterState } from '@tanstack/react-router'
import { AlertCircleIcon, ShieldQuestionIcon } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Separator } from '@/components/ui/separator'
import { Skeleton } from '@/components/ui/skeleton'
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'
import { AppSidebar } from '@/components/AppSidebar'
import { LoginPage } from '@/features/auth/LoginPage'
import { useSession } from '@/features/auth/useAuth'
import { pendingAuthorizationID, useOIDCResume } from '@/features/auth/useOIDCResume'
import { ConsentPrompt } from '@/features/consent/ConsentPrompt'
import { EnrollPage, invitationToken } from '@/features/enroll/EnrollPage'
import { StepUpDialog } from '@/features/auth/StepUpDialog'
import { ACCOUNT, locate } from '@/lib/nav'

/**
 * Everything that wraps a page: authentication, the OIDC hand-off, and the
 * chrome.
 *
 * Enrollment and sign-in deliberately render without the shell. Someone
 * following an invitation has no session and no navigation to offer, and
 * wrapping a sign-in page in a sidebar full of links they cannot use would be
 * an odd first impression.
 */
export function AppShell() {
  const token = invitationToken()
  if (token !== null) {
    return <EnrollPage token={token} />
  }

  return <Authenticated />
}

function Authenticated() {
  const { session, isLoading } = useSession()
  const { state: resume, decide, deciding } = useOIDCResume(session !== null)

  if (isLoading) {
    return (
      <div className="grid min-h-dvh place-items-center bg-background p-6">
        <Skeleton className="h-48 w-full max-w-sm" />
      </div>
    )
  }

  if (session === null) {
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

  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <header className="flex h-14 shrink-0 items-center gap-2 border-b px-4">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 h-4" />
          <Crumbs />
        </header>

        {/* Outside the scroll area on purpose. A view that wants a
            viewport-height table asks for h-full, and it should get exactly the
            space left over — not that minus however tall this banner is
            today. */}
        {!session.fullyEnrolled && (
          <div className="shrink-0 px-4 pt-4 md:px-6">
            <Alert className="border-warning/50 text-warning-foreground [&>svg]:text-warning">
              <ShieldQuestionIcon />
              <AlertTitle>Register a second passkey</AlertTitle>
              <AlertDescription>
                With only one, losing that device means losing the account. A
                hardware key kept somewhere else is the usual second.
              </AlertDescription>
            </Alert>
          </div>
        )}

        {/* The page scroller. Views that fill the height put their own scroll
            region inside instead, so a long table scrolls its rows rather than
            the whole screen — and its header and pagination stay put. */}
        <main className="min-h-0 min-w-0 flex-1 overflow-y-auto p-4 md:p-6">
          <Outlet />
        </main>

        {/* Mounted once, at the top. Any request refused for want of a fresh
            credential opens it, wherever the user happens to be — rather than
            the section they were looking at emptying itself and leaving them to
            work out that Passkeys is where the fix lives. */}
        <StepUpDialog />
      </SidebarInset>
    </SidebarProvider>
  )
}

/**
 * Where you are, read off the navigation rather than off the path.
 *
 * The path alone cannot produce "Directory › People": it only knows
 * /directory/people, and turning segments into labels means a second table of
 * names that has to be kept level with the sidebar's. It was not level — the
 * sidebar said Directory and the breadcrumb said Admin, for the same page.
 * Both now come from lib/nav, so a section renamed there is renamed in both
 * places or in neither.
 *
 * Anything below the matched entry is shown verbatim, which is exactly right
 * for `alonfils` in Directory › People › alonfils.
 */
function Crumbs() {
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const here = locate(pathname)

  let crumbs: { key: string; label: string; to?: string }[]
  if (here !== null) {
    crumbs = [
      // The section is a heading, not a page — it has no route of its own, so
      // it is deliberately not a link to one.
      { key: here.section.label, label: here.section.label },
      { key: here.item.to, label: here.item.label, to: here.item.to },
      ...here.rest.map((segment) => ({ key: segment, label: segment })),
    ]
  } else if (pathname === ACCOUNT.to) {
    crumbs = [{ key: 'account', label: ACCOUNT.label }]
  } else {
    // Somewhere the navigation does not describe — a dead link, or a route
    // added without one. Shown as it is rather than folded into the account
    // page, because a breadcrumb naming a page you are not on is worse than
    // one that admits it does not know.
    crumbs = pathname
      .split('/')
      .filter(Boolean)
      .map((segment) => ({ key: segment, label: segment }))
  }

  return (
    <Breadcrumb>
      <BreadcrumbList>
        {crumbs.map((crumb, index) => {
          const last = index === crumbs.length - 1
          return (
            <BreadcrumbItem key={crumb.key}>
              {last || crumb.to === undefined ? (
                last ? (
                  <BreadcrumbPage>{crumb.label}</BreadcrumbPage>
                ) : (
                  <span className="text-muted-foreground">{crumb.label}</span>
                )
              ) : (
                <BreadcrumbLink href={crumb.to}>{crumb.label}</BreadcrumbLink>
              )}
              {!last && <BreadcrumbSeparator />}
            </BreadcrumbItem>
          )
        })}
      </BreadcrumbList>
    </Breadcrumb>
  )
}

function Centered({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid min-h-dvh place-items-center bg-background p-6">
      <div className="w-full max-w-sm">{children}</div>
    </div>
  )
}
