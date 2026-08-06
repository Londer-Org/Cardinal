import { Link } from '@tanstack/react-router'
import {
  CheckCircle2Icon,
  ChevronRightIcon,
  KeyRoundIcon,
  LifeBuoyIcon,
  ShieldAlertIcon,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { useSession } from '@/features/auth/useAuth'
import { useConsents } from '@/features/consent/useConsents'
import { useCredentials } from '@/features/credentials/useCredentials'
import { useDecisions } from '@/features/decisions/useDecisions'
import { useGroups, useUsers } from '@/features/directory/useDirectory'
import { useRecoveries } from '@/features/recovery/useRecovery'
import type { Me } from '@/lib/api/schemas'
import { ViewHeader } from '@/views/ViewHeader'

/**
 * Where you land.
 *
 * Two questions, in that order: what needs doing, and where is everything. The
 * counts are second because a number nobody has to act on is decoration — the
 * page earns its place by the first card, not the rest.
 *
 * Everything here comes from endpoints the other views already use, so nothing
 * on this page can show a figure the page it links to would disagree with.
 */
export function HomeView() {
  const { session } = useSession()
  if (session === null) return <Skeleton className="h-64 w-full" />

  const name = session.displayName || session.login

  return (
    <div className="space-y-4">
      <ViewHeader
        title={`Welcome back, ${name.split(' ')[0] ?? name}`}
        description="What needs your attention, and where everything is."
      />

      <NeedsAttention session={session} />

      <div className="grid gap-4 lg:grid-cols-2">
        <YourAccess session={session} />
        <RecentDecisions />
      </div>

      {/* Entitled *and* currently fresh, which is not what canManageUsers alone
          says — it reports entitlement as if a key had just been touched, so
          that a section does not vanish when authentication goes stale.

          Firing an administrative query on a stale session returns the
          freshness refusal, and that refusal opens the step-up dialog. Gated on
          entitlement alone, an admin who had been reading for a while would be
          met by a security-key prompt for the crime of loading the home page.
          The sidebar still offers the section; asking there is a response to
          something they did. */}
      {session.canManageUsers && !session.adminNeedsReauth && (
        <DirectorySummary session={session} />
      )}
    </div>
  )
}

interface Guidance {
  key: string
  title: string
  detail: string
  to: string
  action: string
  icon: LucideIcon
  urgent: boolean
}

/**
 * The part of the page with a job.
 *
 * Each item is something the reader can go and fix, with the link that fixes
 * it. Nothing appears here that is merely true — "you have 2 passkeys" belongs
 * in the summary below, because there is nothing to do about it.
 */
function NeedsAttention({ session }: { session: Me }) {
  const items: Guidance[] = []

  if (!session.fullyEnrolled) {
    items.push({
      key: 'second-passkey',
      title: 'Register a second passkey',
      detail:
        'With only one, losing that device means losing the account. A hardware key kept somewhere else is the usual second.',
      to: '/access/passkeys',
      action: 'Add a passkey',
      icon: KeyRoundIcon,
      urgent: true,
    })
  }

  if (session.recoveryCodesRemaining === 0) {
    items.push({
      key: 'no-recovery-codes',
      title: 'Generate recovery codes',
      detail:
        'You have none. They are what gets you back in when every registered device is gone, and they can only be created while you are already signed in.',
      to: '/account',
      action: 'Generate codes',
      icon: LifeBuoyIcon,
      urgent: true,
    })
  } else if (session.recoveryCodesRemaining <= 2) {
    items.push({
      key: 'low-recovery-codes',
      title: `Only ${session.recoveryCodesRemaining} recovery ${
        session.recoveryCodesRemaining === 1 ? 'code' : 'codes'
      } left`,
      detail:
        'Generating a new set replaces the old one, so do it before the last is spent rather than after.',
      to: '/account',
      action: 'Generate a new set',
      icon: LifeBuoyIcon,
      urgent: false,
    })
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Needs your attention</CardTitle>
        <CardDescription>
          {items.length === 0
            ? 'Nothing right now.'
            : 'Each of these is something you can fix from here.'}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {items.length === 0 ? (
          <p className="flex items-center gap-2 text-sm text-muted-foreground">
            <CheckCircle2Icon className="size-4 shrink-0" />
            Your account is set up and nothing is waiting on you.
          </p>
        ) : (
          items.map((item) => (
            <Link
              key={item.key}
              to={item.to}
              className="flex items-start gap-3 rounded-md border p-3 transition-colors hover:bg-accent"
            >
              <item.icon
                className={`mt-0.5 size-4 shrink-0 ${
                  item.urgent ? 'text-warning' : 'text-muted-foreground'
                }`}
              />
              <span className="min-w-0 flex-1">
                <span className="block text-sm font-medium">{item.title}</span>
                <span className="mt-0.5 block text-sm text-muted-foreground">
                  {item.detail}
                </span>
                <span className="mt-1 block text-sm font-medium text-primary">
                  {item.action}
                </span>
              </span>
              <ChevronRightIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            </Link>
          ))
        )}
      </CardContent>
    </Card>
  )
}

/** One number and what it is, linking to the page that owns it. */
function Stat({
  label,
  value,
  to,
}: {
  label: string
  value: number | undefined
  to: string
}) {
  return (
    <Link
      to={to}
      className="rounded-md border p-3 transition-colors hover:bg-accent"
    >
      <span className="block text-2xl font-semibold tabular-nums">
        {value === undefined ? '—' : value}
      </span>
      <span className="mt-0.5 block text-sm text-muted-foreground">{label}</span>
    </Link>
  )
}

function YourAccess({ session }: { session: Me }) {
  const credentials = useCredentials()
  const consents = useConsents()

  return (
    <Card>
      <CardHeader>
        <CardTitle>Your access</CardTitle>
        <CardDescription>How you sign in, and what you let in.</CardDescription>
      </CardHeader>
      <CardContent className="grid grid-cols-3 gap-3">
        <Stat
          label={credentials.data?.length === 1 ? 'passkey' : 'passkeys'}
          value={credentials.data?.length}
          to="/access/passkeys"
        />
        <Stat
          label="recovery codes"
          value={session.recoveryCodesRemaining}
          to="/account"
        />
        <Stat
          label={consents.data?.length === 1 ? 'connected app' : 'connected apps'}
          value={consents.data?.length}
          to="/access/connected"
        />
      </CardContent>
    </Card>
  )
}

/**
 * The last few decisions about you.
 *
 * Scoped to the caller by the server, so this is your own history rather than
 * the directory's.
 *
 * Console reads are filtered out, and that is not cosmetic. Every list this
 * admin UI draws is itself an authorized action, so opening two pages buries
 * anything meaningful under a dozen `ManageUsers on GET /api/directory/users` —
 * the product describing its own plumbing back to you.
 *
 * Their denials are filtered too, which took a second look to get right. They
 * seem worth keeping until you notice where they come from: a session going
 * stale means every background refetch is refused, so the page would fill with
 * five refusals the reader never asked for. Those already announce themselves
 * at the moment they happen, by asking for a key — which is better feedback
 * than a list item afterwards.
 *
 * What is left is what this reader actually did: reach an application, or fail
 * to. The Decisions view still shows everything — an explorer that hides
 * records is worse than a noisy one.
 *
 * The filtering happens after the server's window of the last hundred, so a
 * busy console session can push every application decision out of view. Hence
 * "nothing recent" rather than "nothing yet", and hence the link to the full
 * record being there whether or not this card found anything: the one thing it
 * must not do is let a bounded window read as an empty history.
 */
function RecentDecisions() {
  const { data, isPending } = useDecisions(false)
  const recent = (data ?? [])
    .filter((d) => d.decisionPoint !== 'adminAPI')
    .slice(0, 5)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent decisions</CardTitle>
        <CardDescription>
          Applications you reached, and anything you were refused.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        {isPending ? (
          <Skeleton className="h-16 w-full" />
        ) : (
          <>
            {recent.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                Nothing recent. Decisions appear here as you reach applications.
              </p>
            ) : (
              recent.map((decision, index) => (
                <div
                  key={`${decision.action}-${decision.resource}-${String(index)}`}
                  className="flex items-center gap-2 text-sm"
                >
                  <Badge variant={decision.allowed ? 'secondary' : 'destructive'}>
                    {decision.allowed ? 'allowed' : 'denied'}
                  </Badge>
                  <span className="min-w-0 flex-1 truncate">
                    {decision.action}
                    <span className="text-muted-foreground">
                      {' on '}
                      {decision.resource}
                    </span>
                  </span>
                </div>
              ))
            )}
            <Link
              to="/access/decisions"
              className="block pt-1 text-sm font-medium text-primary"
            >
              All decisions
            </Link>
          </>
        )}
      </CardContent>
    </Card>
  )
}

/**
 * The directory at a glance, for sessions that administer it.
 *
 * Totals rather than pages: one row is fetched from each list purely for the
 * count the server reports alongside it, which is what these endpoints already
 * return for the tables.
 */
function DirectorySummary({ session }: { session: Me }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Directory</CardTitle>
        <CardDescription>What you administer.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <DirectoryCounts />
        {/* Recovery is the broad tier, which managing users does not grant. A
            user-admin asking for this list is refused, and the refusal would be
            written to the decision log as if they had tried to reach it. */}
        {session.canAdministerDirectory && <RecoveryWaiting />}
      </CardContent>
    </Card>
  )
}

function DirectoryCounts() {
  // One row from each list, for the total the server reports beside it — the
  // same figure the tables paginate against.
  const users = useUsers({ q: '', limit: 1, offset: 0 })
  const groups = useGroups({ q: '', limit: 1, offset: 0 })

  return (
    <div className="grid grid-cols-2 gap-3">
      <Stat label="people" value={users.data?.total} to="/directory/people" />
      <Stat label="groups" value={groups.data?.total} to="/directory/groups" />
    </div>
  )
}

function RecoveryWaiting() {
  const recoveries = useRecoveries()

  // Requests that cannot proceed without another administrator. Someone has to
  // notice them, and nothing else in the product says so.
  const waiting = (recoveries.data ?? []).filter((r) => !r.satisfied).length

  // Nothing waiting is not worth a row of its own. The count belongs with the
  // others; the notice only exists when there is something to notice.
  if (waiting === 0) return null

  return (
    <Link
      to="/directory/recovery"
      className="flex items-start gap-3 rounded-md border p-3 transition-colors hover:bg-accent"
    >
      <ShieldAlertIcon className="mt-0.5 size-4 shrink-0 text-warning" />
      <span className="min-w-0 flex-1 text-sm">
        <span className="block font-medium">
          {waiting === 1
            ? 'A recovery request needs a second approver'
            : `${String(waiting)} recovery requests need a second approver`}
        </span>
        <span className="mt-0.5 block text-muted-foreground">
          Restoring an account takes two administrators, and it cannot proceed
          until another one agrees.
        </span>
      </span>
      <ChevronRightIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
    </Link>
  )
}
