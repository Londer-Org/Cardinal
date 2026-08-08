import {
  AppWindowIcon,
  BadgeCheckIcon,
  HouseIcon,
  KeyRoundIcon,
  LayersIcon,
  LifeBuoyIcon,
  MailIcon,
  ScaleIcon,
  SlidersHorizontalIcon,
  ScrollTextIcon,
  ShieldCheckIcon,
  ServerIcon,
  TerminalIcon,
  UsersIcon,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import type { Me } from '@/lib/api/schemas'

/**
 * The navigation, described once.
 *
 * The sidebar renders this and the breadcrumbs read it, so "where am I" has a
 * single answer rather than two that agree until someone adds a route. They
 * did not agree before: the sidebar filed People under Directory while the
 * breadcrumb said Admin › People, and the personal pages had no section at all.
 *
 * The paths follow the same shape, so the URL is the third view of it. Nothing
 * enforces that beyond this file — but a path that cannot be found here shows
 * up immediately as a breadcrumb with no section in front of it.
 */

export interface NavItem {
  label: string
  /** Matched as a prefix, so /directory/people/alonfils still finds People. */
  to: string
  icon: LucideIcon
}

export interface NavSection {
  label: string
  items: NavItem[]
  /**
   * Sections a session cannot use are not rendered. Presentation only — every
   * endpoint behind them evaluates the policy itself. Hiding a section beats
   * letting someone find out by being refused, and showing a user-admin an
   * Applications link they will be told no about reads as a broken system
   * rather than as a permission they lack.
   */
  visible?: (session: Me) => boolean
}

export const NAV: NavSection[] = [
  {
    // Not "Account": the account itself is the profile page, which lives in the
    // menu at the foot of the sidebar. What is left is the three questions you
    // ask about your own access — how you sign in, what you have let in, and
    // what you were allowed to do.
    label: 'Your access',
    items: [
      { label: 'Passkeys', to: '/access/passkeys', icon: KeyRoundIcon },
      { label: 'Access tokens', to: '/access/tokens', icon: TerminalIcon },
      { label: 'Connected apps', to: '/access/connected', icon: AppWindowIcon },
      { label: 'Decisions', to: '/access/decisions', icon: ScrollTextIcon },
    ],
  },
  {
    label: 'Directory',
    visible: (session) => session.canManageUsers,
    items: [
      { label: 'People', to: '/directory/people', icon: UsersIcon },
      { label: 'Groups', to: '/directory/groups', icon: LayersIcon },
      { label: 'Hosts', to: '/directory/hosts', icon: ServerIcon },
      { label: 'Recovery', to: '/directory/recovery', icon: LifeBuoyIcon },
    ],
  },
  {
    // Its own section, and gated on the broad tier rather than the directory
    // one. Activating a policy set decides every question Cardinal answers,
    // including who may activate the next one, so it does not belong beside
    // the pages somebody gets for managing accounts.
    label: 'Authorization',
    visible: (session) => session.canAdministerDirectory,
    items: [
      { label: 'Policy', to: '/policy', icon: ScaleIcon },
      // Beside policy rather than under Directory: this is the record of what
      // happened, which is the other half of the same question as what is
      // allowed to happen.
      { label: 'Audit journal', to: '/audit', icon: ShieldCheckIcon },
      // Here rather than under Directory: what machines trust is a property of
      // the deployment, not of any entity in it.
      { label: 'Authorities', to: '/authorities', icon: BadgeCheckIcon },
      // Alongside them for the same reason: what this server is configured to
      // do is a property of the deployment. Read-only, and its most useful
      // column is the one saying which settings nothing reads.
      { label: 'Configuration', to: '/admin/configuration', icon: SlidersHorizontalIcon },
      // Beside it because it is the other half of the same question: what this
      // deployment is set up to do. Editable, unlike configuration, because
      // none of it is a trust root.
      { label: 'Notifications', to: '/admin/notifications', icon: MailIcon },
    ],
  },
  {
    label: 'Integrations',
    visible: (session) => session.canManageApplications,
    items: [
      {
        label: 'Applications',
        to: '/integrations/applications',
        icon: AppWindowIcon,
      },
    ],
  },
]

/**
 * The two pages that belong to no section.
 *
 * Home is where you land; the account page is reached from the menu at the
 * foot of the sidebar, beside the identity it describes, rather than from a
 * section of its own.
 */
export const HOME = { label: 'Home', to: '/', icon: HouseIcon } as const
export const ACCOUNT = { label: 'Your account', to: '/account' } as const

export interface Location {
  section: NavSection
  item: NavItem
  /** Path segments below the item, such as the login in People › alonfils. */
  rest: string[]
}

/**
 * Which navigation entry a path belongs to.
 *
 * Longest match wins, so a future /directory/groups/new cannot be claimed by a
 * shorter sibling that happens to share a prefix.
 */
export function locate(pathname: string): Location | null {
  let best: Location | null = null

  for (const section of NAV) {
    for (const item of section.items) {
      if (pathname !== item.to && !pathname.startsWith(`${item.to}/`)) continue
      if (best !== null && item.to.length <= best.item.to.length) continue
      best = {
        section,
        item,
        rest: pathname.slice(item.to.length).split('/').filter(Boolean),
      }
    }
  }

  return best
}

export interface Crumb {
  key: string
  label: string
  /** Absent for headings and for the page you are on. */
  to?: string
}

/**
 * The trail for a path.
 *
 * Lives here rather than in the header that draws it, so the breadcrumbs and
 * the sidebar cannot describe the same page differently — which is exactly
 * what they used to do.
 */
export function crumbsFor(pathname: string): Crumb[] {
  if (pathname === HOME.to) return [{ key: 'home', label: HOME.label }]
  if (pathname === ACCOUNT.to) {
    return [{ key: 'account', label: ACCOUNT.label }]
  }

  const here = locate(pathname)
  if (here !== null) {
    return [
      // A section is a heading, not a page — it has no route of its own, so it
      // is deliberately not a link to one.
      { key: here.section.label, label: here.section.label },
      { key: here.item.to, label: here.item.label, to: here.item.to },
      ...here.rest.map((segment) => ({ key: segment, label: segment })),
    ]
  }

  // Somewhere the navigation does not describe — a dead link, or a route added
  // without one. Shown as it is rather than folded into a real page, because a
  // breadcrumb naming a page you are not on is worse than one admitting it
  // does not know.
  return pathname
    .split('/')
    .filter(Boolean)
    .map((segment) => ({ key: segment, label: segment }))
}
