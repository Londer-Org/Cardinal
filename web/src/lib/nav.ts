import {
  AppWindowIcon,
  KeyRoundIcon,
  LayersIcon,
  LifeBuoyIcon,
  ScrollTextIcon,
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
      { label: 'Recovery', to: '/directory/recovery', icon: LifeBuoyIcon },
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

/** The profile page, which has no section — it is the whole of one. */
export const ACCOUNT = { label: 'Your account', to: '/' } as const

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
