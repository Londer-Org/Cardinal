import { Link, useRouterState } from '@tanstack/react-router'
import {
  AppWindowIcon,
  KeyRoundIcon,
  LayersIcon,
  LifeBuoyIcon,
  LogOutIcon,
  ScrollTextIcon,
  UserIcon,
  UsersIcon,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from '@/components/ui/sidebar'
import { CardinalMark } from '@/components/CardinalMark'
import { useLogout, useSession } from '@/features/auth/useAuth'

interface NavItem {
  label: string
  to: string
  icon: LucideIcon
}

const ACCOUNT_NAV: NavItem[] = [
  { label: 'Your account', to: '/', icon: UserIcon },
  { label: 'Passkeys', to: '/passkeys', icon: KeyRoundIcon },
  { label: 'Applications', to: '/connected', icon: AppWindowIcon },
  { label: 'Decisions', to: '/decisions', icon: ScrollTextIcon },
]

const PEOPLE_NAV: NavItem[] = [
  { label: 'People', to: '/admin/users', icon: UsersIcon },
  { label: 'Groups', to: '/admin/groups', icon: LayersIcon },
  { label: 'Recovery', to: '/admin/recovery', icon: LifeBuoyIcon },
]

const APPS_NAV: NavItem[] = [
  { label: 'Applications', to: '/admin/applications', icon: AppWindowIcon },
]

/**
 * The one place navigation lives.
 *
 * Sections are hidden by tier, which is presentation only — every endpoint
 * behind them evaluates the policy itself. Hiding a section someone cannot use
 * beats letting them find out by being refused, and showing a user-admin an
 * Applications link they will be told no about reads as a broken system rather
 * than as a permission they lack.
 */
export function AppSidebar() {
  const { session } = useSession()
  const logout = useLogout()
  const pathname = useRouterState({ select: (state) => state.location.pathname })

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to="/">
                <CardinalMark className="size-6 shrink-0 text-foreground" />
                <span className="text-base font-semibold">Cardinal</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <NavGroup items={ACCOUNT_NAV} pathname={pathname} />

        {session?.canManageUsers === true && (
          <NavGroup label="Directory" items={PEOPLE_NAV} pathname={pathname} />
        )}
        {session?.canManageApplications === true && (
          <NavGroup label="Integrations" items={APPS_NAV} pathname={pathname} />
        )}
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              onClick={() => { logout.mutate() }}
              disabled={logout.isPending}
              tooltip="Sign out"
            >
              <LogOutIcon />
              <span>{session?.displayName || session?.login || 'Sign out'}</span>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}

/**
 * A group of links.
 *
 * `isActive` is a prefix match so a detail route keeps its section highlighted —
 * /admin/users/alonfils should not make People look unselected, which is the
 * moment a sidebar stops telling you where you are.
 */
function NavGroup({
  label,
  items,
  pathname,
}: {
  label?: string
  items: NavItem[]
  pathname: string
}) {
  const { setOpenMobile } = useSidebar()

  return (
    <SidebarGroup>
      {label !== undefined && <SidebarGroupLabel>{label}</SidebarGroupLabel>}
      <SidebarMenu>
        {items.map((item) => (
          <SidebarMenuItem key={item.to}>
            <SidebarMenuButton
              asChild
              isActive={
                item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)
              }
              tooltip={item.label}
            >
              <Link to={item.to} onClick={() => { setOpenMobile(false) }}>
                <item.icon />
                <span>{item.label}</span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        ))}
      </SidebarMenu>
    </SidebarGroup>
  )
}
