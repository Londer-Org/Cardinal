import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import {
  AppWindowIcon,
  ChevronsUpDownIcon,
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
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
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

// "Your account" is not here — it lives in the account menu at the bottom,
// beside the identity it belongs to.
const ACCOUNT_NAV: NavItem[] = [
  { label: 'Passkeys', to: '/passkeys', icon: KeyRoundIcon },
  // "Connected" rather than "Applications": the Integrations section below has
  // an entry by that name, and two identical labels in one sidebar is a menu
  // you have to click to understand.
  { label: 'Connected apps', to: '/connected', icon: AppWindowIcon },
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
  const pathname = useRouterState({ select: (state) => state.location.pathname })

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton
              size="lg"
              asChild
              tooltip="Cardinal"
              // Collapsed, the mark is the only thing left, so it gets the whole
              // rail rather than the 32px box a menu icon would take.
              className="group-data-[collapsible=icon]:size-10! group-data-[collapsible=icon]:justify-center"
            >
              <Link to="/">
                {/* Wrapped in a span deliberately. SidebarMenuButton styles its
                    direct svg children at size-4, and that selector is more
                    specific than a class on the svg itself — so the mark was
                    being silently held at 16px whatever it asked for. */}
                <span className="flex shrink-0 items-center justify-center">
                  <CardinalMark className="size-7 text-foreground transition-[width,height] group-data-[collapsible=icon]:size-9" />
                </span>
                <span className="text-base font-semibold group-data-[collapsible=icon]:hidden">
                  Cardinal
                </span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <NavGroup label="Account" items={ACCOUNT_NAV} pathname={pathname} />

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
            <NavUser />
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}

/**
 * The account menu.
 *
 * Signing out used to be a bare button in the footer, sitting among the links
 * and looking like one — the same shape and the same colour as Passkeys, next
 * to it. Ending a session is the one irreversible thing the chrome can do, so
 * it belongs behind a deliberate open and is the only control here coloured as
 * destructive.
 *
 * Putting "Your account" in the same menu is the other half of that: both are
 * about who you are signed in as, and this is where the sidebar says so.
 */
function NavUser() {
  const { session } = useSession()
  const logout = useLogout()
  const navigate = useNavigate()
  const { setOpenMobile, isMobile } = useSidebar()

  if (!session) return null

  const name = session.displayName || session.login
  // The login, not the email. It is what the person is called everywhere else
  // in the directory, and an account may not have an address at all.
  const secondary = session.login

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <SidebarMenuButton
          size="lg"
          tooltip={name}
          className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
        >
          {/* Brand blue rather than the hover grey: collapsed to the rail this
              square is the only thing left of the footer, and it has to look
              like a deliberate avatar rather than two stray letters. */}
          <span className="grid size-8 shrink-0 place-items-center rounded-md bg-sidebar-primary text-xs font-medium text-sidebar-primary-foreground">
            {initials(name)}
          </span>
          <span className="grid flex-1 text-left text-sm leading-tight">
            <span className="truncate font-medium">{name}</span>
            <span className="truncate text-xs text-sidebar-foreground/70">
              {secondary}
            </span>
          </span>
          <ChevronsUpDownIcon className="ml-auto size-4" />
        </SidebarMenuButton>
      </DropdownMenuTrigger>

      {/* Opens to the side rather than upward: collapsed to the icon rail there
          is no room above it, and a menu that changes direction with the
          sidebar state is one you have to look for. */}
      <DropdownMenuContent
        side={isMobile ? 'top' : 'right'}
        align="end"
        sideOffset={4}
        className="min-w-56"
      >
        <DropdownMenuLabel className="grid gap-0.5">
          <span className="truncate text-sm font-medium">{name}</span>
          <span className="truncate text-xs font-normal text-muted-foreground">
            {session.email || secondary}
          </span>
        </DropdownMenuLabel>

        <DropdownMenuSeparator />

        <DropdownMenuItem
          onSelect={() => {
            setOpenMobile(false)
            void navigate({ to: '/' })
          }}
        >
          <UserIcon />
          Your account
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <DropdownMenuItem
          variant="destructive"
          disabled={logout.isPending}
          onSelect={(event) => {
            // Hold the menu open while the request is in flight. It goes with
            // the page when the redirect lands, and closing it first would
            // leave the sidebar looking untouched mid-sign-out.
            event.preventDefault()
            logout.mutate()
          }}
        >
          <LogOutIcon />
          {logout.isPending ? 'Signing out…' : 'Sign out'}
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

/**
 * Initials for the avatar square.
 *
 * No image: Cardinal has nowhere to upload one, and a stock silhouette says
 * less than two letters do.
 */
function initials(name: string): string {
  const parts = name.split(/\s+/).filter(Boolean)
  const first = parts.at(0)
  const last = parts.at(-1)
  if (first === undefined || last === undefined) return '?'
  if (parts.length === 1) return first.slice(0, 2).toUpperCase()
  return `${first.charAt(0)}${last.charAt(0)}`.toUpperCase()
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
