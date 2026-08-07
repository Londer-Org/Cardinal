import { Link, useNavigate, useRouterState } from '@tanstack/react-router'
import {
  CheckIcon,
  ChevronsUpDownIcon,
  LogOutIcon,
  MonitorIcon,
  MoonIcon,
  PaletteIcon,
  SunIcon,
  UserIcon,
} from 'lucide-react'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuSub,
  DropdownMenuSubContent,
  DropdownMenuSubTrigger,
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
import { useTheme } from '@/features/theme/useTheme'
import { ACCOUNT, HOME, NAV } from '@/lib/nav'
import type { NavItem } from '@/lib/nav'

/**
 * The sidebar.
 *
 * The sections come from lib/nav, which the breadcrumbs read too — so the
 * answer to "where am I" is written once rather than twice.
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
        {/* Above the sections and outside them: home is not part of any one of
            them, and giving it a heading of its own would be a label for a
            single link. */}
        <NavGroup items={[HOME]} pathname={pathname} />

        {NAV.filter(
          (section) =>
            section.visible === undefined ||
            (session !== null && section.visible(session)),
        ).map((section) => (
          <NavGroup
            key={section.label}
            label={section.label}
            items={section.items}
            pathname={pathname}
          />
        ))}
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
            void navigate({ to: ACCOUNT.to })
          }}
        >
          <UserIcon />
          {ACCOUNT.label}
        </DropdownMenuItem>

        <DropdownMenuSeparator />

        <ThemeSubmenu />

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
 * Light, dark, or follow the machine.
 *
 * In the account menu rather than as a button in the chrome: it is a preference
 * about this person's view, which is what everything else in this menu is, and
 * a permanently visible sun/moon is a control people press once and never
 * again taking up space forever.
 */
function ThemeSubmenu() {
  const { theme, setTheme } = useTheme()

  const options = [
    { value: 'light' as const, label: 'Light', icon: SunIcon },
    { value: 'dark' as const, label: 'Dark', icon: MoonIcon },
    { value: 'system' as const, label: 'System', icon: MonitorIcon },
  ]

  return (
    <DropdownMenuSub>
      <DropdownMenuSubTrigger>
        <PaletteIcon />
        Theme
      </DropdownMenuSubTrigger>
      <DropdownMenuSubContent>
        {options.map((option) => (
          <DropdownMenuItem
            key={option.value}
            onSelect={() => { setTheme(option.value) }}
          >
            <option.icon />
            {option.label}
            {theme === option.value && <CheckIcon className="ml-auto size-4" />}
          </DropdownMenuItem>
        ))}
      </DropdownMenuSubContent>
    </DropdownMenuSub>
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
 * /directory/people/alonfils should not make People look unselected, which is
 * the moment a sidebar stops telling you where you are.
 */
function NavGroup({
  label,
  items,
  pathname,
}: {
  label?: string
  items: readonly NavItem[]
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
                // Home is every path's prefix, so it alone matches exactly —
                // otherwise it would light up on every page in the product.
                item.to === HOME.to
                  ? pathname === HOME.to
                  : pathname === item.to || pathname.startsWith(`${item.to}/`)
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
