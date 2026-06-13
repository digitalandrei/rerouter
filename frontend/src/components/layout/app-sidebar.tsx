import { Link, NavLink, useLocation } from 'react-router-dom'
import { Shield } from 'lucide-react'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  SidebarSeparator,
} from '@/components/ui/sidebar'
import { sidebarData } from './data/sidebar-data'
import { NavUser } from './nav-user'
import { useAuth } from '@/lib/auth'
import type { NavItem } from '@/components/layout/types'

export function AppSidebar() {
  const location = useLocation()
  const { hasPermission } = useAuth()

  // Hide permission-gated items the session can't access (e.g. Users).
  const visible = (item: NavItem) =>
    !item.permission || hasPermission(item.permission)

  const allNavUrls = [
    ...(sidebarData.topItems ?? []).map((i) => i.url),
    ...sidebarData.navGroups.flatMap((g) => g.items.map((i) => i.url)),
  ]

  function isActive(url: string) {
    if (location.pathname === url) return true
    if (!location.pathname.startsWith(url + '/')) return false
    // A longer, more specific sibling owns the deeper path.
    return !allNavUrls.some(
      (u) =>
        u !== url &&
        u.startsWith(url + '/') &&
        (location.pathname === u || location.pathname.startsWith(u + '/')),
    )
  }

  return (
    <Sidebar collapsible="icon" variant="inset">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild>
              <Link to="/dashboard">
                <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-primary text-primary-foreground">
                  <Shield className="h-4 w-4" />
                </div>
                <div className="grid flex-1 text-left text-sm leading-tight">
                  <span className="truncate font-semibold">Rerouter</span>
                  <span className="truncate text-xs text-muted-foreground">
                    DDoS mitigation
                  </span>
                </div>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        {sidebarData.topItems && sidebarData.topItems.length > 0 && (
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {sidebarData.topItems.filter(visible).map((item) => (
                  <SidebarMenuItem key={item.url}>
                    <SidebarMenuButton
                      asChild
                      isActive={isActive(item.url)}
                      tooltip={item.title}
                    >
                      <NavLink to={item.url}>
                        {item.icon && <item.icon className="h-4 w-4" />}
                        <span>{item.title}</span>
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        )}
        {sidebarData.navGroups.map((group) => (
          <div key={group.title}>
            <SidebarSeparator className="mx-2" />
            <SidebarGroup>
              <SidebarGroupLabel>{group.title}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.filter(visible).map((item) => (
                    <SidebarMenuItem key={item.url}>
                      <SidebarMenuButton
                        asChild
                        isActive={isActive(item.url)}
                        tooltip={item.title}
                      >
                        <NavLink to={item.url}>
                          {item.icon && <item.icon className="h-4 w-4" />}
                          <span>{item.title}</span>
                        </NavLink>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </div>
        ))}
      </SidebarContent>

      <SidebarFooter>
        <NavUser />
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  )
}
