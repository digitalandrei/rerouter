import { useEffect, useState } from 'react'
import { Link, NavLink, useLocation } from 'react-router-dom'
import { Shield } from 'lucide-react'
import {
  Sidebar,
  SidebarContent,
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
import { useAuth } from '@/lib/auth'
import { api } from '@/lib/api'
import type { NavItem } from '@/components/layout/types'

// Poll interval for api.status() badge counts (30 s — same cadence as other
// background refreshes in the app; avoids hammering the controller).
const STATUS_POLL_MS = 30_000

export function AppSidebar() {
  const location = useLocation()
  const { hasPermission } = useAuth()

  // Badge counts keyed by badgeKey string (currently only active_rule_matches).
  const [badgeCounts, setBadgeCounts] = useState<Record<string, number>>({})

  useEffect(() => {
    function fetchStatus() {
      api
        .status()
        .then((s) => {
          setBadgeCounts({ active_rule_matches: s.active_rule_matches })
        })
        .catch(() => {})
    }
    fetchStatus()
    const t = setInterval(fetchStatus, STATUS_POLL_MS)
    return () => clearInterval(t)
  }, [])

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

  function renderItem(item: NavItem) {
    const badge =
      item.badgeKey && badgeCounts[item.badgeKey]
        ? badgeCounts[item.badgeKey]
        : 0

    return (
      <SidebarMenuItem key={item.url}>
        <SidebarMenuButton
          asChild
          isActive={isActive(item.url)}
          tooltip={item.title}
        >
          <NavLink to={item.url} className="flex items-center gap-2">
            {item.icon && <item.icon className="h-4 w-4 shrink-0" />}
            <span className="flex-1">{item.title}</span>
            {badge > 0 && (
              <span className="inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1.5 text-[11px] font-semibold text-white">
                {badge}
              </span>
            )}
          </NavLink>
        </SidebarMenuButton>
      </SidebarMenuItem>
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
                {sidebarData.topItems.filter(visible).map(renderItem)}
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
                  {group.items.filter(visible).map(renderItem)}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          </div>
        ))}
      </SidebarContent>

      <SidebarRail />
    </Sidebar>
  )
}
