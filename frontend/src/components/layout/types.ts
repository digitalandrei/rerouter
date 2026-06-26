import type { LucideIcon } from 'lucide-react'

export interface NavItem {
  title: string
  url: string
  icon?: LucideIcon
  /**
   * When set, the item is only rendered if the current session holds this
   * permission (checked via auth context `hasPermission`). Used to gate the
   * Users entry behind `manage_users`.
   */
  permission?: string
  /**
   * When set, a numeric badge is rendered on this nav item when the value > 0.
   * The value is supplied at runtime by the sidebar via a badge provider.
   * The string is a key into the badge context (e.g. "active_rule_matches").
   */
  badgeKey?: string
}

export interface NavGroup {
  title: string
  items: NavItem[]
}

export interface SidebarData {
  topItems?: NavItem[]
  navGroups: NavGroup[]
}
