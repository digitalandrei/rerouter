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
}

export interface NavGroup {
  title: string
  items: NavItem[]
}

export interface SidebarData {
  topItems?: NavItem[]
  navGroups: NavGroup[]
}
