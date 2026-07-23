import {
  LayoutDashboard,
  Router,
  SlidersHorizontal,
  FileCode2,
  Shuffle,
  Waves,
  ScrollText,
  Settings,
  Users,
  BookOpen,
} from 'lucide-react'
import type { SidebarData } from '@/components/layout/types'

// Rerouter navigation. Dashboard is the landing item; the remaining
// operational pages live under one group. The Users entry carries a
// `permission` gate so it only renders for sessions with `manage_users`
// (mirrors the route guard in App.tsx).
//
// Mitigations is the unified Detections + Alerts + History page; it carries a
// badgeKey so the sidebar can display active_rule_matches from api.status().
export const sidebarData: SidebarData = {
  topItems: [{ title: 'Dashboard', url: '/dashboard', icon: LayoutDashboard }],
  navGroups: [
    {
      title: 'Control plane',
      items: [
        { title: 'Devices', url: '/devices', icon: Router },
        { title: 'Rules', url: '/rules', icon: SlidersHorizontal },
        { title: 'Templates', url: '/templates', icon: FileCode2 },
        { title: 'Mitigations', url: '/mitigations', icon: Shuffle, badgeKey: 'active_rule_matches' },
        { title: 'Flows', url: '/flows', icon: Waves },
        { title: 'Audit', url: '/audit', icon: ScrollText },
        { title: 'Settings', url: '/settings', icon: Settings },
        { title: 'Users', url: '/users', icon: Users, permission: 'manage_users' },
      ],
    },
    {
      title: 'Help',
      items: [
        { title: 'Documentation', url: '/documentation', icon: BookOpen },
      ],
    },
  ],
}
