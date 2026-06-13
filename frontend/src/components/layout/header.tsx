import { cn } from '@/lib/utils'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { Separator } from '@/components/ui/separator'
import { ThemeToggle } from '@/components/theme-toggle'
import { UserMenu } from '@/components/layout/user-menu'

interface HeaderProps extends React.ComponentProps<'header'> {
  children?: React.ReactNode
}

// Top bar for the authenticated shell: the sidebar toggle plus a slot for
// page-specific content (title / breadcrumbs). The page heading itself is
// rendered by each page, so the slot is usually empty.
export function Header({ className, children, ...props }: HeaderProps) {
  return (
    <header
      className={cn(
        'flex h-14 shrink-0 items-center gap-2 border-b bg-background px-4',
        className,
      )}
      {...props}
    >
      <SidebarTrigger className="-ml-1" />
      <Separator
        orientation="vertical"
        className="mr-2 data-[orientation=vertical]:h-4"
      />
      <div className="flex items-center gap-2">{children}</div>
      <div className="ml-auto flex items-center gap-1">
        <ThemeToggle />
        <UserMenu />
      </div>
    </header>
  )
}
