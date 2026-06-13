import { ChevronDown, LogOut } from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'

function initialsFrom(label: string) {
  return label
    .split(/[\s@.]+/)
    .filter(Boolean)
    .map((w) => w[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)
}

// Top-bar account menu (moved here from the sidebar footer): avatar + name,
// opening to email/role and a Log out action wired to the auth context.
// Logout clears the session cookie server-side and the route guards redirect
// to /login.
export function UserMenu() {
  const { user, logout } = useAuth()
  const primary = user?.name?.trim() || user?.email || 'Account'
  const role = user?.roles?.[0] ?? 'user'

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-9 gap-2 px-2" aria-label="Account menu">
          <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-medium text-primary-foreground">
            {initialsFrom(primary)}
          </span>
          <span className="hidden max-w-40 truncate text-sm font-medium sm:inline">
            {primary}
          </span>
          <ChevronDown className="size-4 text-muted-foreground" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="min-w-56">
        <DropdownMenuLabel className="font-normal">
          <div className="flex flex-col gap-0.5">
            <span className="truncate text-sm font-semibold">{primary}</span>
            <span className="truncate text-xs text-muted-foreground">
              {user?.email}
            </span>
            <span className="text-xs capitalize text-muted-foreground">{role}</span>
          </div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => void logout()}>
          <LogOut className="mr-2 size-4" />
          Log out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
