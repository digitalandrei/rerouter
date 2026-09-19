import { Suspense } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { AppSidebar } from '@/components/layout/app-sidebar'
import { Header } from '@/components/layout/header'
import { ObserveBanner } from '@/components/layout/observe-banner'

// The authenticated application shell: a collapsible inset sidebar plus the
// content column (header + observe banner + routed page). Session gating is
// handled upstream by <RequireAuth> in App.tsx — this component is only ever
// mounted once the auth context reports an authenticated session, so it does
// not re-probe the session itself.
export function AuthenticatedLayout({ connectionIssue, onRetryConnection }: { connectionIssue?: string | null; onRetryConnection?: () => void }) {
  const location = useLocation()
  const segments = location.pathname.split('/').filter(Boolean)
  return (
    <SidebarProvider>
      <a href="#main-content" className="sr-only z-50 rounded-md bg-background px-3 py-2 focus:not-sr-only focus:fixed focus:left-3 focus:top-3">Skip to main content</a>
      <AppSidebar />
      <SidebarInset className="flex flex-col">
        {/* Fixed top bar (header + observe banner); content scrolls beneath. */}
        <div className="sticky top-0 z-30">
          <Header>
            <nav aria-label="Breadcrumb" className="hidden min-w-0 items-center gap-2 text-sm text-muted-foreground sm:flex">
              <Link to="/dashboard" className="hover:text-foreground">Rerouter</Link>
              {segments.map((segment, index) => {
                const path = `/${segments.slice(0, index + 1).join('/')}`
                const label = segment.replaceAll('-', ' ')
                const current = index === segments.length - 1
                return <span key={path} className="flex min-w-0 items-center gap-2"><span aria-hidden="true">/</span>{current ? <span aria-current="page" className="truncate capitalize text-foreground">{label}</span> : <Link to={path} className="truncate capitalize hover:text-foreground">{label}</Link>}</span>
              })}
            </nav>
          </Header>
          <ObserveBanner connectionIssue={connectionIssue} onRetryConnection={onRetryConnection} />
        </div>
        <div id="main-content" tabIndex={-1} className="flex-1 p-4 outline-none md:p-6">
          <Suspense fallback={<div role="status" className="py-8 text-sm text-muted-foreground">Loading page…</div>}>
            <Outlet />
          </Suspense>
        </div>
      </SidebarInset>
    </SidebarProvider>
  )
}
