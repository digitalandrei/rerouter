import { Outlet } from 'react-router-dom'
import { SidebarProvider, SidebarInset } from '@/components/ui/sidebar'
import { AppSidebar } from '@/components/layout/app-sidebar'
import { Header } from '@/components/layout/header'
import { ObserveBanner } from '@/components/layout/observe-banner'

// The authenticated application shell: a collapsible inset sidebar plus the
// content column (header + observe banner + routed page). Session gating is
// handled upstream by <RequireAuth> in App.tsx — this component is only ever
// mounted once the auth context reports an authenticated session, so it does
// not re-probe the session itself.
export function AuthenticatedLayout() {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset className="flex flex-col">
        <Header />
        <ObserveBanner />
        <main className="flex-1 overflow-auto p-4 md:p-6">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
