/**
 * App shell: React Router with an auth-gated layout.
 *
 * Route map mirrors the canonical page list (docs/doctrine.md §5.3):
 * /login, /dashboard, /assets, /assets/:id, /providers, /rules, /reroutes,
 * /reroutes/manual, /alerts, /audit, /settings.
 *
 * Everything except /login sits behind <RequireAuth>; the session itself is
 * an HttpOnly cookie validated server-side on every request, so this gate is
 * UX only — authorization is enforced by the controller (RBAC middleware).
 */
import {
  BrowserRouter,
  Link,
  Navigate,
  NavLink,
  Outlet,
  Route,
  Routes,
} from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Assets from "@/pages/Assets";
import AssetDetail from "@/pages/AssetDetail";
import Providers from "@/pages/Providers";
import Rules from "@/pages/Rules";
import Reroutes from "@/pages/Reroutes";
import ManualReroute from "@/pages/ManualReroute";
import Alerts from "@/pages/Alerts";
import Audit from "@/pages/Audit";
import Settings from "@/pages/Settings";

const NAV_ITEMS: Array<{ to: string; label: string }> = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/assets", label: "Assets" },
  { to: "/providers", label: "Providers" },
  { to: "/rules", label: "Rules" },
  { to: "/reroutes", label: "Reroutes" },
  { to: "/alerts", label: "Alerts" },
  { to: "/audit", label: "Audit" },
  { to: "/settings", label: "Settings" },
];

function RequireAuth() {
  const { stage } = useAuth();

  if (stage === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted-foreground">
        Checking session…
      </div>
    );
  }

  if (stage !== "authenticated") {
    return <Navigate to="/login" replace />;
  }

  return <AppLayout />;
}

function AppLayout() {
  const { user, logout } = useAuth();

  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b">
        <div className="mx-auto flex w-full max-w-6xl items-center gap-6 px-4 py-3">
          <Link to="/dashboard" className="text-lg font-bold tracking-tight">
            Rerouter
          </Link>
          <nav className="flex flex-1 items-center gap-1 overflow-x-auto">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 text-sm font-medium",
                    isActive
                      ? "bg-secondary text-secondary-foreground"
                      : "text-muted-foreground hover:bg-accent hover:text-accent-foreground",
                  )
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>
          <span className="text-sm text-muted-foreground">{user?.email}</span>
          <Button variant="outline" size="sm" onClick={() => void logout()}>
            Log out
          </Button>
        </div>
      </header>
      <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6">
        <Outlet />
      </main>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<RequireAuth />}>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/assets" element={<Assets />} />
            <Route path="/assets/:id" element={<AssetDetail />} />
            <Route path="/providers" element={<Providers />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/reroutes" element={<Reroutes />} />
            <Route path="/reroutes/manual" element={<ManualReroute />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
