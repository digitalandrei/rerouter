/**
 * App shell: React Router with an auth-gated sidebar layout.
 *
 * Route map:
 * /login, /dashboard, /devices, /devices/:id,
 * /devices/:deviceId/interfaces/:ifaceId, /rules, /templates, /mitigations,
 * /manual-mitigations, /flows, /alerts, /audit, /settings, /documentation,
 * /users.
 *
 * Everything except /login sits behind <RequireAuth>; the session itself is
 * an HttpOnly cookie validated server-side on every request, so this gate is
 * UX only — authorization is enforced by the controller (RBAC middleware).
 * /users is additionally gated by the `manage_users` permission, mirroring the
 * server guard and the gated nav entry in the sidebar.
 *
 * Page components are code-split with React.lazy so the initial bundle stays
 * small; each page's chunk loads on navigation behind the <Suspense> fallback.
 */
import { lazy, Suspense } from "react";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { Toaster } from "@/components/ui/toaster";
import { AuthenticatedLayout } from "@/components/layout/authenticated-layout";

const Login = lazy(() => import("@/pages/Login"));
const Dashboard = lazy(() => import("@/pages/Dashboard"));
const Devices = lazy(() => import("@/pages/Devices"));
const DeviceDetail = lazy(() => import("@/pages/DeviceDetail"));
const InterfaceDetail = lazy(() => import("@/pages/InterfaceDetail"));
const Rules = lazy(() => import("@/pages/Rules"));
const Templates = lazy(() => import("@/pages/Templates"));
const Mitigations = lazy(() => import("@/pages/Mitigations"));
const ManualReroute = lazy(() => import("@/pages/ManualReroute"));
const Flows = lazy(() => import("@/pages/Flows"));
const Audit = lazy(() => import("@/pages/Audit"));
const Settings = lazy(() => import("@/pages/Settings"));
const Documentation = lazy(() => import("@/pages/Documentation"));
const Users = lazy(() => import("@/pages/Users"));

const PageFallback = (
  <div className="flex min-h-screen items-center justify-center text-muted-foreground">
    Loading…
  </div>
);

function RequirePermission({ permission }: { permission: string }) {
  const { hasPermission } = useAuth();
  if (!hasPermission(permission)) {
    return <Navigate to="/dashboard" replace />;
  }
  return <Outlet />;
}

function RequireAuth() {
  const { stage, user, authError, retrySession } = useAuth();
  const location = useLocation();

  if (stage === "loading" || (stage === "reconnecting" && !user)) {
    return (
      <div className="flex min-h-screen items-center justify-center text-muted-foreground">
        Checking session…
      </div>
    );
  }

  if (stage === "unavailable") {
    return <Navigate to="/login" replace state={{ returnTo: location.pathname + location.search }} />;
  }

  if (stage !== "authenticated" && stage !== "reconnecting") {
    return <Navigate to="/login" replace state={{ returnTo: location.pathname + location.search }} />;
  }

  return <AuthenticatedLayout connectionIssue={stage === "reconnecting" ? authError : null} onRetryConnection={retrySession} />;
}

const router = createBrowserRouter([
  { path: "/login", element: <Login /> },
  { element: <RequireAuth />, children: [
    { path: "/dashboard", element: <Dashboard /> }, { path: "/devices", element: <Devices /> },
    { path: "/devices/:id", element: <DeviceDetail /> }, { path: "/devices/:deviceId/interfaces/:ifaceId", element: <InterfaceDetail /> },
    { path: "/rules", element: <Rules /> }, { path: "/rules/:id", element: <Rules /> }, { path: "/rules/:id/edit", element: <Rules /> }, { path: "/templates", element: <Templates /> }, { path: "/mitigations", element: <Mitigations /> },
    { path: "/manual-mitigations", element: <ManualReroute /> }, { path: "/manual-mitigations/new", element: <ManualReroute /> },
    { path: "/manual-mitigations/:id", element: <ManualReroute /> }, { path: "/manual-mitigations/:id/edit", element: <ManualReroute /> },
    { path: "/manual-mitigations/:id/run", element: <ManualReroute /> }, { path: "/mitigations/manual", element: <Navigate to="/manual-mitigations" replace /> },
    { path: "/flows", element: <Flows /> }, { path: "/alerts", element: <Navigate to="/mitigations?tab=alerts" replace /> },
    { path: "/audit", element: <Audit /> }, { path: "/settings", element: <Settings /> }, { path: "/documentation", element: <Documentation /> },
    { element: <RequirePermission permission="manage_users" />, children: [{ path: "/users", element: <Users /> }] },
  ]},
  { path: "*", element: <Navigate to="/dashboard" replace /> },
]);

export default function App() { return <AuthProvider><Toaster /><Suspense fallback={PageFallback}><RouterProvider router={router} /></Suspense></AuthProvider>; }
