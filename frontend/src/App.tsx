/**
 * App shell: React Router with an auth-gated sidebar layout.
 *
 * Route map:
 * /login, /dashboard, /devices, /devices/:id,
 * /devices/:deviceId/interfaces/:ifaceId, /rules, /templates, /mitigations,
 * /mitigations/manual, /flows, /alerts, /audit, /settings, /users.
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
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
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

  return <AuthenticatedLayout />;
}

export default function App() {
  return (
    <AuthProvider>
      <Toaster />
      <BrowserRouter>
        <Suspense fallback={PageFallback}>
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route element={<RequireAuth />}>
              <Route path="/dashboard" element={<Dashboard />} />
              <Route path="/devices" element={<Devices />} />
              <Route path="/devices/:id" element={<DeviceDetail />} />
              <Route
                path="/devices/:deviceId/interfaces/:ifaceId"
                element={<InterfaceDetail />}
              />
              <Route path="/rules" element={<Rules />} />
              <Route path="/templates" element={<Templates />} />
              <Route path="/mitigations" element={<Mitigations />} />
              <Route path="/mitigations/manual" element={<ManualReroute />} />
              <Route path="/flows" element={<Flows />} />
              {/* /alerts redirects to the Mitigations page Alerts tab */}
              <Route path="/alerts" element={<Navigate to="/mitigations?tab=alerts" replace />} />
              <Route path="/audit" element={<Audit />} />
              <Route path="/settings" element={<Settings />} />
              <Route element={<RequirePermission permission="manage_users" />}>
                <Route path="/users" element={<Users />} />
              </Route>
            </Route>
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Routes>
        </Suspense>
      </BrowserRouter>
    </AuthProvider>
  );
}
