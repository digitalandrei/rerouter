/**
 * App shell: React Router with an auth-gated sidebar layout.
 *
 * Route map:
 * /login, /dashboard, /devices, /devices/:id, /rules, /reroutes,
 * /reroutes/manual, /alerts, /audit, /settings, /users.
 *
 * Everything except /login sits behind <RequireAuth>; the session itself is
 * an HttpOnly cookie validated server-side on every request, so this gate is
 * UX only — authorization is enforced by the controller (RBAC middleware).
 * /users is additionally gated by the `manage_users` permission, mirroring the
 * server guard and the gated nav entry in the sidebar.
 */
import { BrowserRouter, Navigate, Outlet, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { AuthenticatedLayout } from "@/components/layout/authenticated-layout";
import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Devices from "@/pages/Devices";
import DeviceDetail from "@/pages/DeviceDetail";
import InterfaceDetail from "@/pages/InterfaceDetail";
import Rules from "@/pages/Rules";
import Reroutes from "@/pages/Reroutes";
import ManualReroute from "@/pages/ManualReroute";
import Alerts from "@/pages/Alerts";
import Audit from "@/pages/Audit";
import Settings from "@/pages/Settings";
import Users from "@/pages/Users";

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
      <BrowserRouter>
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
            <Route path="/reroutes" element={<Reroutes />} />
            <Route path="/reroutes/manual" element={<ManualReroute />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/settings" element={<Settings />} />
            <Route element={<RequirePermission permission="manage_users" />}>
              <Route path="/users" element={<Users />} />
            </Route>
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
