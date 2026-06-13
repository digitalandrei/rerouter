/**
 * /users — user management for superadmins only (manage_users permission).
 *
 * Governed by docs/doctrine.md §9 and docs/authentication.md.
 * Lists all users; allows creating, editing roles, resetting 2FA, and
 * deleting users. Server-side guards against last-superadmin demotion/deletion
 * and self-deletion; error messages from the API are surfaced inline.
 */
import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { api, type User, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

interface AddUserForm {
  email: string;
  name: string;
  role: string;
  password: string;
}

const DEFAULT_FORM: AddUserForm = {
  email: "",
  name: "",
  role: "admin",
  password: "",
};

function roleBadgeVariant(
  role: string,
): "default" | "secondary" | "destructive" | "outline" {
  return role === "superadmin" ? "destructive" : "secondary";
}

export default function Users() {
  const { hasPermission } = useAuth();
  const navigate = useNavigate();

  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<AddUserForm>(DEFAULT_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);
  // Per-row inline error messages: userId -> message
  const [rowError, setRowError] = useState<Record<number, string>>({});
  const [rowBusy, setRowBusy] = useState<Record<number, boolean>>({});

  // Defensive gate: redirect away if permission is missing.
  useEffect(() => {
    if (!hasPermission("manage_users")) {
      navigate("/dashboard", { replace: true });
    }
  }, [hasPermission, navigate]);

  function loadUsers() {
    setLoading(true);
    api.users
      .list()
      .then(setUsers)
      .catch(() => setUsers([]))
      .finally(() => setLoading(false));
  }

  useEffect(loadUsers, []);

  function setField(field: keyof AddUserForm, value: string) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    setAddBusy(true);
    try {
      await api.users.create({
        email: form.email.trim(),
        name: form.name.trim(),
        role: form.role,
        password: form.password,
      });
      setForm(DEFAULT_FORM);
      setShowAdd(false);
      loadUsers();
    } catch (err) {
      setAddError(
        err instanceof ApiError ? err.message : "Failed to create user",
      );
    } finally {
      setAddBusy(false);
    }
  }

  function setRowErr(id: number, msg: string) {
    setRowError((e) => ({ ...e, [id]: msg }));
  }
  function clearRowErr(id: number) {
    setRowError((e) => {
      const next = { ...e };
      delete next[id];
      return next;
    });
  }
  function setRowBusyState(id: number, busy: boolean) {
    setRowBusy((b) => ({ ...b, [id]: busy }));
  }

  async function handleRoleChange(user: User, newRole: string) {
    clearRowErr(user.id);
    setRowBusyState(user.id, true);
    try {
      const updated = await api.users.update(user.id, { role: newRole });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setRowErr(
        user.id,
        err instanceof ApiError ? err.message : "Failed to update role",
      );
    } finally {
      setRowBusyState(user.id, false);
    }
  }

  async function handleReset2fa(user: User) {
    if (
      !confirm(
        `Reset 2FA for ${user.email}? They will need to re-enroll at next login.`,
      )
    )
      return;
    clearRowErr(user.id);
    setRowBusyState(user.id, true);
    try {
      await api.users.reset2fa(user.id);
    } catch (err) {
      setRowErr(
        user.id,
        err instanceof ApiError ? err.message : "Failed to reset 2FA",
      );
    } finally {
      setRowBusyState(user.id, false);
    }
  }

  async function handleDelete(user: User) {
    if (!confirm(`Delete user ${user.email}? This cannot be undone.`)) return;
    clearRowErr(user.id);
    setRowBusyState(user.id, true);
    try {
      await api.users.remove(user.id);
      setUsers((prev) => prev.filter((u) => u.id !== user.id));
    } catch (err) {
      setRowErr(
        user.id,
        err instanceof ApiError ? err.message : "Failed to delete user",
      );
      setRowBusyState(user.id, false);
    }
  }

  // Render nothing while the permission redirect is in flight
  if (!hasPermission("manage_users")) return null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Users</h1>
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowAdd((v) => !v)}
        >
          {showAdd ? "Cancel" : "Add user"}
        </Button>
      </div>

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Add user</CardTitle>
            <CardDescription>
              Create a new user account. A temporary password is set; they must
              enroll TOTP on first login.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1 text-sm font-medium">
                  Email
                  <input
                    type="email"
                    required
                    className={inputClass}
                    value={form.email}
                    onChange={(e) => setField("email", e.target.value)}
                    placeholder="user@example.com"
                    autoComplete="off"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Name
                  <input
                    required
                    className={inputClass}
                    value={form.name}
                    onChange={(e) => setField("name", e.target.value)}
                    placeholder="Full name"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Role
                  <select
                    className={inputClass}
                    value={form.role}
                    onChange={(e) => setField("role", e.target.value)}
                  >
                    <option value="admin">Admin</option>
                    <option value="superadmin">Super admin</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Temporary password
                  <input
                    type="password"
                    required
                    className={inputClass}
                    value={form.password}
                    onChange={(e) => setField("password", e.target.value)}
                    autoComplete="new-password"
                  />
                </label>
              </div>
              {addError && (
                <p className="text-sm text-destructive" role="alert">
                  {addError}
                </p>
              )}
              <Button type="submit" disabled={addBusy}>
                {addBusy ? "Creating…" : "Create user"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">All users</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : users.length === 0 ? (
            <p className="text-sm text-muted-foreground">No users found.</p>
          ) : (
            <div className="divide-y">
              {users.map((user) => (
                <div key={user.id} className="py-4 space-y-1">
                  <div className="flex flex-wrap items-center gap-3">
                    {/* Identity */}
                    <span className="font-medium">{user.email}</span>
                    <span className="text-xs text-muted-foreground">
                      {user.name}
                    </span>
                    <Badge variant={roleBadgeVariant(user.role)}>
                      {user.role === "superadmin" ? "Super admin" : "Admin"}
                    </Badge>
                    <Badge
                      variant={user.twofa_enrolled ? "default" : "outline"}
                    >
                      {user.twofa_enrolled ? "2FA enrolled" : "not enrolled"}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(user.created_at).toLocaleDateString()}
                    </span>

                    <span className="flex-1" />

                    {/* Role selector */}
                    <select
                      className="rounded-md border border-input bg-background px-2 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                      value={user.role}
                      disabled={rowBusy[user.id]}
                      onChange={(e) => void handleRoleChange(user, e.target.value)}
                      aria-label={`Role for ${user.email}`}
                    >
                      <option value="admin">Admin</option>
                      <option value="superadmin">Super admin</option>
                    </select>

                    <Button
                      size="sm"
                      variant="outline"
                      disabled={rowBusy[user.id]}
                      onClick={() => void handleReset2fa(user)}
                    >
                      Reset 2FA
                    </Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={rowBusy[user.id]}
                      onClick={() => void handleDelete(user)}
                    >
                      Delete
                    </Button>
                  </div>
                  {rowError[user.id] && (
                    <p className="text-xs text-destructive" role="alert">
                      {rowError[user.id]}
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
