/**
 * /devices — SNMP device management.
 *
 * Lists enrolled devices with a polished shadcn Table (sortable headers,
 * icon+badge columns, ghost action buttons). Add-device form is preserved
 * and gated by manage_devices. Test/Discover actions moved to DeviceDetail.
 */
import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import {
  Router,
  Eye,
  ArrowUp,
  ArrowDown,
  ChevronsUpDown,
} from "lucide-react";
import { api, type Device, ApiError } from "@/lib/api";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

interface AddDeviceForm {
  name: string;
  hostname: string;
  snmp_version: string;
  community: string;
  snmp_port: string;
  poll_interval_seconds: string;
  ssh_auth_method: string;
  ssh_username: string;
  ssh_port: string;
  ssh_password: string;
  ssh_private_key: string;
  ssh_key_passphrase: string;
}

const DEFAULT_FORM: AddDeviceForm = {
  name: "",
  hostname: "",
  snmp_version: "v2c",
  community: "public",
  snmp_port: "161",
  poll_interval_seconds: "60",
  ssh_auth_method: "none",
  ssh_username: "",
  ssh_port: "22",
  ssh_password: "",
  ssh_private_key: "",
  ssh_key_passphrase: "",
};

type SortField = "name" | "status";
type SortDir = "asc" | "desc";

function SortIcon({
  field,
  active,
  dir,
}: {
  field: SortField;
  active: SortField;
  dir: SortDir;
}) {
  if (field !== active)
    return <ChevronsUpDown className="ml-1 inline-block size-3.5 text-muted-foreground" />;
  return dir === "asc" ? (
    <ArrowUp className="ml-1 inline-block size-3.5" />
  ) : (
    <ArrowDown className="ml-1 inline-block size-3.5" />
  );
}

export default function Devices() {
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canEnroll = hasPermission("manage_devices");

  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<AddDeviceForm>(DEFAULT_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);

  const [sortField, setSortField] = useState<SortField>("name");
  const [sortDir, setSortDir] = useState<SortDir>("asc");

  function loadDevices() {
    setLoading(true);
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]))
      .finally(() => setLoading(false));
  }

  useEffect(loadDevices, []);

  function setField(field: keyof AddDeviceForm, value: string) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    setAddBusy(true);
    try {
      const payload: Parameters<typeof api.devices.create>[0] = {
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        snmp_version: form.snmp_version,
        snmp_port: parseInt(form.snmp_port, 10),
        community: form.community.trim(),
        poll_interval_seconds: parseInt(form.poll_interval_seconds, 10),
      };
      if (form.ssh_auth_method !== "none") {
        payload.ssh_auth_method = form.ssh_auth_method as "password" | "key";
        payload.ssh_username = form.ssh_username.trim();
        payload.ssh_port = parseInt(form.ssh_port, 10);
        if (form.ssh_auth_method === "password") {
          payload.ssh_password = form.ssh_password;
        } else {
          payload.ssh_private_key = form.ssh_private_key;
          if (form.ssh_key_passphrase) {
            payload.ssh_key_passphrase = form.ssh_key_passphrase;
          }
        }
      }
      await api.devices.create(payload);
      setForm(DEFAULT_FORM);
      setShowAdd(false);
      loadDevices();
    } catch (err) {
      setAddError(err instanceof ApiError ? err.message : "Failed to add device");
    } finally {
      setAddBusy(false);
    }
  }

  function toggleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortField(field);
      setSortDir("asc");
    }
  }

  const sorted = [...devices].sort((a, b) => {
    let cmp = 0;
    if (sortField === "name") {
      cmp = a.name.localeCompare(b.name);
    } else {
      // status: reachable first when asc
      cmp = Number(b.reachable) - Number(a.reachable);
    }
    return sortDir === "asc" ? cmp : -cmp;
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Devices</h1>
        {canEnroll ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => setShowAdd((v) => !v)}
          >
            {showAdd ? "Cancel" : "Add device"}
          </Button>
        ) : (
          <p className="text-sm text-muted-foreground">
            Device enrollment is restricted to super admins.
          </p>
        )}
      </div>

      {showAdd && canEnroll && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">Add SNMP device</CardTitle>
            <CardDescription>
              Enroll a new router or switch for SNMP polling.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="space-y-4">
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1 text-sm font-medium">
                  Name
                  <input
                    required
                    className={inputClass}
                    value={form.name}
                    onChange={(e) => setField("name", e.target.value)}
                    placeholder="core-router-01"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Hostname / IP
                  <input
                    required
                    className={inputClass}
                    value={form.hostname}
                    onChange={(e) => setField("hostname", e.target.value)}
                    placeholder="192.168.1.1"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  SNMP version
                  <select
                    className={inputClass}
                    value={form.snmp_version}
                    onChange={(e) => setField("snmp_version", e.target.value)}
                  >
                    <option value="v2c">v2c</option>
                    <option value="v1">v1</option>
                    <option value="v3">v3</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Community string
                  <input
                    required
                    className={inputClass}
                    value={form.community}
                    onChange={(e) => setField("community", e.target.value)}
                    placeholder="public"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  SNMP port
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    required
                    className={inputClass}
                    value={form.snmp_port}
                    onChange={(e) => setField("snmp_port", e.target.value)}
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Poll interval (seconds)
                  <input
                    type="number"
                    min={10}
                    required
                    className={inputClass}
                    value={form.poll_interval_seconds}
                    onChange={(e) =>
                      setField("poll_interval_seconds", e.target.value)
                    }
                  />
                </label>
              </div>

              {/* SSH access — captured at onboarding for future CLI reroute
                  actions; not used in observe mode. Password XOR key. */}
              <div className="space-y-4 rounded-md border border-border p-4">
                <div className="flex items-center justify-between">
                  <p className="text-sm font-medium">SSH access</p>
                  <span className="text-xs text-muted-foreground">
                    stored encrypted · unused in observe mode
                  </span>
                </div>
                <div className="grid gap-4 sm:grid-cols-2">
                  <label className="block space-y-1 text-sm font-medium">
                    Auth method
                    <select
                      className={inputClass}
                      value={form.ssh_auth_method}
                      onChange={(e) => setField("ssh_auth_method", e.target.value)}
                    >
                      <option value="none">None (SNMP only)</option>
                      <option value="password">Password</option>
                      <option value="key">SSH key</option>
                    </select>
                  </label>
                  {form.ssh_auth_method !== "none" && (
                    <>
                      <label className="block space-y-1 text-sm font-medium">
                        SSH username
                        <input
                          required
                          className={inputClass}
                          value={form.ssh_username}
                          onChange={(e) => setField("ssh_username", e.target.value)}
                          placeholder="admin"
                          autoComplete="off"
                        />
                      </label>
                      <label className="block space-y-1 text-sm font-medium">
                        SSH port
                        <input
                          type="number"
                          min={1}
                          max={65535}
                          required
                          className={inputClass}
                          value={form.ssh_port}
                          onChange={(e) => setField("ssh_port", e.target.value)}
                        />
                      </label>
                    </>
                  )}
                </div>
                {form.ssh_auth_method === "password" && (
                  <label className="block space-y-1 text-sm font-medium">
                    SSH password
                    <input
                      type="password"
                      required
                      className={inputClass}
                      value={form.ssh_password}
                      onChange={(e) => setField("ssh_password", e.target.value)}
                      autoComplete="new-password"
                    />
                  </label>
                )}
                {form.ssh_auth_method === "key" && (
                  <div className="space-y-4">
                    <label className="block space-y-1 text-sm font-medium">
                      SSH private key
                      <textarea
                        required
                        rows={6}
                        className={`${inputClass} font-mono text-xs`}
                        value={form.ssh_private_key}
                        onChange={(e) =>
                          setField("ssh_private_key", e.target.value)
                        }
                        placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                      />
                    </label>
                    <label className="block space-y-1 text-sm font-medium">
                      Key passphrase (optional)
                      <input
                        type="password"
                        className={inputClass}
                        value={form.ssh_key_passphrase}
                        onChange={(e) =>
                          setField("ssh_key_passphrase", e.target.value)
                        }
                        autoComplete="new-password"
                      />
                    </label>
                  </div>
                )}
              </div>

              {addError && (
                <p className="text-sm text-destructive" role="alert">
                  {addError}
                </p>
              )}
              <Button type="submit" disabled={addBusy}>
                {addBusy ? "Adding…" : "Add device"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Enrolled devices</CardTitle>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {loading ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">Loading…</p>
          ) : devices.length === 0 ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">
              No devices enrolled yet. Use "Add device" to enroll your first
              SNMP-polled router.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead
                    className="cursor-pointer select-none pl-6"
                    onClick={() => toggleSort("name")}
                  >
                    Name
                    <SortIcon field="name" active={sortField} dir={sortDir} />
                  </TableHead>
                  <TableHead>Vendor / Model</TableHead>
                  <TableHead>Interfaces</TableHead>
                  <TableHead>SNMP / SSH</TableHead>
                  <TableHead
                    className="cursor-pointer select-none"
                    onClick={() => toggleSort("status")}
                  >
                    Status
                    <SortIcon field="status" active={sortField} dir={sortDir} />
                  </TableHead>
                  <TableHead className="pr-6 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((device) => (
                  <TableRow
                    key={device.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => navigate(`/devices/${device.id}`)}
                  >
                    {/* Name + hostname */}
                    <TableCell className="pl-6">
                      <div className="flex items-start gap-2">
                        <Router className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="font-medium">{device.name}</span>
                            <span
                              className={[
                                "inline-block size-1.5 shrink-0 rounded-full",
                                device.reachable ? "bg-green-500" : "bg-red-500",
                              ].join(" ")}
                              title={device.reachable ? "Reachable" : "Unreachable"}
                            />
                          </div>
                          <code className="block text-xs text-muted-foreground">
                            {device.hostname}
                          </code>
                        </div>
                      </div>
                    </TableCell>

                    {/* Vendor / Model */}
                    <TableCell className="text-sm text-muted-foreground">
                      {device.vendor || device.model
                        ? [device.vendor, device.model].filter(Boolean).join(" ")
                        : "—"}
                    </TableCell>

                    {/* Interface count */}
                    <TableCell>
                      <Badge variant="secondary">{device.interface_count}</Badge>
                    </TableCell>

                    {/* SNMP version + SSH badge */}
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        <Badge variant="secondary">{device.snmp_version}</Badge>
                        {device.ssh_configured && (
                          <Badge variant="outline">SSH</Badge>
                        )}
                      </div>
                    </TableCell>

                    {/* Reachability status */}
                    <TableCell>
                      {device.reachable ? (
                        <Badge className="bg-green-500/15 text-green-700 dark:text-green-400 border-transparent">
                          reachable
                        </Badge>
                      ) : (
                        <Badge variant="destructive">unreachable</Badge>
                      )}
                    </TableCell>

                    {/* Actions */}
                    <TableCell
                      className="pr-6 text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1">
                        <Button
                          size="icon-sm"
                          variant="ghost"
                          title="View device"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/devices/${device.id}`);
                          }}
                        >
                          <Eye className="size-4" />
                          <span className="sr-only">View</span>
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
