/**
 * /devices/:id — device detail, organised as an NMS-style tabbed view.
 *
 * Header: back arrow, device name, a reachability badge, a "Read-only · SNMP"
 * badge, and (gated by manage_devices, except Refresh) Refresh / Test SNMP /
 * Discover / Edit / Delete actions.
 *
 * Tabs:
 *  - Overview: a responsive grid of info cards (Device Information, Connectivity,
 *    Status) using uppercase muted labels + bold values and green pills.
 *  - Interfaces: the polished interface table; each row links to the interface
 *    detail page (`/devices/:id/interfaces/:ifaceId`). Per-interface charts live
 *    on the interface page.
 *
 * The device + interface list auto-refresh every 30 s.
 */
import {
  useEffect,
  useState,
  useCallback,
  useRef,
  type FormEvent,
} from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import {
  ArrowLeft,
  Pencil,
  Trash2,
  RefreshCw,
  Activity,
  Compass,
} from "lucide-react";
import { api, type Device, type Interface, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  classifyInterface,
  statusVariant,
  TYPE_VARIANT,
  fmtBps,
  fmtPps,
} from "@/lib/telemetry";

// ---------------------------------------------------------------------------
// Shared input class (matches the rest of the app)
// ---------------------------------------------------------------------------

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

// ---------------------------------------------------------------------------
// Info-card label/value primitive
// ---------------------------------------------------------------------------

function Fact({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-0.5">
      <dt className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        {label}
      </dt>
      <dd className="text-sm font-semibold break-words">{children}</dd>
    </div>
  );
}

function GreenPill({ children }: { children: React.ReactNode }) {
  return (
    <Badge className="border-transparent bg-green-500/15 text-green-700 dark:text-green-400">
      {children}
    </Badge>
  );
}

// ---------------------------------------------------------------------------
// Edit device form (inside a Dialog) — preserved from the previous page
// ---------------------------------------------------------------------------

interface EditDeviceForm {
  name: string;
  hostname: string;
  snmp_port: string;
  poll_interval_seconds: string;
  enabled: boolean;
  community: string;
  ssh_auth_method: string; // "none" | "password" | "key" (display-only)
  ssh_username: string;
  ssh_port: string;
  ssh_password: string;
  ssh_private_key: string;
  ssh_key_passphrase: string;
}

function buildEditForm(device: Device): EditDeviceForm {
  return {
    name: device.name,
    hostname: device.hostname,
    snmp_port: String(device.snmp_port),
    poll_interval_seconds: String(device.poll_interval_seconds),
    enabled: device.enabled,
    community: "",
    ssh_auth_method: device.ssh_auth_method ?? "none",
    ssh_username: device.ssh_username ?? "",
    ssh_port: String(device.ssh_port ?? 22),
    ssh_password: "",
    ssh_private_key: "",
    ssh_key_passphrase: "",
  };
}

interface EditDialogProps {
  device: Device;
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}

function EditDialog({ device, open, onClose, onSaved }: EditDialogProps) {
  const [form, setForm] = useState<EditDeviceForm>(() => buildEditForm(device));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setForm(buildEditForm(device));
      setError(null);
    }
  }, [open, device]);

  function setField<K extends keyof EditDeviceForm>(
    field: K,
    value: EditDeviceForm[K],
  ) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      const payload: Parameters<typeof api.devices.update>[1] = {
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        snmp_port: parseInt(form.snmp_port, 10),
        poll_interval_seconds: parseInt(form.poll_interval_seconds, 10),
        enabled: form.enabled,
      };

      if (form.community.trim()) {
        (payload as Record<string, unknown>).community = form.community.trim();
      }

      if (form.ssh_auth_method !== "none") {
        if (form.ssh_username.trim())
          (payload as Record<string, unknown>).ssh_username = form.ssh_username.trim();
        if (form.ssh_port)
          (payload as Record<string, unknown>).ssh_port = parseInt(form.ssh_port, 10);
        if (form.ssh_auth_method === "password" && form.ssh_password)
          (payload as Record<string, unknown>).ssh_password = form.ssh_password;
        if (form.ssh_auth_method === "key" && form.ssh_private_key)
          (payload as Record<string, unknown>).ssh_private_key = form.ssh_private_key;
        if (form.ssh_key_passphrase)
          (payload as Record<string, unknown>).ssh_key_passphrase = form.ssh_key_passphrase;
      }

      await api.devices.update(device.id, payload);
      onSaved();
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update device");
    } finally {
      setBusy(false);
    }
  }

  const sshConfigured = form.ssh_auth_method !== "none";

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit device — {device.name}</DialogTitle>
        </DialogHeader>
        <form id="edit-device-form" onSubmit={handleSubmit} className="space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Name
              <input
                required
                className={inputClass}
                value={form.name}
                onChange={(e) => setField("name", e.target.value)}
              />
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Hostname / IP
              <input
                required
                className={inputClass}
                value={form.hostname}
                onChange={(e) => setField("hostname", e.target.value)}
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
                onChange={(e) => setField("poll_interval_seconds", e.target.value)}
              />
            </label>
          </div>

          <label className="flex items-center gap-2 text-sm font-medium">
            <input
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setField("enabled", e.target.checked)}
              className="h-4 w-4 rounded border border-input"
            />
            Enabled (polling active)
          </label>

          <label className="block space-y-1 text-sm font-medium">
            SNMP community string
            <input
              className={inputClass}
              value={form.community}
              onChange={(e) => setField("community", e.target.value)}
              placeholder="leave blank to keep stored value"
              autoComplete="off"
            />
          </label>

          {sshConfigured && (
            <div className="space-y-4 rounded-md border border-border p-4">
              <div className="flex items-center justify-between">
                <p className="text-sm font-medium">
                  SSH access ({form.ssh_auth_method})
                </p>
                <span className="text-xs text-muted-foreground">
                  stored encrypted · leave blank to keep
                </span>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1 text-sm font-medium">
                  SSH username
                  <input
                    className={inputClass}
                    value={form.ssh_username}
                    onChange={(e) => setField("ssh_username", e.target.value)}
                    placeholder="leave blank to keep"
                    autoComplete="off"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  SSH port
                  <input
                    type="number"
                    min={1}
                    max={65535}
                    className={inputClass}
                    value={form.ssh_port}
                    onChange={(e) => setField("ssh_port", e.target.value)}
                  />
                </label>
              </div>
              {form.ssh_auth_method === "password" && (
                <label className="block space-y-1 text-sm font-medium">
                  SSH password
                  <input
                    type="password"
                    className={inputClass}
                    value={form.ssh_password}
                    onChange={(e) => setField("ssh_password", e.target.value)}
                    placeholder="leave blank to keep stored password"
                    autoComplete="new-password"
                  />
                </label>
              )}
              {form.ssh_auth_method === "key" && (
                <div className="space-y-4">
                  <label className="block space-y-1 text-sm font-medium">
                    SSH private key
                    <textarea
                      rows={5}
                      className={`${inputClass} font-mono text-xs`}
                      value={form.ssh_private_key}
                      onChange={(e) => setField("ssh_private_key", e.target.value)}
                      placeholder="leave blank to keep stored key"
                    />
                  </label>
                  <label className="block space-y-1 text-sm font-medium">
                    Key passphrase
                    <input
                      type="password"
                      className={inputClass}
                      value={form.ssh_key_passphrase}
                      onChange={(e) => setField("ssh_key_passphrase", e.target.value)}
                      placeholder="leave blank to keep"
                      autoComplete="new-password"
                    />
                  </label>
                </div>
              )}
            </div>
          )}

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button form="edit-device-form" type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Overview tab — info cards
// ---------------------------------------------------------------------------

function OverviewTab({ device }: { device: Device }) {
  const sshMethodLabel =
    device.ssh_auth_method === "password"
      ? "password"
      : device.ssh_auth_method === "key"
        ? "SSH key"
        : "none";

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
      {/* Device Information */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Device Information</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Name">{device.name}</Fact>
            <Fact label="Vendor">{device.vendor ?? "—"}</Fact>
            <Fact label="Model">{device.model ?? "—"}</Fact>
            <Fact label="OS Version">{device.os_version ?? "—"}</Fact>
            <Fact label="Sys Name">{device.sys_name ?? "—"}</Fact>
            <Fact label="Sys Uptime">{device.sys_uptime ?? "—"}</Fact>
          </dl>
        </CardContent>
      </Card>

      {/* Connectivity */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Connectivity</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Hostname / IP">
              <code className="text-xs">{device.hostname}</code>
            </Fact>
            <Fact label="SNMP">
              {device.snmp_version} · port {device.snmp_port}
            </Fact>
            <Fact label="SSH">
              <span className="flex flex-wrap items-center gap-1.5">
                {device.ssh_configured ? (
                  <>
                    <span>
                      {device.ssh_username ?? "—"} · {sshMethodLabel}
                    </span>
                    <GreenPill>configured</GreenPill>
                  </>
                ) : (
                  <Badge variant="secondary">none</Badge>
                )}
              </span>
            </Fact>
            <Fact label="Poll Interval">{device.poll_interval_seconds} s</Fact>
          </dl>
        </CardContent>
      </Card>

      {/* Status */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-2 gap-4">
            <Fact label="Reachable">
              {device.reachable ? (
                <GreenPill>reachable</GreenPill>
              ) : (
                <Badge variant="destructive">unreachable</Badge>
              )}
            </Fact>
            <Fact label="Interfaces">{device.interface_count}</Fact>
            <Fact label="Last Poll">
              {device.last_poll_at
                ? new Date(device.last_poll_at).toLocaleString()
                : "—"}
            </Fact>
            <Fact label="Last Error">
              {device.last_error ? (
                <span className="text-destructive">{device.last_error}</span>
              ) : (
                "—"
              )}
            </Fact>
          </dl>
        </CardContent>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Interfaces tab — table (rows link to the interface detail page)
// ---------------------------------------------------------------------------

interface InterfacesTabProps {
  deviceId: number;
  interfaces: Interface[];
  loading: boolean;
}

function InterfacesTab({
  deviceId,
  interfaces,
  loading,
}: InterfacesTabProps) {
  const navigate = useNavigate();

  if (loading) {
    return <p className="px-6 pb-6 text-sm text-muted-foreground">Loading…</p>;
  }
  if (interfaces.length === 0) {
    return (
      <p className="px-6 pb-6 text-sm text-muted-foreground">
        No interfaces discovered yet. Use "Discover" above.
      </p>
    );
  }

  return (
    <Table>
      <TableHeader>
        <TableRow className="hover:bg-transparent">
          <TableHead className="pl-6">Name</TableHead>
          <TableHead>Type</TableHead>
          <TableHead>Descr / Alias</TableHead>
          <TableHead>Speed</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Rx bps / pps</TableHead>
          <TableHead>Tx bps / pps</TableHead>
          <TableHead className="pr-6">Util %</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {interfaces.map((iface) => {
          const ifType = classifyInterface(iface.if_name, iface.if_descr);
          const valid = iface.metrics && iface.metrics.valid_sample;
          return (
            <TableRow
              key={iface.id}
              className="cursor-pointer hover:bg-muted/50"
              onClick={() =>
                navigate(`/devices/${deviceId}/interfaces/${iface.id}`)
              }
            >
              <TableCell className="pl-6 font-medium">{iface.if_name}</TableCell>
              <TableCell>
                <Badge variant={TYPE_VARIANT[ifType]}>{ifType}</Badge>
              </TableCell>
              <TableCell className="text-xs text-muted-foreground">
                {iface.if_alias ?? iface.if_descr ?? "—"}
              </TableCell>
              <TableCell className="text-xs">
                {iface.if_speed_bps !== null ? fmtBps(iface.if_speed_bps) : "—"}
              </TableCell>
              <TableCell>
                <div className="flex items-center gap-1">
                  <Badge variant={statusVariant(iface.oper_status)}>
                    {iface.oper_status}
                  </Badge>
                  {iface.admin_status !== iface.oper_status && (
                    <Badge variant="outline">adm:{iface.admin_status}</Badge>
                  )}
                </div>
              </TableCell>
              <TableCell className="text-xs">
                {valid ? (
                  <>
                    {fmtBps(iface.metrics!.rx_bps)}
                    <br />
                    {fmtPps(iface.metrics!.rx_pps)}
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="text-xs">
                {valid ? (
                  <>
                    {fmtBps(iface.metrics!.tx_bps)}
                    <br />
                    {fmtPps(iface.metrics!.tx_pps)}
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
              <TableCell className="pr-6 text-xs">
                {valid ? (
                  <>
                    Rx {iface.metrics!.rx_util_percent.toFixed(1)}%
                    <br />
                    Tx {iface.metrics!.tx_util_percent.toFixed(1)}%
                  </>
                ) : (
                  "—"
                )}
              </TableCell>
            </TableRow>
          );
        })}
      </TableBody>
    </Table>
  );
}

// ---------------------------------------------------------------------------
// Main page component
// ---------------------------------------------------------------------------

export default function DeviceDetail() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("manage_devices");
  const { id } = useParams<{ id: string }>();
  const deviceId = Number(id);
  const navigate = useNavigate();

  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(true);
  const [ifLoading, setIfLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);

  const ifaceTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadDevice = useCallback(() => {
    if (!Number.isFinite(deviceId)) return;
    api.devices
      .get(deviceId)
      .then(setDevice)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Failed to load device"),
      )
      .finally(() => setLoading(false));
  }, [deviceId]);

  const loadInterfaces = useCallback(() => {
    if (!Number.isFinite(deviceId)) return;
    api.devices
      .interfaces(deviceId)
      .then((ifaces) => setInterfaces(ifaces))
      .catch(() => setInterfaces([]))
      .finally(() => setIfLoading(false));
  }, [deviceId]);

  useEffect(() => {
    loadDevice();
    loadInterfaces();
    ifaceTimerRef.current = setInterval(() => {
      loadDevice();
      loadInterfaces();
    }, 30_000);
    return () => {
      if (ifaceTimerRef.current !== null) clearInterval(ifaceTimerRef.current);
    };
  }, [loadDevice, loadInterfaces]);

  async function handleDelete() {
    if (!device) return;
    if (
      !confirm(
        `Delete device "${device.name}"? All interfaces and telemetry data will be removed. This cannot be undone.`,
      )
    )
      return;
    try {
      await api.devices.remove(device.id);
      navigate("/devices");
    } catch (err) {
      alert(err instanceof ApiError ? err.message : "Delete failed");
    }
  }

  if (loading) {
    return <div className="text-sm text-muted-foreground">Loading device…</div>;
  }

  if (error || !device) {
    return (
      <div className="space-y-4">
        <Link
          to="/devices"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="size-4" /> Back to devices
        </Link>
        <p className="text-sm text-destructive">{error ?? "Device not found."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* ---- Header ---- */}
      <div className="space-y-2">
        <Link
          to="/devices"
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="size-4" /> Devices
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight">{device.name}</h1>
          {device.reachable ? (
            <GreenPill>Active · reachable</GreenPill>
          ) : (
            <Badge variant="destructive">Unreachable</Badge>
          )}
          <Badge
            variant="secondary"
            title="SNMP is read-only telemetry; Rerouter only polls this device."
          >
            Read-only · SNMP
          </Badge>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => {
                loadDevice();
                loadInterfaces();
              }}
            >
              <RefreshCw className="size-4" />
              Refresh
            </Button>
            {canManage && (
              <>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    api.devices.test(device.id).then((r) => {
                      const msg = r.ok
                        ? `OK: ${[r.vendor, r.model].filter(Boolean).join(" / ") || "reachable"}`
                        : `Failed: ${r.error ?? "unknown"}`;
                      alert(msg);
                    })
                  }
                >
                  <Activity className="size-4" />
                  Test SNMP
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    api.devices.discover(device.id).then((r) => {
                      alert(`Discovered ${r.discovered} interfaces`);
                      loadInterfaces();
                    })
                  }
                >
                  <Compass className="size-4" />
                  Discover
                </Button>
                <Button size="sm" variant="outline" onClick={() => setEditOpen(true)}>
                  <Pencil className="size-4" />
                  Edit
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="text-destructive hover:text-destructive"
                  onClick={() => void handleDelete()}
                >
                  <Trash2 className="size-4" />
                  Delete
                </Button>
              </>
            )}
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          <code>{device.hostname}</code>
          {(device.vendor || device.model) &&
            ` · ${[device.vendor, device.model].filter(Boolean).join(" ")}`}
          {device.os_version && ` · ${device.os_version}`}
        </p>
      </div>

      {/* Edit dialog */}
      {canManage && (
        <EditDialog
          device={device}
          open={editOpen}
          onClose={() => setEditOpen(false)}
          onSaved={() => loadDevice()}
        />
      )}

      {/* ---- Tabs ---- */}
      <Tabs defaultValue="overview">
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="interfaces">
            Interfaces ({device.interface_count})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="mt-4">
          <OverviewTab device={device} />
        </TabsContent>

        <TabsContent value="interfaces" className="mt-4">
          <Card>
            <CardContent className="px-0 py-2">
              <InterfacesTab
                deviceId={deviceId}
                interfaces={interfaces}
                loading={ifLoading}
              />
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
