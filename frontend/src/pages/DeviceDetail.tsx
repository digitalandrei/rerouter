/**
 * /devices/:id — device facts, Edit/Delete (manage_devices), interface table
 * (with type badges + row selection), and last-hour SNMP telemetry charts for
 * the selected interface.
 *
 * Charts: recharts ResponsiveContainer + LineChart — three panels:
 *   1. Throughput  (rx_bps / tx_bps)
 *   2. Packet rate (rx_pps / tx_pps)
 *   3. Errors      (in_errors / out_errors — per-interval counts)
 *
 * Auto-refreshes the interface list and the selected interface's metrics
 * every 30 s; clears the timer on unmount or interface change.
 */
import { useEffect, useState, useCallback, useRef, type FormEvent } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { Pencil, Trash2 } from "lucide-react";
import { api, type Device, type Interface, type Sample, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

function fmtBps(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(2)} Kbps`;
  return `${bps} bps`;
}

function fmtPps(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(2)} Kpps`;
  return `${pps} pps`;
}

/** Format a bps value for the Y-axis tick (shorter form). */
function fmtBpsTick(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)}G`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)}M`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)}K`;
  return `${bps}`;
}

/** Format a pps value for the Y-axis tick. */
function fmtPpsTick(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(1)}M`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(0)}K`;
  return `${pps}`;
}

/** Format ISO timestamp -> HH:MM for the X-axis. */
function fmtTime(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

// ---------------------------------------------------------------------------
// Interface type classification
// ---------------------------------------------------------------------------

type IfaceType =
  | "Port-channel"
  | "Tunnel"
  | "Sub-if"
  | "Loopback"
  | "VLAN"
  | "Null"
  | "Physical";

function classifyInterface(ifName: string, ifDescr: string | null): IfaceType {
  const name = ifName ?? "";
  const descr = ifDescr ?? "";

  if (/^Po/i.test(name) || /^Port-channel/i.test(name) || /^Port-channel/i.test(descr))
    return "Port-channel";
  if (/^Tu/i.test(name) || /^Tunnel/i.test(name) || /^Tunnel/i.test(descr))
    return "Tunnel";
  if (name.includes(".")) return "Sub-if";
  if (/^Lo/i.test(name) || /^Loopback/i.test(name) || /^Loopback/i.test(descr))
    return "Loopback";
  if (
    /^Vl/i.test(name) ||
    /^BDI/i.test(name) ||
    /Vlan/i.test(name) ||
    /Vlan/i.test(descr)
  )
    return "VLAN";
  if (/Null/i.test(name) || /Null/i.test(descr)) return "Null";
  return "Physical";
}

const TYPE_VARIANT: Record<
  IfaceType,
  "default" | "secondary" | "destructive" | "outline"
> = {
  Physical: "default",
  "Port-channel": "secondary",
  Tunnel: "outline",
  "Sub-if": "outline",
  Loopback: "outline",
  VLAN: "secondary",
  Null: "outline",
};

// ---------------------------------------------------------------------------
// Status badge helper
// ---------------------------------------------------------------------------

function operStatusVariant(
  status: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (status.toLowerCase()) {
    case "up":
      return "default";
    case "down":
      return "destructive";
    default:
      return "outline";
  }
}

// ---------------------------------------------------------------------------
// Shared input class (matches the rest of the app)
// ---------------------------------------------------------------------------

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

// ---------------------------------------------------------------------------
// Edit device form (inside a Dialog)
// ---------------------------------------------------------------------------

interface EditDeviceForm {
  name: string;
  hostname: string;
  snmp_port: string;
  poll_interval_seconds: string;
  enabled: boolean;
  // Secrets — only sent when non-empty
  community: string;
  ssh_auth_method: string; // "none" | "password" | "key"  (display-only, read from device)
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

  // Re-seed the form whenever the dialog opens (device may have been reloaded)
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
      // Build a partial payload: only include fields that exist / changed.
      // Secrets are omitted when blank.
      const payload: Parameters<typeof api.devices.update>[1] = {
        name: form.name.trim(),
        hostname: form.hostname.trim(),
        snmp_port: parseInt(form.snmp_port, 10),
        poll_interval_seconds: parseInt(form.poll_interval_seconds, 10),
        enabled: form.enabled,
      };

      // community — only send when operator typed something
      if (form.community.trim()) {
        (payload as Record<string, unknown>).community = form.community.trim();
      }

      // SSH secrets — only update when a new value was provided
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

          {/* Community — secret, omit when blank */}
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

          {/* SSH — only shown when a method is already configured */}
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
// Telemetry chart panel
// ---------------------------------------------------------------------------

interface TelemetryPanelProps {
  iface: Interface;
}

function TelemetryPanel({ iface }: TelemetryPanelProps) {
  const [samples, setSamples] = useState<Sample[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(true);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMetrics = useCallback(() => {
    api.interfaces
      .metrics(iface.id, 60)
      .then((data) => setSamples(data))
      .catch(() => setSamples([]))
      .finally(() => setMetricsLoading(false));
  }, [iface.id]);

  useEffect(() => {
    setMetricsLoading(true);
    setSamples([]);
    fetchMetrics();

    timerRef.current = setInterval(fetchMetrics, 30_000);
    return () => {
      if (timerRef.current !== null) clearInterval(timerRef.current);
    };
  }, [fetchMetrics]);

  const chartData = samples.map((s) => ({
    ...s,
    time: fmtTime(s.sampled_at),
  }));

  const emptyState = (
    <p className="py-6 text-center text-sm text-muted-foreground">
      Collecting telemetry — valid rates appear after the second poll…
    </p>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <span className="text-sm font-medium">{iface.if_name}</span>
        {iface.if_alias || iface.if_descr ? (
          <span className="text-xs text-muted-foreground">
            {iface.if_alias ?? iface.if_descr}
          </span>
        ) : null}
        <span className="ml-auto flex items-center gap-1.5 text-xs text-muted-foreground">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-500" />
          live · refreshes every 30 s
        </span>
      </div>

      {metricsLoading ? (
        <p className="text-sm text-muted-foreground">Loading metrics…</p>
      ) : (
        <>
          {/* --- Throughput --- */}
          <div>
            <p className="mb-1 text-sm font-medium">Throughput</p>
            {chartData.length === 0 ? (
              emptyState
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 11 }}
                    minTickGap={30}
                  />
                  <YAxis
                    tick={{ fontSize: 11 }}
                    tickFormatter={fmtBpsTick}
                    width={52}
                  />
                  <Tooltip
                    formatter={(value) =>
                      typeof value === "number" ? fmtBps(value) : String(value ?? "")
                    }
                    labelClassName="font-mono text-xs"
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="rx_bps"
                    name="Rx (in)"
                    stroke="var(--chart-1)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                  <Line
                    type="monotone"
                    dataKey="tx_bps"
                    name="Tx (out)"
                    stroke="var(--chart-2)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* --- Packet rate --- */}
          <div>
            <p className="mb-1 text-sm font-medium">Packet rate</p>
            {chartData.length === 0 ? (
              emptyState
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 11 }}
                    minTickGap={30}
                  />
                  <YAxis
                    tick={{ fontSize: 11 }}
                    tickFormatter={fmtPpsTick}
                    width={52}
                  />
                  <Tooltip
                    formatter={(value) =>
                      typeof value === "number" ? fmtPps(value) : String(value ?? "")
                    }
                    labelClassName="font-mono text-xs"
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="rx_pps"
                    name="Rx (in)"
                    stroke="var(--chart-1)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                  <Line
                    type="monotone"
                    dataKey="tx_pps"
                    name="Tx (out)"
                    stroke="var(--chart-2)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* --- Errors --- */}
          <div>
            <p className="mb-1 text-sm font-medium">Errors (per interval)</p>
            {chartData.length === 0 ? (
              emptyState
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={chartData}>
                  <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
                  <XAxis
                    dataKey="time"
                    tick={{ fontSize: 11 }}
                    minTickGap={30}
                  />
                  <YAxis
                    tick={{ fontSize: 11 }}
                    allowDecimals={false}
                    width={52}
                  />
                  <Tooltip
                    formatter={(value) =>
                      typeof value === "number" ? value.toString() : String(value ?? "")
                    }
                    labelClassName="font-mono text-xs"
                  />
                  <Legend />
                  <Line
                    type="monotone"
                    dataKey="in_errors"
                    name="In errors"
                    stroke="var(--chart-5)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                  <Line
                    type="monotone"
                    dataKey="out_errors"
                    name="Out errors"
                    stroke="var(--destructive)"
                    dot={false}
                    strokeWidth={1.5}
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </div>
        </>
      )}
    </div>
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
  const [toggleBusy, setToggleBusy] = useState<Record<number, boolean>>({});
  const [error, setError] = useState<string | null>(null);
  const [selectedIfaceId, setSelectedIfaceId] = useState<number | null>(null);

  const [editOpen, setEditOpen] = useState(false);

  // Auto-refresh timer for the interface list (30 s)
  const ifaceTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadDevice = useCallback(() => {
    if (!Number.isFinite(deviceId)) return;
    setLoading(true);
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
    setIfLoading(true);
    api.devices
      .interfaces(deviceId)
      .then((ifaces) => {
        setInterfaces(ifaces);
        // Default-select the first "up" interface (or the very first one).
        setSelectedIfaceId((prev) => {
          if (prev !== null) return prev; // keep existing selection
          const firstUp = ifaces.find(
            (i) => i.oper_status.toLowerCase() === "up",
          );
          return firstUp?.id ?? ifaces[0]?.id ?? null;
        });
      })
      .catch(() => setInterfaces([]))
      .finally(() => setIfLoading(false));
  }, [deviceId]);

  // Initial load + 30 s auto-refresh of interface list
  useEffect(() => {
    loadDevice();
    loadInterfaces();

    ifaceTimerRef.current = setInterval(loadInterfaces, 30_000);
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

  async function toggleMonitoring(iface: Interface) {
    setToggleBusy((b) => ({ ...b, [iface.id]: true }));
    try {
      const updated = await api.interfaces.update(iface.id, {
        enabled_for_monitoring: !iface.enabled_for_monitoring,
      });
      setInterfaces((prev) =>
        prev.map((i) => (i.id === updated.id ? updated : i)),
      );
    } catch {
      // silently ignore; state stays unchanged
    } finally {
      setToggleBusy((b) => ({ ...b, [iface.id]: false }));
    }
  }

  const selectedIface =
    interfaces.find((i) => i.id === selectedIfaceId) ?? null;

  if (loading) {
    return (
      <div className="text-sm text-muted-foreground">Loading device…</div>
    );
  }

  if (error || !device) {
    return (
      <div className="space-y-4">
        <Link to="/devices" className="text-sm text-muted-foreground hover:underline">
          ← Back to devices
        </Link>
        <p className="text-sm text-destructive">{error ?? "Device not found."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div className="flex flex-wrap items-center gap-3">
        <Link
          to="/devices"
          className="text-sm text-muted-foreground hover:underline"
        >
          ← Devices
        </Link>
        <h1 className="text-2xl font-bold tracking-tight">{device.name}</h1>
        <Badge variant={device.reachable ? "default" : "destructive"}>
          {device.reachable ? "reachable" : "unreachable"}
        </Badge>
        {/* Read-only badge: every device is an SNMP telemetry source */}
        <Badge
          variant="secondary"
          title="SNMP is read-only telemetry; Rerouter only polls this device."
        >
          Read-only · SNMP
        </Badge>

        {/* Edit / Delete — gated by manage_devices */}
        {canManage && (
          <div className="ml-auto flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setEditOpen(true)}
            >
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
          </div>
        )}
      </div>

      {/* Edit dialog */}
      {canManage && (
        <EditDialog
          device={device}
          open={editOpen}
          onClose={() => setEditOpen(false)}
          onSaved={() => { loadDevice(); }}
        />
      )}

      {/* Device facts */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Device facts</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
            <dt className="font-medium text-muted-foreground">Hostname</dt>
            <dd>
              <code>{device.hostname}</code>
            </dd>
            <dt className="font-medium text-muted-foreground">SNMP</dt>
            <dd>
              {device.snmp_version} / port {device.snmp_port}
            </dd>
            {device.vendor && (
              <>
                <dt className="font-medium text-muted-foreground">Vendor</dt>
                <dd>{device.vendor}</dd>
              </>
            )}
            {device.model && (
              <>
                <dt className="font-medium text-muted-foreground">Model</dt>
                <dd>{device.model}</dd>
              </>
            )}
            {device.os_version && (
              <>
                <dt className="font-medium text-muted-foreground">OS version</dt>
                <dd>{device.os_version}</dd>
              </>
            )}
            {device.sys_name && (
              <>
                <dt className="font-medium text-muted-foreground">sysName</dt>
                <dd>{device.sys_name}</dd>
              </>
            )}
            {device.sys_uptime && (
              <>
                <dt className="font-medium text-muted-foreground">sysUptime</dt>
                <dd>{device.sys_uptime}</dd>
              </>
            )}
            {device.last_poll_at && (
              <>
                <dt className="font-medium text-muted-foreground">Last poll</dt>
                <dd>{new Date(device.last_poll_at).toLocaleString()}</dd>
              </>
            )}
            <dt className="font-medium text-muted-foreground">Poll interval</dt>
            <dd>{device.poll_interval_seconds} s</dd>
            {device.last_error && (
              <>
                <dt className="font-medium text-muted-foreground">Last error</dt>
                <dd className="text-destructive">{device.last_error}</dd>
              </>
            )}
          </dl>

          {canManage && (
            <div className="mt-4 flex gap-2">
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
                Test SNMP
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() =>
                  api.devices
                    .discover(device.id)
                    .then((r) => {
                      alert(`Discovered ${r.discovered} interfaces`);
                      loadInterfaces();
                    })
                }
              >
                Discover interfaces
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Interfaces table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">
            Interfaces ({device.interface_count})
          </CardTitle>
        </CardHeader>
        <CardContent>
          {ifLoading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : interfaces.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No interfaces discovered yet. Click "Discover interfaces" above.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">Name</th>
                    <th className="py-2 pr-4 font-medium">Type</th>
                    <th className="py-2 pr-4 font-medium">Descr / Alias</th>
                    <th className="py-2 pr-4 font-medium">Speed</th>
                    <th className="py-2 pr-4 font-medium">Status</th>
                    <th className="py-2 pr-4 font-medium">Rx bps / pps</th>
                    <th className="py-2 pr-4 font-medium">Tx bps / pps</th>
                    <th className="py-2 pr-4 font-medium">Util %</th>
                    <th className="py-2 font-medium">Monitor</th>
                  </tr>
                </thead>
                <tbody>
                  {interfaces.map((iface) => {
                    const ifType = classifyInterface(
                      iface.if_name,
                      iface.if_descr,
                    );
                    const isSelected = iface.id === selectedIfaceId;
                    return (
                      <tr
                        key={iface.id}
                        className={[
                          "border-b last:border-0 cursor-pointer transition-colors",
                          isSelected
                            ? "bg-accent/60"
                            : "hover:bg-accent/30",
                        ].join(" ")}
                        onClick={() => setSelectedIfaceId(iface.id)}
                        aria-selected={isSelected}
                      >
                        <td className="py-2 pr-4 font-medium">
                          {iface.if_name}
                        </td>
                        <td className="py-2 pr-4">
                          <Badge variant={TYPE_VARIANT[ifType]}>
                            {ifType}
                          </Badge>
                        </td>
                        <td className="py-2 pr-4 text-xs text-muted-foreground">
                          {iface.if_alias ?? iface.if_descr ?? "—"}
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {iface.if_speed_bps !== null
                            ? fmtBps(iface.if_speed_bps)
                            : "—"}
                        </td>
                        <td className="py-2 pr-4">
                          <div className="flex items-center gap-1">
                            <Badge
                              variant={operStatusVariant(iface.oper_status)}
                            >
                              {iface.oper_status}
                            </Badge>
                            {iface.admin_status !== iface.oper_status && (
                              <Badge variant="outline">
                                adm:{iface.admin_status}
                              </Badge>
                            )}
                          </div>
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {iface.metrics && iface.metrics.valid_sample ? (
                            <>
                              {fmtBps(iface.metrics.rx_bps)}
                              <br />
                              {fmtPps(iface.metrics.rx_pps)}
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {iface.metrics && iface.metrics.valid_sample ? (
                            <>
                              {fmtBps(iface.metrics.tx_bps)}
                              <br />
                              {fmtPps(iface.metrics.tx_pps)}
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td className="py-2 pr-4 text-xs">
                          {iface.metrics && iface.metrics.valid_sample ? (
                            <>
                              Rx{" "}
                              {iface.metrics.rx_util_percent.toFixed(1)}%
                              <br />
                              Tx{" "}
                              {iface.metrics.tx_util_percent.toFixed(1)}%
                            </>
                          ) : (
                            "—"
                          )}
                        </td>
                        <td
                          className="py-2"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {canManage ? (
                            <Button
                              size="sm"
                              variant={
                                iface.enabled_for_monitoring
                                  ? "default"
                                  : "outline"
                              }
                              disabled={toggleBusy[iface.id]}
                              onClick={() => void toggleMonitoring(iface)}
                            >
                              {iface.enabled_for_monitoring ? "On" : "Off"}
                            </Button>
                          ) : (
                            <span className="text-xs text-muted-foreground">
                              {iface.enabled_for_monitoring ? "On" : "Off"}
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Telemetry panel — shown for the selected interface */}
      {selectedIface !== null && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">
              Telemetry — last hour
            </CardTitle>
          </CardHeader>
          <CardContent>
            <TelemetryPanel key={selectedIface.id} iface={selectedIface} />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
