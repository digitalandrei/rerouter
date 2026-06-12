/**
 * /devices/:id — device facts and interface table.
 *
 * Shows: vendor/model/OS/uptime/last poll/last error, then the interface list
 * with name, descr/alias, speed, oper/admin status, live rx/tx bps & pps,
 * utilization %, and an enable-for-monitoring toggle.
 */
import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import { api, type Device, type Interface, ApiError } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

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

export default function DeviceDetail() {
  const { id } = useParams<{ id: string }>();
  const deviceId = Number(id);

  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(true);
  const [ifLoading, setIfLoading] = useState(true);
  const [toggleBusy, setToggleBusy] = useState<Record<number, boolean>>({});
  const [error, setError] = useState<string | null>(null);

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
      .then(setInterfaces)
      .catch(() => setInterfaces([]))
      .finally(() => setIfLoading(false));
  }, [deviceId]);

  useEffect(() => {
    loadDevice();
    loadInterfaces();
  }, [loadDevice, loadInterfaces]);

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
      <div className="flex items-center gap-3">
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
      </div>

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
                  {interfaces.map((iface) => (
                    <tr key={iface.id} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-medium">
                        {iface.if_name}
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
                      <td className="py-2">
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
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
