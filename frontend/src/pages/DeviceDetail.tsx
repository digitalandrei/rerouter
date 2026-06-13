/**
 * /devices/:id — device detail, an NMS-style tabbed view. Thin orchestrator: the
 * tabs and cards live in ./device-detail/*. Header has a back link, name, a
 * reachability badge, a read-only badge, a single inventory Refresh, and Delete.
 * Edit + Test SNMP/SSH live in the Settings tab. Auto-reloads every 30 s.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, useNavigate, useSearchParams, Link } from "react-router-dom";
import { ArrowLeft, RefreshCw, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { api, type Device, type Interface, type Rule, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ToneBadge } from "@/components/status-badge";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { OverviewTab } from "./device-detail/overview-tab";
import { InterfacesTab } from "./device-detail/interfaces-tab";
import { BgpSessionsCard } from "./device-detail/bgp-sessions-card";
import { AnnouncedPrefixesCard } from "./device-detail/announced-prefixes-card";
import { DeviceSettingsTab } from "./device-detail/device-settings-tab";

export default function DeviceDetail() {
  const { hasPermission } = useAuth();
  const canManage = hasPermission("manage_devices");
  const { id } = useParams<{ id: string }>();
  const deviceId = Number(id);
  const navigate = useNavigate();

  const [searchParams, setSearchParams] = useSearchParams();
  const raw = searchParams.get("tab");
  const tab = raw === "settings" && canManage ? "settings" : raw === "interfaces" ? "interfaces" : "overview";
  const setTab = (next: string) =>
    setSearchParams(
      (prev) => {
        const p = new URLSearchParams(prev);
        if (next === "overview") p.delete("tab");
        else p.set("tab", next);
        return p;
      },
      { replace: true },
    );

  const [device, setDevice] = useState<Device | null>(null);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [rules, setRules] = useState<Rule[]>([]);
  const [loading, setLoading] = useState(true);
  const [ifLoading, setIfLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [refreshing, setRefreshing] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadDevice = useCallback(() => {
    if (!Number.isFinite(deviceId)) return;
    api.devices
      .get(deviceId)
      .then(setDevice)
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load device"))
      .finally(() => setLoading(false));
  }, [deviceId]);

  const loadInterfaces = useCallback(() => {
    if (!Number.isFinite(deviceId)) return;
    api.devices
      .interfaces(deviceId)
      .then(setInterfaces)
      .catch(() => setInterfaces([]))
      .finally(() => setIfLoading(false));
  }, [deviceId]);

  useEffect(() => {
    loadDevice();
    loadInterfaces();
    api.rules.list().then(setRules).catch(() => setRules([]));
    timerRef.current = setInterval(() => {
      loadDevice();
      loadInterfaces();
    }, 30_000);
    return () => {
      if (timerRef.current !== null) clearInterval(timerRef.current);
    };
  }, [loadDevice, loadInterfaces]);

  // The single "Refresh": re-discover the inventory (interfaces, BGP sessions,
  // announced prefixes) — NOT telemetry — then reload the page + cards.
  async function refresh() {
    setRefreshing(true);
    try {
      if (canManage) {
        await Promise.allSettled([
          api.devices.discover(deviceId),
          api.devices.discoverBgp(deviceId),
          api.devices.discoverPrefixes(deviceId),
        ]);
      }
      loadDevice();
      loadInterfaces();
      setRefreshKey((k) => k + 1);
      toast.success("Refreshed device inventory");
    } finally {
      setRefreshing(false);
    }
  }

  const ruleCountByIfaceId = useMemo(() => {
    const m = new Map<number, number>();
    for (const r of rules) {
      if (r.interface_id !== null) m.set(r.interface_id, (m.get(r.interface_id) ?? 0) + 1);
    }
    return m;
  }, [rules]);

  if (loading) {
    return <div className="text-sm text-muted-foreground">Loading device…</div>;
  }
  if (error || !device) {
    return (
      <div className="space-y-4">
        <Link to="/devices" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline">
          <ArrowLeft className="size-4" /> Back to devices
        </Link>
        <p className="text-sm text-destructive">{error ?? "Device not found."}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Link to="/devices" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline">
          <ArrowLeft className="size-4" /> Devices
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight">{device.name}</h1>
          {device.reachable ? (
            <ToneBadge tone="good">reachable</ToneBadge>
          ) : (
            <ToneBadge tone="bad">unreachable</ToneBadge>
          )}
          <Badge variant="secondary" title="SNMP is read-only telemetry; Rerouter only polls this device.">
            Read-only · SNMP
          </Badge>

          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Button size="sm" variant="outline" disabled={refreshing} onClick={() => void refresh()}>
              <RefreshCw className="size-4" />
              {refreshing ? "Refreshing…" : "Refresh"}
            </Button>
            {canManage && (
              <Button
                size="sm"
                variant="outline"
                className="text-destructive hover:text-destructive"
                onClick={() => setDeleteOpen(true)}
              >
                <Trash2 className="size-4" />
                Delete
              </Button>
            )}
          </div>
        </div>
        <p className="text-sm text-muted-foreground">
          <code>{device.hostname}</code>
          {(device.vendor || device.model) && ` · ${[device.vendor, device.model].filter(Boolean).join(" ")}`}
          {device.os_version && ` · ${device.os_version}`}
        </p>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="interfaces">Interfaces ({device.interface_count})</TabsTrigger>
          {canManage && <TabsTrigger value="settings">Settings</TabsTrigger>}
        </TabsList>

        <TabsContent value="overview" className="mt-4 space-y-4">
          <OverviewTab device={device} />
          <BgpSessionsCard deviceId={deviceId} canManage={canManage} refreshKey={refreshKey} />
          <AnnouncedPrefixesCard deviceId={deviceId} refreshKey={refreshKey} />
        </TabsContent>

        <TabsContent value="interfaces" className="mt-4">
          <Card>
            <CardContent className="px-0 py-2">
              <InterfacesTab
                deviceId={deviceId}
                interfaces={interfaces}
                loading={ifLoading}
                ruleCountByIfaceId={ruleCountByIfaceId}
              />
            </CardContent>
          </Card>
        </TabsContent>

        {canManage && (
          <TabsContent value="settings" className="mt-4">
            <DeviceSettingsTab device={device} onSaved={loadDevice} />
          </TabsContent>
        )}
      </Tabs>

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        title="Delete device"
        description={
          <>
            Permanently delete <strong>{device.name}</strong> and all its interfaces, telemetry, BGP
            sessions and prefixes. This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        destructive
        requireText="CONFIRM"
        onConfirm={async () => {
          try {
            await api.devices.remove(device.id);
            toast.success("Device deleted");
            navigate("/devices");
          } catch (err) {
            toast.error(err instanceof ApiError ? err.message : "Delete failed");
            setDeleteOpen(false);
          }
        }}
      />
    </div>
  );
}
