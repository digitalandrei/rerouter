/**
 * /flows — NetFlow/IPFIX flow telemetry. Two tabs:
 *  - Top statistics: per-device top-10 talkers / ports / interface traffic.
 *  - Search: filter flows by device / source / destination / port, with lazy
 *    autocomplete on the source/destination/port fields.
 *
 * Flow signals can participate in automatic rules only when the independent
 * flow-action gate, device allowlist, and fresh SNMP corroboration all pass.
 */
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Eye, Waves } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  type Device,
  type FlowTopRow,
  type FlowDetailResponse,
  ApiError,
} from "@/lib/api";
import { SearchableSelect, type SelectOption } from "@/components/searchable-select";
import { PROTOCOLS } from "@/lib/protocols";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { RowActionButton } from "@/components/row-action-button";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { AutocompleteInput } from "@/components/autocomplete-input";
import { fmtBps, fmtPps } from "@/lib/telemetry";
import { FlowsTab } from "@/pages/device-detail/flows-tab";
import { protoName } from "@/pages/device-detail/flows-tab";

/** Native styled <select> for picking a device (avoids a new UI dependency). */
function DeviceSelect({
  devices,
  value,
  onChange,
  allowAll,
  id,
}: {
  devices: Device[];
  value: number | null;
  onChange: (id: number | null) => void;
  allowAll?: boolean;
  id?: string;
}) {
  return (
    <select
      id={id}
      className="h-9 rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
      value={value ?? ""}
      onChange={(e) => onChange(e.target.value === "" ? null : Number(e.target.value))}
    >
      {allowAll && <option value="">All devices</option>}
      {devices.map((d) => (
        <option key={d.id} value={d.id}>
          {d.name}
        </option>
      ))}
    </select>
  );
}

export default function Flows() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "search" ? "search" : "top";
  const [devices, setDevices] = useState<Device[]>([]);
  const [devicesError, setDevicesError] = useState(false);
  useEffect(() => {
    api.devices.list().then((value) => { setDevices(value); setDevicesError(false); }).catch(() => setDevicesError(true));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Waves className="size-6" />
        <h1 className="text-2xl font-bold tracking-tight">Flows</h1>
      </div>

      {devicesError && <p role="alert" className="text-sm text-destructive">Devices could not be loaded. Device filters and top statistics are unavailable.</p>}

      {!devicesError && <Tabs value={tab} onValueChange={(value) => setParams((previous) => { const next = new URLSearchParams(previous); if (value === "top") next.delete("tab"); else next.set("tab", value); return next; })}>
        <TabsList>
          <TabsTrigger value="top">Top statistics</TabsTrigger>
          <TabsTrigger value="search">Search</TabsTrigger>
        </TabsList>

        <TabsContent value="top" className="mt-4">
          <TopStatsTab devices={devices} />
        </TabsContent>
        <TabsContent value="search" className="mt-4">
          <SearchTab devices={devices} />
        </TabsContent>
      </Tabs>}
    </div>
  );
}

function TopStatsTab({ devices }: { devices: Device[] }) {
  const [deviceId, setDeviceId] = useState<number | null>(null);
  // Default to the first device once the list loads.
  useEffect(() => {
    if (deviceId === null && devices.length > 0) setDeviceId(devices[0].id);
  }, [devices, deviceId]);

  if (devices.length === 0) {
    return <p className="text-sm text-muted-foreground">No devices enrolled.</p>;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Label htmlFor="top-flow-device">Device</Label>
        <DeviceSelect id="top-flow-device" devices={devices} value={deviceId} onChange={setDeviceId} />
      </div>
      {deviceId !== null && <FlowsTab deviceId={deviceId} refreshKey={0} />}
    </div>
  );
}

function SearchTab({ devices }: { devices: Device[] }) {
  const [params, setParams] = useSearchParams();
  const numberParam = (name: string) => { const raw = params.get(name); const value = raw === null ? NaN : Number(raw); return Number.isSafeInteger(value) && value >= 0 ? value : null; };
  const deviceId = numberParam("device");
  const src = params.get("src") ?? "";
  const dst = params.get("dst") ?? "";
  const port = params.get("port") ?? "";
  const proto = params.get("protocol") ?? "";
  const metric: "bytes" | "pkts" = params.get("metric") === "pkts" ? "pkts" : "bytes";
  const minutes = [15, 60, 360, 1440].includes(numberParam("minutes") ?? 60) ? (numberParam("minutes") ?? 60) : 60;
  const limit = [25, 50, 100].includes(numberParam("limit") ?? 50) ? (numberParam("limit") ?? 50) : 50;
  const setFilter = (name: string, value: string) => setParams((previous) => { const next = new URLSearchParams(previous); if (value) next.set(name, value); else next.delete(name); return next; }, { replace: true });
  const [rows, setRows] = useState<FlowTopRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<FlowTopRow | null>(null);
  const ifIndex = params.get("interface") ?? "";
  const [interfaces, setInterfaces] = useState<SelectOption[]>([]);
  const seqRef = useRef(0);

  // Suggestion fetchers, memoized on the selected device so the autocomplete's
  // debounced effect only re-subscribes when the scope changes.
  const fetchSrc = useCallback(
    (q: string) => api.flows.suggest("src", q, deviceId ?? undefined),
    [deviceId],
  );
  const fetchDst = useCallback(
    (q: string) => api.flows.suggest("dst", q, deviceId ?? undefined),
    [deviceId],
  );
  const fetchPort = useCallback(
    (q: string) => api.flows.suggest("port", q, deviceId ?? undefined),
    [deviceId],
  );

  const portNum = useMemo(() => {
    const n = parseInt(port, 10);
    return Number.isFinite(n) && String(n) === port.trim() ? n : undefined;
  }, [port]);
  const protoNum = useMemo(() => (proto === "" ? undefined : parseInt(proto, 10)), [proto]);
  const ifIndexNum = useMemo(
    () => (ifIndex === "" ? undefined : parseInt(ifIndex, 10)),
    [ifIndex],
  );
  const portInvalid = port.trim() !== "" && (portNum === undefined || portNum < 0 || portNum > 65535);

  // Load the selected device's interfaces for the interface filter dropdown.
  useEffect(() => {
    if (deviceId === null) {
      setInterfaces([]);
      setFilter("interface", "");
      return;
    }
    let cancelled = false;
    setFilter("interface", ""); // reset the interface filter when the device changes
    api.devices
      .interfaces(deviceId)
      .then((ifs) => {
        if (!cancelled)
          setInterfaces(
            ifs.map((i) => ({
              value: String(i.if_index),
              label: i.if_name || i.if_descr || `if${i.if_index}`,
            })),
          );
      })
      .catch(() => {
        if (!cancelled) setInterfaces([]);
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId]);

  // Lazy search: debounced on any filter change, with a sequence guard so a
  // slower earlier response can't overwrite a newer one.
  useEffect(() => {
    const t = setTimeout(() => {
      if (portInvalid) { setError("Enter a port from 0 to 65535."); return; }
      const seq = ++seqRef.current;
      setLoading(true);
      api.flows
        .search({
          deviceId: deviceId ?? undefined,
          src: src.trim() || undefined,
          dst: dst.trim() || undefined,
          port: portNum,
          protocol: protoNum,
          ifIndex: ifIndexNum,
          metric,
          minutes,
          limit,
        })
        .then((res) => {
          if (seq !== seqRef.current) return;
          setRows(res.rows);
          setError(null);
        })
        .catch((e) => {
          if (seq !== seqRef.current) return;
          setError(e instanceof ApiError ? e.message : "Search failed");
        })
        .finally(() => {
          if (seq === seqRef.current) setLoading(false);
        });
    }, 350);
    return () => clearTimeout(t);
  }, [deviceId, src, dst, portNum, protoNum, ifIndexNum, metric, minutes, limit, portInvalid]);

  const windowSecs = minutes * 60;
  const rate = (r: FlowTopRow) =>
    metric === "bytes" ? fmtBps((r.est_bytes * 8) / windowSecs) : fmtPps(r.est_pkts / windowSecs);

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="grid grid-cols-1 gap-4 py-4 md:grid-cols-3 xl:grid-cols-7">
          <div className="space-y-1">
            <Label htmlFor="flow-device">Device</Label>
            <DeviceSelect id="flow-device" devices={devices} value={deviceId} onChange={(value) => setFilter("device", value === null ? "" : String(value))} allowAll />
          </div>
          <div className="space-y-1">
            <Label htmlFor="flow-interface">Interface</Label>
            <SearchableSelect
              id="flow-interface"
              options={[{ value: "", label: "All interfaces" }, ...interfaces]}
              value={ifIndex}
              onChange={(value) => setFilter("interface", value)}
              placeholder={deviceId === null ? "Select a device first" : "All interfaces"}
              disabled={deviceId === null}
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="flow-source">Source</Label>
            <AutocompleteInput
              id="flow-source"
              value={src}
              onChange={(value) => setFilter("src", value)}
              fetchSuggestions={fetchSrc}
              placeholder="e.g. 192.168.200.92 (partial ok)"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="flow-destination">Destination</Label>
            <AutocompleteInput
              id="flow-destination"
              value={dst}
              onChange={(value) => setFilter("dst", value)}
              fetchSuggestions={fetchDst}
              placeholder="e.g. 23.45.23.208 (partial ok)"
            />
          </div>
          <div className="space-y-1">
            <Label htmlFor="flow-port">Port</Label>
            <AutocompleteInput
              id="flow-port"
              value={port}
              onChange={(value) => setFilter("port", value)}
              fetchSuggestions={fetchPort}
              placeholder="e.g. 53"
              inputMode="numeric"
            />
            {portInvalid && <p className="text-xs text-destructive">Enter a numeric port</p>}
          </div>
          <div className="space-y-1">
            <Label htmlFor="flow-protocol">Protocol</Label>
            <SearchableSelect
              id="flow-protocol"
              options={PROTOCOLS}
              value={proto}
              onChange={(value) => setFilter("protocol", value)}
              placeholder="Any protocol"
            />
          </div>
          <div className="space-y-1">
            <Label>Rank by</Label>
            <div className="flex items-center gap-1">
              <Button
                size="sm"
                variant={metric === "bytes" ? "default" : "outline"}
                onClick={() => setFilter("metric", "bytes")}
              >
                Traffic
              </Button>
              <Button
                size="sm"
                variant={metric === "pkts" ? "default" : "outline"}
                onClick={() => setFilter("metric", "pkts")}
              >
                Packets
              </Button>
            </div>
          </div>
          <div className="space-y-1"><Label htmlFor="flow-window">Time window</Label><select id="flow-window" className="h-9 rounded-md border bg-background px-2 text-sm" value={minutes} onChange={(event) => setFilter("minutes", event.target.value)}><option value="15">15 minutes</option><option value="60">1 hour</option><option value="360">6 hours</option><option value="1440">24 hours</option></select></div>
          <div className="space-y-1"><Label htmlFor="flow-limit">Top results</Label><select id="flow-limit" className="h-9 rounded-md border bg-background px-2 text-sm" value={limit} onChange={(event) => setFilter("limit", event.target.value)}><option value="25">25</option><option value="50">50</option><option value="100">100</option></select></div>
          <div className="flex items-end"><Button type="button" variant="outline" onClick={() => setParams({ tab: "search" }, { replace: true })}>Clear filters</Button></div>
        </CardContent>
      </Card>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <Card>
        <CardContent className="px-0 py-0">
          {loading && rows.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">Searching…</p>
          ) : rows.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">
              No matching flows in the last {minutes} min.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-6">Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Proto</TableHead>
                  <TableHead className="text-right">{metric === "bytes" ? "Rate" : "Packets/s"}</TableHead>
                  <TableHead className="pr-6">Sampling</TableHead>
                  <TableHead className="pr-6 text-right">Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell className="pl-6 font-mono text-xs">
                      {r.src_addr}
                      {r.src_port != null && `:${r.src_port}`}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {r.dst_addr}
                      {r.dst_port != null && `:${r.dst_port}`}
                    </TableCell>
                    <TableCell>{protoName(r.protocol)}</TableCell>
                    <TableCell className="text-right font-mono text-xs">{rate(r)}</TableCell>
                    <TableCell className="pr-6">
                      <div className="flex items-center gap-1">
                        {r.estimated && (
                          <Badge variant="outline" title={`Scaled by the ${r.sampling_rate}:1 sampling rate`}>
                            est {r.sampling_rate}:1
                          </Badge>
                        )}
                        {r.low_confidence && <Badge variant="destructive">low conf</Badge>}
                        {!r.estimated && !r.low_confidence && (
                          <span className="text-xs text-muted-foreground">1:1</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="pr-6 text-right"><RowActionButton label={`View flow to ${r.dst_addr}`} onClick={() => setSelected(r)}><Eye className="size-4" /></RowActionButton></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <FlowDetailDialog
        row={selected}
        deviceId={deviceId ?? undefined}
        windowMinutes={minutes}
        onClose={() => setSelected(null)}
      />
    </div>
  );
}

/** Read-only full detail for one searched flow: the 5-tuple summary (from the
 *  clicked row) plus the per-(interface, direction) in/out breakdown fetched
 *  from /api/flows/detail. */
function FlowDetailDialog({
  row,
  deviceId,
  windowMinutes,
  onClose,
}: {
  row: FlowTopRow | null;
  deviceId?: number;
  windowMinutes: number;
  onClose: () => void;
}) {
  const [detail, setDetail] = useState<FlowDetailResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (row == null) {
      setDetail(null);
      setError(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.flows
      .detail({
        deviceId,
        src: row.src_addr ?? "",
        dst: row.dst_addr ?? "",
        srcPort: row.src_port,
        dstPort: row.dst_port,
        protocol: row.protocol ?? 0,
        minutes: windowMinutes,
      })
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof ApiError ? e.message : "Failed to load flow detail");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [row, deviceId, windowMinutes]);

  if (row == null) return null;
  const windowSecs = windowMinutes * 60;
  const dirLabel = (d: string) => (d === "ingress" ? "in (ingress)" : "out (egress)");

  return (
    <Dialog open={row != null} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Flow detail</DialogTitle>
        </DialogHeader>

        <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1.5 text-sm">
          <DetailRow label="Source">
            <span className="font-mono text-xs">
              {row.src_addr}
              {row.src_port != null && `:${row.src_port}`}
            </span>
          </DetailRow>
          <DetailRow label="Destination">
            <span className="font-mono text-xs">
              {row.dst_addr}
              {row.dst_port != null && `:${row.dst_port}`}
            </span>
          </DetailRow>
          <DetailRow label="Protocol">{protoName(row.protocol)}</DetailRow>
        </dl>

        <div className="mt-3">
          <p className="mb-1 text-xs font-medium text-muted-foreground">
            Interfaces (in / out) · last {windowMinutes} min
          </p>
          {loading ? (
            <p className="py-2 text-sm text-muted-foreground">Loading…</p>
          ) : error ? (
            <p className="py-2 text-sm text-destructive">{error}</p>
          ) : detail && detail.interfaces.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-0">Interface</TableHead>
                  <TableHead>Direction</TableHead>
                  <TableHead className="text-right">Rate</TableHead>
                  <TableHead className="text-right">Packets/s</TableHead>
                  <TableHead className="pr-0 text-right">Sampling</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detail.interfaces.map((iface, i) => (
                  <TableRow key={i}>
                    <TableCell className="pl-0 font-medium">
                      {iface.if_name ?? `if${iface.if_index}`}
                    </TableCell>
                    <TableCell>{dirLabel(iface.direction)}</TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {fmtBps((iface.est_bytes * 8) / windowSecs)}
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs">
                      {fmtPps(iface.est_pkts / windowSecs)}
                    </TableCell>
                    <TableCell className="pr-0 text-right">
                      <span className="inline-flex items-center justify-end gap-1">
                        {iface.estimated ? `${iface.sampling_rate}:1` : "1:1"}
                        {iface.low_confidence && <Badge variant="destructive">low</Badge>}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <p className="py-2 text-sm text-muted-foreground">
              No per-interface data in the last {windowMinutes} min.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function DetailRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </>
  );
}
