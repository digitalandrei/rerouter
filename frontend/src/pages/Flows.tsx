/**
 * /flows — NetFlow/IPFIX flow telemetry (read-only). Two tabs:
 *  - Top statistics: per-device top-10 talkers / ports / interface traffic.
 *  - Search: filter flows by device / source / destination / port, with lazy
 *    autocomplete on the source/destination/port fields.
 *
 * Flows are a second, read-only telemetry source (docs/flow-telemetry.md). A
 * later iteration will wire these signals (pps & bps) into rule conditions.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Waves } from "lucide-react";
import { api, type Device, type FlowTopRow, ApiError } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
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

const WINDOW_MINUTES = 60;

/** Native styled <select> for picking a device (avoids a new UI dependency). */
function DeviceSelect({
  devices,
  value,
  onChange,
  allowAll,
}: {
  devices: Device[];
  value: number | null;
  onChange: (id: number | null) => void;
  allowAll?: boolean;
}) {
  return (
    <select
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
  const [devices, setDevices] = useState<Device[]>([]);
  useEffect(() => {
    api.devices.list().then(setDevices).catch(() => setDevices([]));
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <Waves className="size-6" />
        <h1 className="text-2xl font-bold tracking-tight">Flows</h1>
      </div>

      <Tabs defaultValue="top">
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
      </Tabs>
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
        <Label>Device</Label>
        <DeviceSelect devices={devices} value={deviceId} onChange={setDeviceId} />
      </div>
      {deviceId !== null && <FlowsTab deviceId={deviceId} refreshKey={0} />}
    </div>
  );
}

function SearchTab({ devices }: { devices: Device[] }) {
  const [deviceId, setDeviceId] = useState<number | null>(null);
  const [src, setSrc] = useState("");
  const [dst, setDst] = useState("");
  const [port, setPort] = useState("");
  const [proto, setProto] = useState(""); // "" = any; else IP protocol number
  const [metric, setMetric] = useState<"bytes" | "pkts">("bytes");
  const [rows, setRows] = useState<FlowTopRow[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
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

  // Lazy search: debounced on any filter change, with a sequence guard so a
  // slower earlier response can't overwrite a newer one.
  useEffect(() => {
    const t = setTimeout(() => {
      const seq = ++seqRef.current;
      setLoading(true);
      api.flows
        .search({
          deviceId: deviceId ?? undefined,
          src: src.trim() || undefined,
          dst: dst.trim() || undefined,
          port: portNum,
          protocol: protoNum,
          metric,
          limit: 100,
        })
        .then((res) => {
          if (seq !== seqRef.current) return;
          setRows(res.rows);
          setError(null);
        })
        .catch((e) => {
          if (seq !== seqRef.current) return;
          setError(e instanceof ApiError ? e.message : "Search failed");
          setRows([]);
        })
        .finally(() => {
          if (seq === seqRef.current) setLoading(false);
        });
    }, 350);
    return () => clearTimeout(t);
  }, [deviceId, src, dst, portNum, protoNum, metric]);

  const windowSecs = WINDOW_MINUTES * 60;
  const rate = (r: FlowTopRow) =>
    metric === "bytes" ? fmtBps((r.est_bytes * 8) / windowSecs) : fmtPps(r.est_pkts / windowSecs);

  const portInvalid = port.trim() !== "" && portNum === undefined;

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="grid grid-cols-1 gap-4 py-4 md:grid-cols-6">
          <div className="space-y-1">
            <Label>Device</Label>
            <DeviceSelect devices={devices} value={deviceId} onChange={setDeviceId} allowAll />
          </div>
          <div className="space-y-1">
            <Label>Source</Label>
            <AutocompleteInput
              value={src}
              onChange={setSrc}
              fetchSuggestions={fetchSrc}
              placeholder="e.g. 192.168.200.92 (partial ok)"
            />
          </div>
          <div className="space-y-1">
            <Label>Destination</Label>
            <AutocompleteInput
              value={dst}
              onChange={setDst}
              fetchSuggestions={fetchDst}
              placeholder="e.g. 23.45.23.208 (partial ok)"
            />
          </div>
          <div className="space-y-1">
            <Label>Port</Label>
            <AutocompleteInput
              value={port}
              onChange={setPort}
              fetchSuggestions={fetchPort}
              placeholder="e.g. 53"
              inputMode="numeric"
            />
            {portInvalid && <p className="text-xs text-destructive">Enter a numeric port</p>}
          </div>
          <div className="space-y-1">
            <Label>Protocol</Label>
            <select
              className="h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              value={proto}
              onChange={(e) => setProto(e.target.value)}
            >
              <option value="">Any</option>
              <option value="6">TCP</option>
              <option value="17">UDP</option>
              <option value="1">ICMP</option>
              <option value="132">SCTP</option>
            </select>
          </div>
          <div className="space-y-1">
            <Label>Rank by</Label>
            <div className="flex items-center gap-1">
              <Button
                size="sm"
                variant={metric === "bytes" ? "default" : "outline"}
                onClick={() => setMetric("bytes")}
              >
                Traffic
              </Button>
              <Button
                size="sm"
                variant={metric === "pkts" ? "default" : "outline"}
                onClick={() => setMetric("pkts")}
              >
                Packets
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <Card>
        <CardContent className="px-0 py-0">
          {loading && rows.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">Searching…</p>
          ) : rows.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">
              No matching flows in the last {WINDOW_MINUTES} min.
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
