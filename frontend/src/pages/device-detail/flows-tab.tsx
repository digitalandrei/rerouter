/**
 * Flows tab — NetFlow/IPFIX telemetry for a device: top talkers,
 * ports, and per-interface traffic over the last hour, plus exporter health.
 * Counts are sampled; values scaled by the sampling rate are badged "est".
 * See ../../../../docs/flow-telemetry.md.
 */
import { useCallback, useEffect, useState } from "react";
import { Info, TriangleAlert } from "lucide-react";
import {
  api,
  type FlowExporter,
  type FlowTopResponse,
  type FlowTopRow,
  ApiError,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { fmtBps, fmtPps } from "@/lib/telemetry";
import { samplingSourceLabel } from "@/lib/labels";

const WINDOW_MINUTES = 60;

const PROTO: Record<number, string> = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 58: "ICMPv6", 132: "SCTP" };
export const protoName = (n?: number) => (n === undefined ? "—" : (PROTO[n] ?? String(n)));

interface FlowsTabProps {
  deviceId: number;
  refreshKey: number;
}

export function FlowsTab({ deviceId, refreshKey }: FlowsTabProps) {
  const [metric, setMetric] = useState<"bytes" | "pkts">("bytes");
  const [traffic, setTraffic] = useState<FlowTopResponse | null>(null);
  const [ports, setPorts] = useState<FlowTopResponse | null>(null);
  const [asStats, setAsStats] = useState<FlowTopResponse | null>(null);
  const [talkers, setTalkers] = useState<FlowTopResponse | null>(null);
  const [exporters, setExporters] = useState<FlowExporter[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      api.flows.top(deviceId, { dimension: "traffic", minutes: WINDOW_MINUTES, metric }),
      api.flows.top(deviceId, { dimension: "ports", minutes: WINDOW_MINUTES, metric, portKind: "dst" }),
      api.flows.top(deviceId, { dimension: "as", minutes: WINDOW_MINUTES, metric, asKind: "src" }),
      api.flows.top(deviceId, { dimension: "talkers", minutes: WINDOW_MINUTES, metric }),
      api.flows.exporters(deviceId),
    ])
      .then(([t, p, a, k, e]) => {
        setTraffic(t);
        setPorts(p);
        setAsStats(a);
        setTalkers(k);
        setExporters(e);
        setError(null);
      })
      .catch((err) => setError(err instanceof ApiError ? err.message : "Failed to load flows"))
      .finally(() => setLoading(false));
  }, [deviceId, metric]);

  useEffect(() => {
    load();
  }, [load, refreshKey]);

  // bytes/pkts totals are over the window; show them as a rate (per second).
  const windowSecs = WINDOW_MINUTES * 60;
  const rate = (row: FlowTopRow) =>
    metric === "bytes"
      ? fmtBps((row.est_bytes * 8) / windowSecs)
      : fmtPps(row.est_pkts / windowSecs);

  const hasAnyData =
    (traffic?.rows.length ?? 0) +
      (ports?.rows.length ?? 0) +
      (asStats?.rows.length ?? 0) +
      (talkers?.rows.length ?? 0) >
    0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Last {WINDOW_MINUTES} min · sampled flow telemetry. Read-only — flows never trigger reroutes.
        </p>
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant={metric === "bytes" ? "default" : "outline"}
            onClick={() => setMetric("bytes")}
          >
            By traffic
          </Button>
          <Button
            size="sm"
            variant={metric === "pkts" ? "default" : "outline"}
            onClick={() => setMetric("pkts")}
          >
            By packets
          </Button>
        </div>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}

      <ExportersCard exporters={exporters} />

      {!loading && !hasAnyData && !error && (
        <Card>
          <CardContent className="flex items-center gap-2 py-6 text-sm text-muted-foreground">
            <Info className="size-4" />
            No flows collected yet. Enable the flow collector ([flow] in config) and point the
            device's NetFlow exporter at it. See docs/flow-telemetry.md.
          </CardContent>
        </Card>
      )}

      {(() => {
        const rateHead = metric === "bytes" ? "Rate" : "Packets/s";
        return (
          <>
            <TopCard
              title="Top interfaces (traffic)"
              response={traffic}
              headers={
                <>
                  <TableHead className="pl-6">Interface</TableHead>
                  <TableHead className="text-right">{rateHead}</TableHead>
                  <TableHead className="pr-6">Sampling</TableHead>
                </>
              }
              renderRow={(row, i) => (
                <TableRow key={i}>
                  <TableCell className="pl-6 font-medium">
                    {row.if_name ?? `if${row.if_index}`}
                    {row.if_name != null && (
                      <span className="ml-1.5 text-xs font-normal text-muted-foreground">
                        if{row.if_index}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-right font-mono text-xs">{rate(row)}</TableCell>
                  <RowFlags row={row} />
                </TableRow>
              )}
            />

            <TopCard
              title="Top destination ports"
              response={ports}
              headers={
                <>
                  <TableHead className="pl-6">Port</TableHead>
                  <TableHead>Proto</TableHead>
                  <TableHead className="text-right">{rateHead}</TableHead>
                  <TableHead className="pr-6">Sampling</TableHead>
                </>
              }
              renderRow={(row, i) => (
                <TableRow key={i}>
                  <TableCell className="pl-6 font-medium">{row.port}</TableCell>
                  <TableCell>{protoName(row.protocol)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{rate(row)}</TableCell>
                  <RowFlags row={row} />
                </TableRow>
              )}
            />

            <TopCard
              title="Top source AS"
              response={asStats}
              headers={
                <>
                  <TableHead className="pl-6">AS number</TableHead>
                  <TableHead className="text-right">{rateHead}</TableHead>
                  <TableHead className="pr-6">Sampling</TableHead>
                </>
              }
              renderRow={(row, i) => (
                <TableRow key={i}>
                  <TableCell className="pl-6 font-mono">AS{row.asn}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{rate(row)}</TableCell>
                  <RowFlags row={row} />
                </TableRow>
              )}
            />

            <TopCard
              title="Top talkers (5-tuple)"
              response={talkers}
              headers={
                <>
                  <TableHead className="pl-6">Source</TableHead>
                  <TableHead>Destination</TableHead>
                  <TableHead>Proto</TableHead>
                  <TableHead className="text-right">{rateHead}</TableHead>
                  <TableHead className="pr-6">Sampling</TableHead>
                </>
              }
              renderRow={(row, i) => (
                <TableRow key={i}>
                  <TableCell className="pl-6 font-mono text-xs">
                    {row.src_addr}
                    {row.src_port != null && `:${row.src_port}`}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {row.dst_addr}
                    {row.dst_port != null && `:${row.dst_port}`}
                  </TableCell>
                  <TableCell>{protoName(row.protocol)}</TableCell>
                  <TableCell className="text-right font-mono text-xs">{rate(row)}</TableCell>
                  <RowFlags row={row} />
                </TableRow>
              )}
            />
          </>
        );
      })()}
    </div>
  );
}

/** Sampling badges shared by every row: "est N:1" when scaled, plus a
 *  low-confidence warning (which also blocks flow-driven automatic actions). */
function RowFlags({ row }: { row: FlowTopRow }) {
  return (
    <TableCell className="pr-6">
      <div className="flex items-center gap-1">
        {row.estimated && (
          <Badge variant="outline" title={`Scaled by the ${row.sampling_rate}:1 sampling rate`}>
            est {row.sampling_rate}:1
          </Badge>
        )}
        {row.low_confidence && (
          <Badge variant="destructive" className="inline-flex items-center gap-1" title="Sampling rate unknown or unverified — treat as a rough estimate">
            <TriangleAlert className="size-3" />
            low conf
          </Badge>
        )}
        {!row.estimated && !row.low_confidence && <span className="text-xs text-muted-foreground">1:1</span>}
      </div>
    </TableCell>
  );
}

/** A titled card wrapping a top-N table. */
function TopCard({
  title,
  response,
  headers,
  renderRow,
}: {
  title: string;
  response: FlowTopResponse | null;
  headers: React.ReactNode;
  renderRow: (row: FlowTopRow, index: number) => React.ReactNode;
}) {
  const rows = response?.rows ?? [];
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent className="px-0 py-0">
        {rows.length === 0 ? (
          <p className="px-6 pb-4 text-sm text-muted-foreground">No data in the last hour.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">{headers}</TableRow>
            </TableHeader>
            <TableBody>{rows.map((r, i) => renderRow(r, i))}</TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}

/** Compact "time ago" for the exporter's last datagram (staleness at a glance). */
function lastSeen(iso: string | null): string {
  if (!iso) return "never";
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return "just now";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

function ExportersCard({ exporters }: { exporters: FlowExporter[] }) {
  if (exporters.length === 0) return null;
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Flow exporters</CardTitle>
      </CardHeader>
      <CardContent className="px-0 py-0">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-6">Source</TableHead>
              <TableHead>Domain</TableHead>
              <TableHead>Last datagram</TableHead>
              <TableHead>Sampling</TableHead>
              <TableHead>SNMP cross-check</TableHead>
              <TableHead>Datagrams</TableHead>
              <TableHead className="pr-6">Drops (no-tmpl / bad)</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {exporters.map((e) => {
              const stale =
                e.last_packet_at != null &&
                Date.now() - new Date(e.last_packet_at).getTime() > 60 * 60 * 1000;
              return (
                <TableRow key={e.id}>
                  <TableCell className="pl-6 font-mono text-xs">{e.source_addr}</TableCell>
                  <TableCell className="text-xs">{e.observation_domain}</TableCell>
                  <TableCell
                    className="text-xs"
                    title={e.last_packet_at ?? undefined}
                  >
                    {stale ? (
                      <Badge variant="destructive">{lastSeen(e.last_packet_at)}</Badge>
                    ) : (
                      lastSeen(e.last_packet_at)
                    )}
                  </TableCell>
                  <TableCell className="text-xs">
                    <div className="flex items-center gap-1">
                      {e.effective_sampling_rate}:1
                      <Badge variant={e.sampling_confidence === "high" ? "secondary" : "destructive"}>
                        {samplingSourceLabel(e.sampling_source)}
                      </Badge>
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">
                    {e.snmp_xcal_ratio == null ? "—" : `${e.snmp_xcal_ratio.toFixed(2)}×`}
                  </TableCell>
                  <TableCell className="text-xs">{e.datagrams_total}</TableCell>
                  <TableCell className="pr-6 text-xs">
                    {e.dropped_no_template} / {e.dropped_malformed}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
