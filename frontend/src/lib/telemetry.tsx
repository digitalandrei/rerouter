/**
 * Shared telemetry helpers for the device / interface detail pages.
 *
 * Centralises:
 *  - value formatters (bps, pps, dBm, °C, integers) + matching Y-axis tick forms,
 *  - interface-type classification + oper/admin status badge variants,
 *  - a moving-average smoother for the shared smoothing control,
 *  - <TelemetryChart>: a recharts LineChart card with a rich CUR/MIN/AVG/MAX
 *    legend, hover tooltip and HH:MM X-axis, reused by all six interface charts.
 *
 * Colour convention (matches the NMS reference): IN/RX is green, OUT/TX is red.
 */
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import type { Sample } from "@/lib/api";

// ---------------------------------------------------------------------------
// Value formatters
// ---------------------------------------------------------------------------

export function fmtBps(bps: number): string {
  if (!Number.isFinite(bps)) return "—";
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(2)} Gbps`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(2)} Kbps`;
  return `${Math.round(bps)} bps`;
}

export function fmtPps(pps: number): string {
  if (!Number.isFinite(pps)) return "—";
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(2)} Mpps`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(2)} Kpps`;
  return `${Math.round(pps)} pps`;
}

/** Whole-number count (errors / discards). */
export function fmtCount(n: number): string {
  if (!Number.isFinite(n)) return "—";
  return `${Math.round(n)}`;
}

export function fmtDbm(v: number): string {
  if (!Number.isFinite(v)) return "—";
  return `${v.toFixed(2)} dBm`;
}

export function fmtTempC(v: number): string {
  if (!Number.isFinite(v)) return "—";
  return `${v.toFixed(1)} °C`;
}

/** Format if_speed_bps for facts panels (uses bit/s scale). */
export function fmtSpeed(bps: number | null): string {
  if (bps === null) return "—";
  return fmtBps(bps);
}

/** Short Y-axis tick for bps. */
function bpsTick(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)}G`;
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)}M`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)}K`;
  return `${Math.round(bps)}`;
}

/** Short Y-axis tick for pps. */
function ppsTick(pps: number): string {
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(1)}M`;
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(0)}K`;
  return `${Math.round(pps)}`;
}

/** ISO timestamp -> HH:MM (X-axis). */
export function fmtTimeShort(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  return `${hh}:${mm}`;
}

/** ISO timestamp -> HH:MM:SS (tooltip). */
export function fmtTimeLong(iso: string): string {
  const d = new Date(iso);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

// ---------------------------------------------------------------------------
// Interface-type classification
// ---------------------------------------------------------------------------

export type IfaceType =
  | "Port-channel"
  | "Tunnel"
  | "Sub-if"
  | "Loopback"
  | "VLAN"
  | "Null"
  | "Physical";

export function classifyInterface(
  ifName: string,
  ifDescr: string | null,
): IfaceType {
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

export const TYPE_VARIANT: Record<
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
// Smoothing — client-side moving average over the last N minutes of points.
// Samples are ~60 s apart, so window 1 ≈ raw, 3 ≈ 3-pt, 5 ≈ 5-pt.
// ---------------------------------------------------------------------------

export type SmoothingWindow = 1 | 3 | 5;

/** Moving average of a numeric series; preserves null gaps (optics). */
function smoothSeries(
  values: (number | null)[],
  window: number,
): (number | null)[] {
  if (window <= 1) return values;
  return values.map((_, i) => {
    const start = Math.max(0, i - window + 1);
    let sum = 0;
    let count = 0;
    for (let j = start; j <= i; j++) {
      const v = values[j];
      if (v !== null && Number.isFinite(v)) {
        sum += v;
        count += 1;
      }
    }
    return count === 0 ? null : sum / count;
  });
}

/**
 * Apply smoothing across the numeric metrics of a Sample[] window.
 * Returns new objects with a derived `time` (HH:MM) label for the X-axis.
 */
export type ChartPoint = Sample & { time: string };

const NUMERIC_KEYS: (keyof Sample)[] = [
  "rx_bps",
  "tx_bps",
  "rx_pps",
  "tx_pps",
  "rx_util_percent",
  "tx_util_percent",
  "in_errors",
  "out_errors",
  "in_discards",
  "out_discards",
  "temp_c",
  "tx_power_dbm",
  "rx_power_dbm",
];

export function buildChartData(
  samples: Sample[],
  window: SmoothingWindow,
): ChartPoint[] {
  const base: ChartPoint[] = samples.map((s) => ({
    ...s,
    time: fmtTimeShort(s.sampled_at),
  }));
  if (window <= 1 || base.length === 0) return base;

  // Smooth each numeric column independently, keeping null gaps intact.
  for (const key of NUMERIC_KEYS) {
    const col = base.map((p) => p[key] as number | null);
    const smoothed = smoothSeries(col, window);
    smoothed.forEach((v, i) => {
      (base[i] as unknown as Record<string, number | null>)[key] = v;
    });
  }
  return base;
}

// ---------------------------------------------------------------------------
// <TelemetryChart> — one chart card with a rich CUR/MIN/AVG/MAX legend
// ---------------------------------------------------------------------------

export interface ChartSeries {
  /** Sample/ChartPoint field this line plots. */
  dataKey: keyof Sample;
  /** Legend / tooltip label. */
  label: string;
  /** Stroke colour (a CSS colour or theme var, e.g. `var(--chart-2)`). */
  color: string;
}

type AxisKind = "bps" | "pps" | "count" | "dbm" | "temp";

const AXIS_TICK: Record<AxisKind, (n: number) => string> = {
  bps: bpsTick,
  pps: ppsTick,
  count: (n) => `${Math.round(n)}`,
  dbm: (n) => n.toFixed(0),
  temp: (n) => n.toFixed(0),
};

const VALUE_FMT: Record<AxisKind, (n: number) => string> = {
  bps: fmtBps,
  pps: fmtPps,
  count: fmtCount,
  dbm: fmtDbm,
  temp: fmtTempC,
};

interface SeriesStats {
  cur: number | null;
  min: number | null;
  avg: number | null;
  max: number | null;
}

/** CUR (latest non-null) / MIN / AVG / MAX over the displayed window. */
function computeStats(points: ChartPoint[], key: keyof Sample): SeriesStats {
  let min = Infinity;
  let max = -Infinity;
  let sum = 0;
  let count = 0;
  let cur: number | null = null;
  for (const p of points) {
    const v = p[key] as number | null;
    if (v === null || !Number.isFinite(v)) continue;
    cur = v; // points are ascending → last seen is current
    if (v < min) min = v;
    if (v > max) max = v;
    sum += v;
    count += 1;
  }
  if (count === 0) return { cur: null, min: null, avg: null, max: null };
  return { cur, min, avg: sum / count, max };
}

export interface TelemetryChartProps {
  title: string;
  /** Smoothed + time-labelled points for the displayed window. */
  data: ChartPoint[];
  series: ChartSeries[];
  /** Y-axis / value scale; drives ticks, tooltip and legend formatting. */
  axis: AxisKind;
  /** Chart body height in px (default 220). */
  height?: number;
}

interface TooltipPayloadEntry {
  name?: string;
  value?: number | string;
  color?: string;
  dataKey?: string | number;
}

export function TelemetryChart({
  title,
  data,
  series,
  axis,
  height = 220,
}: TelemetryChartProps) {
  const fmtValue = VALUE_FMT[axis];
  const tick = AXIS_TICK[axis];

  const renderTooltip = (props: {
    active?: boolean;
    payload?: readonly unknown[];
  }) => {
    const { active } = props;
    const payload = (props.payload ?? []) as TooltipPayloadEntry[];
    if (!active || payload.length === 0) return null;
    // The first entry carries the row; pull its ISO timestamp for HH:MM:SS.
    const iso = (payload[0] as unknown as { payload?: ChartPoint }).payload
      ?.sampled_at;
    return (
      <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
        {iso && (
          <div className="mb-1 font-mono text-muted-foreground">
            {fmtTimeLong(iso)}
          </div>
        )}
        {payload.map((entry, i) => (
          <div key={i} className="flex items-center gap-2">
            <span
              className="inline-block size-2 rounded-full"
              style={{ backgroundColor: entry.color }}
            />
            <span className="text-muted-foreground">{entry.name}</span>
            <span className="ml-auto font-medium tabular-nums">
              {typeof entry.value === "number"
                ? fmtValue(entry.value)
                : String(entry.value ?? "—")}
            </span>
          </div>
        ))}
      </div>
    );
  };

  const hasData = data.length > 0;

  return (
    <div className="rounded-xl border bg-card p-4 text-card-foreground shadow-sm">
      <p className="mb-2 text-sm font-medium">{title}</p>

      {!hasData ? (
        <p className="flex h-[180px] items-center justify-center text-center text-sm text-muted-foreground">
          Collecting telemetry…
        </p>
      ) : (
        <>
          <ResponsiveContainer width="100%" height={height}>
            <LineChart
              data={data}
              margin={{ top: 4, right: 8, left: 0, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" className="opacity-30" />
              <XAxis
                dataKey="time"
                tick={{ fontSize: 11 }}
                minTickGap={28}
                stroke="var(--muted-foreground)"
              />
              <YAxis
                tick={{ fontSize: 11 }}
                tickFormatter={tick}
                width={52}
                stroke="var(--muted-foreground)"
                allowDecimals={axis !== "count"}
              />
              <Tooltip content={renderTooltip} />
              {series.map((s) => (
                <Line
                  key={s.dataKey as string}
                  type="monotone"
                  dataKey={s.dataKey as string}
                  name={s.label}
                  stroke={s.color}
                  dot={false}
                  strokeWidth={1.5}
                  isAnimationActive={false}
                  connectNulls
                />
              ))}
            </LineChart>
          </ResponsiveContainer>

          {/* Rich legend: colored dot + label + CUR/MIN/AVG/MAX */}
          <div className="mt-3 space-y-1.5">
            {series.map((s) => {
              const stats = computeStats(data, s.dataKey);
              const cell = (label: string, v: number | null) => (
                <span className="inline-flex items-baseline gap-1">
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    {label}
                  </span>
                  <span className="font-medium tabular-nums">
                    {v === null ? "—" : fmtValue(v)}
                  </span>
                </span>
              );
              return (
                <div
                  key={s.dataKey as string}
                  className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs"
                >
                  <span className="inline-flex items-center gap-1.5 font-medium">
                    <span
                      className="inline-block size-2 rounded-full"
                      style={{ backgroundColor: s.color }}
                    />
                    {s.label}
                  </span>
                  {cell("cur", stats.cur)}
                  {cell("min", stats.min)}
                  {cell("avg", stats.avg)}
                  {cell("max", stats.max)}
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Series colour tokens (IN/RX green, OUT/TX red; optics TX uses chart-3)
// ---------------------------------------------------------------------------

/** IN / RX — green. dark `--chart-2` is green; light needs an explicit green. */
export const COLOR_IN = "var(--color-in)";
/** OUT / TX — red. */
export const COLOR_OUT = "var(--color-out)";
/** Optics TX power — a distinct third colour. */
export const COLOR_TX_OPTIC = "var(--chart-3)";
