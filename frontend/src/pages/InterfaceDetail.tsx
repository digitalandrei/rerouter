/**
 * /devices/:deviceId/interfaces/:ifaceId — single-interface telemetry view.
 *
 * Header: back to the device, interface name + admin/oper badges, device-name
 * subtitle, Refresh button.
 *
 * Two info cards (Interface Details, Status & Counters) followed by up to six
 * last-hour recharts panels (Traffic, Packets, Errors, Discards, and — only
 * when a transceiver is present — Optics Temperature and Optical Power). The
 * optics cards render only if at least one sample carries the matching value.
 *
 * A shared 1m/3m/5m smoothing control (client-side moving average) feeds every
 * chart; metrics + the interface refetch every 30 s.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, RefreshCw } from "lucide-react";
import {
  api,
  type Device,
  type Interface,
  type Sample,
  ApiError,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  TelemetryChart,
  buildChartData,
  classifyInterface,
  statusVariant,
  fmtBps,
  fmtPps,
  fmtSpeed,
  fmtCount,
  fmtDbm,
  fmtTempC,
  COLOR_IN,
  COLOR_OUT,
  COLOR_TX_OPTIC,
  type SmoothingWindow,
} from "@/lib/telemetry";

// ---------------------------------------------------------------------------
// Small label/value primitive used inside the info cards
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
      <dd className="text-sm font-semibold">{children}</dd>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Smoothing segmented control
// ---------------------------------------------------------------------------

const SMOOTHING_OPTIONS: SmoothingWindow[] = [1, 3, 5];

function SmoothingControl({
  value,
  onChange,
}: {
  value: SmoothingWindow;
  onChange: (w: SmoothingWindow) => void;
}) {
  return (
    <div className="inline-flex items-center gap-2">
      <span className="text-xs text-muted-foreground">Smoothing</span>
      <div className="inline-flex rounded-md border p-0.5">
        {SMOOTHING_OPTIONS.map((w) => (
          <button
            key={w}
            type="button"
            onClick={() => onChange(w)}
            className={[
              "rounded px-2 py-0.5 text-xs font-medium transition-colors",
              value === w
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:text-foreground",
            ].join(" ")}
          >
            {w}m
          </button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function InterfaceDetail() {
  const { deviceId: deviceIdParam, ifaceId: ifaceIdParam } = useParams<{
    deviceId: string;
    ifaceId: string;
  }>();
  const deviceId = Number(deviceIdParam);
  const ifaceId = Number(ifaceIdParam);

  const [device, setDevice] = useState<Device | null>(null);
  const [iface, setIface] = useState<Interface | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const [loading, setLoading] = useState(true);
  const [metricsReady, setMetricsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [smoothing, setSmoothing] = useState<SmoothingWindow>(1);

  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadInterface = useCallback(() => {
    if (!Number.isFinite(ifaceId)) return;
    api.interfaces
      .get(ifaceId)
      .then(setIface)
      .catch((err) =>
        setError(err instanceof ApiError ? err.message : "Failed to load interface"),
      )
      .finally(() => setLoading(false));
  }, [ifaceId]);

  const loadMetrics = useCallback(() => {
    if (!Number.isFinite(ifaceId)) return;
    api.interfaces
      .metrics(ifaceId, 60)
      .then((data) => setSamples(data))
      .catch(() => setSamples([]))
      .finally(() => setMetricsReady(true));
  }, [ifaceId]);

  // Device (for the subtitle) — loaded once.
  useEffect(() => {
    if (!Number.isFinite(deviceId)) return;
    api.devices
      .get(deviceId)
      .then(setDevice)
      .catch(() => setDevice(null));
  }, [deviceId]);

  // Interface + metrics, then a shared 30 s auto-refresh.
  useEffect(() => {
    setLoading(true);
    setMetricsReady(false);
    setSamples([]);
    loadInterface();
    loadMetrics();

    const refresh = () => {
      loadInterface();
      loadMetrics();
    };
    timerRef.current = setInterval(refresh, 30_000);
    return () => {
      if (timerRef.current !== null) clearInterval(timerRef.current);
    };
  }, [loadInterface, loadMetrics]);

  async function refreshNow() {
    loadInterface();
    loadMetrics();
  }

  const chartData = useMemo(
    () => buildChartData(samples, smoothing),
    [samples, smoothing],
  );

  // Optics presence — only render those cards when a transceiver reports values.
  const hasTemp = useMemo(
    () => samples.some((s) => s.temp_c !== null && Number.isFinite(s.temp_c)),
    [samples],
  );
  const hasPower = useMemo(
    () =>
      samples.some(
        (s) =>
          (s.rx_power_dbm !== null && Number.isFinite(s.rx_power_dbm)) ||
          (s.tx_power_dbm !== null && Number.isFinite(s.tx_power_dbm)),
      ),
    [samples],
  );

  if (loading) {
    return <div className="text-sm text-muted-foreground">Loading interface…</div>;
  }

  if (error || !iface) {
    return (
      <div className="space-y-4">
        <Link
          to={`/devices/${deviceId}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="size-4" /> Back to device
        </Link>
        <p className="text-sm text-destructive">{error ?? "Interface not found."}</p>
      </div>
    );
  }

  const ifType = classifyInterface(iface.if_name, iface.if_descr);
  const m = iface.metrics;
  const validMetrics = m !== null && m.valid_sample;

  // Latest sample optics (current values for the Status & Counters card).
  const latest = samples.length > 0 ? samples[samples.length - 1] : null;

  return (
    <div className="space-y-6">
      {/* ---- Header ---- */}
      <div className="space-y-2">
        <Link
          to={`/devices/${deviceId}`}
          className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"
        >
          <ArrowLeft className="size-4" /> {device?.name ?? "Back to device"}
        </Link>
        <div className="flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight">{iface.if_name}</h1>
          <Badge variant={statusVariant(iface.oper_status)}>
            {iface.oper_status.toUpperCase()}
          </Badge>
          <Badge variant="outline">adm:{iface.admin_status}</Badge>

          <div className="ml-auto flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => void refreshNow()}>
              <RefreshCw className="size-4" />
              Refresh
            </Button>
          </div>
        </div>
        {device && (
          <p className="text-sm text-muted-foreground">{device.name}</p>
        )}
      </div>

      {/* ---- Info cards ---- */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Interface Details</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <Fact label="Name">{iface.if_name}</Fact>
              <Fact label="Type">
                <Badge variant="secondary">{ifType}</Badge>
              </Fact>
              <Fact label="Speed">{fmtSpeed(iface.if_speed_bps)}</Fact>
              <Fact label="Description">{iface.if_descr ?? "—"}</Fact>
              <Fact label="Alias">{iface.if_alias ?? "—"}</Fact>
              <Fact label="ifIndex">{iface.if_index}</Fact>
            </dl>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Status &amp; Counters</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-2 gap-4 sm:grid-cols-3">
              <Fact label="Admin State">
                <Badge variant={statusVariant(iface.admin_status)}>
                  {iface.admin_status.toUpperCase()}
                </Badge>
              </Fact>
              <Fact label="Oper State">
                <Badge variant={statusVariant(iface.oper_status)}>
                  {iface.oper_status.toUpperCase()}
                </Badge>
              </Fact>
              <Fact label="Utilization">
                {validMetrics
                  ? `Rx ${m!.rx_util_percent.toFixed(1)}% · Tx ${m!.tx_util_percent.toFixed(1)}%`
                  : "—"}
              </Fact>
              <Fact label="Rx (in)">
                {validMetrics ? (
                  <>
                    {fmtBps(m!.rx_bps)}
                    <span className="block text-xs font-normal text-muted-foreground">
                      {fmtPps(m!.rx_pps)}
                    </span>
                  </>
                ) : (
                  "—"
                )}
              </Fact>
              <Fact label="Tx (out)">
                {validMetrics ? (
                  <>
                    {fmtBps(m!.tx_bps)}
                    <span className="block text-xs font-normal text-muted-foreground">
                      {fmtPps(m!.tx_pps)}
                    </span>
                  </>
                ) : (
                  "—"
                )}
              </Fact>
              <Fact label="Errors">
                {validMetrics
                  ? `In ${fmtCount(m!.in_errors)} · Out ${fmtCount(m!.out_errors)}`
                  : "—"}
              </Fact>
              {latest && latest.temp_c !== null && (
                <Fact label="Temp">{fmtTempC(latest.temp_c)}</Fact>
              )}
              {latest && latest.tx_power_dbm !== null && (
                <Fact label="Tx Power">{fmtDbm(latest.tx_power_dbm)}</Fact>
              )}
              {latest && latest.rx_power_dbm !== null && (
                <Fact label="Rx Power">{fmtDbm(latest.rx_power_dbm)}</Fact>
              )}
            </dl>
          </CardContent>
        </Card>
      </div>

      {/* ---- Telemetry charts ---- */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-lg font-semibold">Telemetry — last hour</h2>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span className="inline-block size-1.5 rounded-full bg-green-500" />
            live · refreshes every 30 s
          </span>
          <SmoothingControl value={smoothing} onChange={setSmoothing} />
        </div>
      </div>

      {!metricsReady ? (
        <p className="text-sm text-muted-foreground">Loading metrics…</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-2">
          <TelemetryChart
            title="Traffic (bps)"
            data={chartData}
            axis="bps"
            series={[
              { dataKey: "rx_bps", label: "IN", color: COLOR_IN },
              { dataKey: "tx_bps", label: "OUT", color: COLOR_OUT },
            ]}
          />
          <TelemetryChart
            title="Packets (pps)"
            data={chartData}
            axis="pps"
            series={[
              { dataKey: "rx_pps", label: "IN", color: COLOR_IN },
              { dataKey: "tx_pps", label: "OUT", color: COLOR_OUT },
            ]}
          />
          <TelemetryChart
            title="Errors (pps)"
            data={chartData}
            axis="count"
            series={[
              { dataKey: "in_errors", label: "IN", color: COLOR_IN },
              { dataKey: "out_errors", label: "OUT", color: COLOR_OUT },
            ]}
          />
          <TelemetryChart
            title="Discards (pps)"
            data={chartData}
            axis="count"
            series={[
              { dataKey: "in_discards", label: "IN", color: COLOR_IN },
              { dataKey: "out_discards", label: "OUT", color: COLOR_OUT },
            ]}
          />
          {hasTemp && (
            <TelemetryChart
              title="Optics Temperature (°C)"
              data={chartData}
              axis="temp"
              series={[{ dataKey: "temp_c", label: "Temp", color: COLOR_OUT }]}
            />
          )}
          {hasPower && (
            <TelemetryChart
              title="Optical Power (dBm)"
              data={chartData}
              axis="dbm"
              series={[
                { dataKey: "rx_power_dbm", label: "RX", color: COLOR_IN },
                { dataKey: "tx_power_dbm", label: "TX", color: COLOR_TX_OPTIC },
              ]}
            />
          )}
        </div>
      )}
    </div>
  );
}
