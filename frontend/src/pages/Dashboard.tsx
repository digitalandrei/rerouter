/**
 * /dashboard — governed by docs/doctrine.md §5.3 (UI principles) and
 * docs/operations-runbook.md.
 *
 * Shows: operating mode banner (observe = read-only/alert-only, the shipped
 * default), device reachability, interfaces monitored, active rule matches,
 * alerts in the last 24 h, telemetry stale count, and a recent-alerts list.
 */
import { useEffect, useState } from "react";
import { api, type SystemStatus, type Alert } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SeverityBadge } from "@/components/status-badge";

function ObserveBanner({ mode }: { mode: string | undefined }) {
  if (mode === "enforce") return null;
  return (
    <div className="flex items-center gap-3 rounded-md border border-yellow-400 bg-yellow-50 px-4 py-3 text-sm font-semibold text-yellow-800">
      <span className="text-base">&#9888;</span>
      <span>
        OBSERVE MODE — read-only / alert-only. No reroutes will execute
        (automatic or manual). Alerts show the actions that WOULD run.
      </span>
    </div>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [loadingAlerts, setLoadingAlerts] = useState(true);

  useEffect(() => {
    api
      .status()
      .then(setStatus)
      .catch(() => setStatus(null))
      .finally(() => setLoadingStatus(false));

    api.alerts
      .list()
      .then((all) => setAlerts(all.slice(0, 10)))
      .catch(() => setAlerts([]))
      .finally(() => setLoadingAlerts(false));
  }, []);

  return (
    <div className="space-y-6">
      <ObserveBanner mode={status?.operating_mode} />

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        {!loadingStatus && status && (
          <Badge
            variant={
              status.operating_mode === "enforce" ? "destructive" : "outline"
            }
          >
            {status.operating_mode === "enforce" ? "ENFORCE" : "observe"}
          </Badge>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Devices reachable</CardDescription>
            <CardTitle className="text-2xl">
              {loadingStatus ? (
                <span className="text-muted-foreground text-base">
                  Loading…
                </span>
              ) : (
                <>
                  {status?.devices_reachable ?? "—"}
                  <span className="ml-1 text-sm font-normal text-muted-foreground">
                    / {status?.devices_total ?? "—"} total
                  </span>
                </>
              )}
            </CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Interfaces monitored</CardDescription>
            <CardTitle className="text-2xl">
              {loadingStatus ? (
                <span className="text-muted-foreground text-base">
                  Loading…
                </span>
              ) : (
                status?.interfaces_monitored ?? "—"
              )}
            </CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active rule matches</CardDescription>
            <CardTitle className="text-2xl">
              {loadingStatus ? (
                <span className="text-muted-foreground text-base">
                  Loading…
                </span>
              ) : (
                <span
                  className={
                    (status?.active_rule_matches ?? 0) > 0
                      ? "text-destructive"
                      : ""
                  }
                >
                  {status?.active_rule_matches ?? "—"}
                </span>
              )}
            </CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Alerts (24 h)</CardDescription>
            <CardTitle className="text-2xl">
              {loadingStatus ? (
                <span className="text-muted-foreground text-base">
                  Loading…
                </span>
              ) : (
                status?.alerts_24h ?? "—"
              )}
            </CardTitle>
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Telemetry stale</CardDescription>
            <CardTitle className="text-2xl">
              {loadingStatus ? (
                <span className="text-muted-foreground text-base">
                  Loading…
                </span>
              ) : (
                <span
                  className={
                    (status?.telemetry_stale_count ?? 0) > 0
                      ? "text-destructive"
                      : ""
                  }
                >
                  {status?.telemetry_stale_count ?? "—"}
                </span>
              )}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recent alerts</CardTitle>
          <CardDescription>
            Latest 10 alert events across all devices and interfaces.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingAlerts ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No alerts yet.</p>
          ) : (
            <ul className="divide-y">
              {alerts.map((alert) => (
                <li
                  key={alert.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <SeverityBadge severity={alert.severity} />
                  <code className="text-xs">{alert.event_type}</code>
                  {alert.device_id !== null && (
                    <span className="text-xs text-muted-foreground">
                      device #{alert.device_id}
                    </span>
                  )}
                  {alert.interface_id !== null && (
                    <span className="text-xs text-muted-foreground">
                      iface #{alert.interface_id}
                    </span>
                  )}
                  <span className="flex-1" />
                  <span className="text-xs text-muted-foreground">
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
