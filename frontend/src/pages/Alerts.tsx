/**
 * /alerts — governed by docs/email-alerts.md and docs/doctrine.md §8, §10.
 *
 * Shows alert events with: severity, device/interface context, the metric
 * value vs threshold (above/below) from payload, created_at timestamp, and
 * the would-run action plan from payload when present (observe mode).
 */
import { useEffect, useState } from "react";
import { api, type Alert } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

function severityVariant(
  severity: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (severity) {
    case "critical":
      return "destructive";
    case "warning":
      return "secondary";
    default:
      return "outline";
  }
}

function PayloadDetails({ payload }: { payload: Record<string, unknown> }) {
  const metric = typeof payload.metric === "string" ? payload.metric : null;
  const value =
    typeof payload.value === "number" ? payload.value : null;
  const threshold =
    typeof payload.threshold_value === "number"
      ? payload.threshold_value
      : null;
  const operator =
    typeof payload.operator === "string" ? payload.operator : null;
  const wouldRun =
    typeof payload.would_run_action === "string"
      ? payload.would_run_action
      : null;

  const hasMeasurement = metric !== null && value !== null;

  return (
    <div className="mt-1 space-y-0.5 text-xs text-muted-foreground">
      {hasMeasurement && (
        <div>
          <code>{metric}</code> ={" "}
          <strong className="text-foreground">{value}</strong>
          {threshold !== null && operator !== null && (
            <span>
              {" "}
              (threshold {operator} {threshold})
            </span>
          )}
        </div>
      )}
      {wouldRun && (
        <div>
          <span className="font-medium text-yellow-700">Would run: </span>
          <code>{wouldRun}</code>
        </div>
      )}
    </div>
  );
}

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.alerts
      .list()
      .then(setAlerts)
      .catch(() => setAlerts([]))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Alert events</CardTitle>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No alerts yet.</p>
          ) : (
            <ul className="divide-y">
              {alerts.map((alert) => (
                <li key={alert.id} className="py-3">
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge variant={severityVariant(alert.severity)}>
                      {alert.severity}
                    </Badge>
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
                    {alert.rule_id !== null && (
                      <span className="text-xs text-muted-foreground">
                        rule #{alert.rule_id}
                      </span>
                    )}
                    <span className="flex-1" />
                    <span className="text-xs text-muted-foreground">
                      {new Date(alert.created_at).toLocaleString()}
                    </span>
                  </div>
                  <PayloadDetails payload={alert.payload} />
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
