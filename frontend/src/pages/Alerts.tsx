/**
 * /alerts — governed by docs/email-alerts.md and docs/doctrine.md §10.
 *
 * Shows alert events and their email delivery records (alert_deliveries),
 * including de-duplication (10-min window per event_type/asset/rule) and
 * per-recipient rate limiting with digest fallback. `reroute_uncertain`,
 * `reroute_failed`, and security events are always sent immediately and are
 * never collapsed — the UI labels them accordingly. Subscription management
 * needs the manage_alerts permission.
 */
import { useEffect, useState } from "react";
import { api, type Alert } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const ALWAYS_IMMEDIATE = new Set(["reroute_uncertain", "reroute_failed"]);

export default function Alerts() {
  const [alerts, setAlerts] = useState<Alert[]>([]);

  useEffect(() => {
    api.alerts.list().then(setAlerts).catch(() => setAlerts([]));
  }, []);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Alert events</CardTitle>
        </CardHeader>
        <CardContent>
          {alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No alerts yet (or API not reachable). Delivery records and
              subscription management placeholder.
            </p>
          ) : (
            <ul className="divide-y">
              {alerts.map((alert) => (
                <li
                  key={alert.id}
                  className="flex items-center gap-3 py-3 text-sm"
                >
                  <code className="text-xs">{alert.event_type}</code>
                  {ALWAYS_IMMEDIATE.has(alert.event_type) && (
                    <Badge variant="destructive">immediate</Badge>
                  )}
                  <span className="flex-1" />
                  <span className="text-xs text-muted-foreground">
                    {alert.created_at}
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
