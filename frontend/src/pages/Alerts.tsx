/**
 * /alerts — governed by docs/email-alerts.md and docs/doctrine.md §8, §10.
 *
 * Alert events from the last 7 days, paginated. Each row shows severity, the
 * rule that fired and its device/interface (by NAME, falling back to #id), the
 * metric value vs threshold from payload, the timestamp, and the would-run
 * action plan from payload when present (observe mode).
 */
import { useEffect, useState } from "react";
import { api, type AlertPage } from "@/lib/api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/status-badge";

const PAGE_SIZE = 50;
const DAYS = 7;

function PayloadDetails({ payload }: { payload: Record<string, unknown> }) {
  const metric = typeof payload.metric === "string" ? payload.metric : null;
  const value = typeof payload.value === "number" ? payload.value : null;
  const threshold =
    typeof payload.threshold_value === "number" ? payload.threshold_value : null;
  const operator =
    typeof payload.operator === "string" ? payload.operator : null;
  const wouldRunActions = Array.isArray(payload.would_run_actions)
    ? (payload.would_run_actions as Array<Record<string, unknown>>)
    : [];

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
      {wouldRunActions.length > 0 && (
        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
          <span className="font-medium text-amber-700 dark:text-amber-400">Would run: </span>
          {wouldRunActions.map((a, i) => {
            const t = typeof a.template_name === "string" ? a.template_name : "action";
            const d = typeof a.device_name === "string" ? a.device_name : "device";
            return (
              <code key={i}>
                {t} on {d}
              </code>
            );
          })}
        </div>
      )}
    </div>
  );
}

/** Friendly label for an alert's rule/device/interface, name first, #id fallback. */
function label(name: string | null, id: number | null, prefix: string): string | null {
  if (name) return name;
  if (id !== null) return `${prefix} #${id}`;
  return null;
}

export default function Alerts() {
  const [page, setPage] = useState<AlertPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    api.alerts
      .list({ limit: PAGE_SIZE, offset, days: DAYS })
      .then(setPage)
      .catch(() => setPage(null))
      .finally(() => setLoading(false));
  }, [offset]);

  const alerts = page?.rows ?? [];
  const total = page?.total ?? 0;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold tracking-tight">Alerts</h1>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Alert events</CardTitle>
          <p className="text-sm text-muted-foreground">
            Last {DAYS} days{total > 0 ? ` · ${total} total` : ""}
          </p>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No alerts in the last {DAYS} days.</p>
          ) : (
            <>
              <ul className="divide-y">
                {alerts.map((alert) => {
                  const rule = label(alert.rule_name, alert.rule_id, "rule");
                  const dev = label(alert.device_name, alert.device_id, "device");
                  const iface = label(alert.interface_name, alert.interface_id, "iface");
                  return (
                    <li key={alert.id} className="py-3">
                      <div className="flex flex-wrap items-center gap-2 text-sm">
                        <SeverityBadge severity={alert.severity} />
                        <code className="text-xs">{alert.event_type}</code>
                        {rule && <span className="font-medium">{rule}</span>}
                        {(dev || iface) && (
                          <span className="text-xs text-muted-foreground">
                            {dev}
                            {dev && iface ? " · " : ""}
                            {iface}
                          </span>
                        )}
                        <span className="flex-1" />
                        <span className="text-xs text-muted-foreground">
                          {new Date(alert.created_at).toLocaleString()}
                        </span>
                      </div>
                      <PayloadDetails payload={alert.payload} />
                    </li>
                  );
                })}
              </ul>
              <div className="mt-4 flex items-center justify-between text-sm text-muted-foreground">
                <span>
                  {from}–{to} of {total}
                </span>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={offset === 0}
                    onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={to >= total}
                    onClick={() => setOffset(offset + PAGE_SIZE)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
