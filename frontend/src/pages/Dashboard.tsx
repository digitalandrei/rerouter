/**
 * /dashboard — governed by docs/doctrine.md §5.3 (UI principles) and
 * docs/operations-runbook.md.
 *
 * Shows: operating mode banner (observe = read-only/alert-only, the shipped
 * default), device reachability, interfaces monitored, active rule matches,
 * alerts in the last 24 h, telemetry stale count, a recent-alerts list, and an
 * "Active matches" section listing firing rules with a manual "Apply mitigation"
 * button for rules that have manual_apply_enabled.
 */
import { useEffect, useState, useCallback } from "react";
import { api, type SystemStatus, type Alert, type Rule, type SystemSettings } from "@/lib/api";
import { eventTypeLabel } from "@/lib/labels";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { SeverityBadge } from "@/components/status-badge";
import { ApplyMitigationDialog } from "@/components/apply-mitigation-dialog";
import { useAuth } from "@/lib/auth";

export default function Dashboard() {
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [firingRules, setFiringRules] = useState<Rule[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  const loadData = useCallback(() => {
    api
      .status()
      .then(setStatus)
      .catch(() => setStatus(null))
      .finally(() => setLoadingStatus(false));

    api.alerts
      .list({ limit: 10 })
      .then((page) => setAlerts(page.rows))
      .catch(() => setAlerts([]))
      .finally(() => setLoadingAlerts(false));

    api.rules
      .list()
      .then((rules) => setFiringRules(rules.filter((r) => r.current_state === "firing")))
      .catch(() => setFiringRules([]));

    api.settings
      .get()
      .then(setSettings)
      .catch(() => {});
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  return (
    <div className="space-y-6">
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

      {/* Active matches — firing rules; apply mitigation for eligible ones */}
      {firingRules.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg text-destructive">
              Active matches ({firingRules.length})
            </CardTitle>
            <CardDescription>
              Rules currently in the firing state. Apply mitigation to manually
              run a rule's configured actions (where enabled).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              {firingRules.map((rule) => {
                const target =
                  rule.interface_name ?? (rule.interface_id != null ? `iface #${rule.interface_id}` : null);
                const device = rule.device_name ?? (rule.device_id != null ? `device #${rule.device_id}` : null);
                const canShowApply = canApply && rule.manual_apply_enabled;
                return (
                  <li key={rule.id} className="flex flex-wrap items-center gap-2 py-3 text-sm">
                    <SeverityBadge severity={rule.severity} />
                    <span className="font-medium">{rule.name}</span>
                    {(target || device) && (
                      <span className="text-xs text-muted-foreground">
                        {target}
                        {target && device ? " · " : ""}
                        {device}
                      </span>
                    )}
                    <span className="flex-1" />
                    {canShowApply && (
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={() => setApplyRule(rule)}
                      >
                        Apply mitigation
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>
      )}

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
                  <span className="text-xs font-medium">{eventTypeLabel(alert.event_type)}</span>
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

      {applyRule && (
        <ApplyMitigationDialog
          rule={applyRule}
          operatingMode={settings?.operating_mode ?? "observe"}
          onClose={() => setApplyRule(null)}
          onApplied={() => {
            setApplyRule(null);
            loadData();
          }}
        />
      )}
    </div>
  );
}
