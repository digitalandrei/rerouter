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
import { api, type SystemStatus, type Alert, type Rule, type SystemSettings, type RunSummary } from "@/lib/api";
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
import { SeverityBadge, ToneBadge } from "@/components/status-badge";
import { ApplyMitigationDialog } from "@/components/apply-mitigation-dialog";
import { useAuth } from "@/lib/auth";
import { Link } from "react-router-dom";
import { presentMitigationRun, runSourceName } from "@/lib/mitigation-run-state";

export default function Dashboard() {
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");

  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [firingRules, setFiringRules] = useState<Rule[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [activeRuns, setActiveRuns] = useState<RunSummary[]>([]);
  const [recentRuns, setRecentRuns] = useState<RunSummary[]>([]);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [loadingAlerts, setLoadingAlerts] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [applyRule, setApplyRule] = useState<Rule | null>(null);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const loadData = useCallback((manual = false) => {
    if (manual) setRefreshing(true);
    const tasks: Promise<unknown>[] = [];
    tasks.push(api
      .status()
      .then(setStatus)
      .then(() => setErrors((value) => { const next = { ...value }; delete next.status; return next; }))
      .catch(() => setErrors((value) => ({ ...value, status: "System status could not be refreshed." })))
      .finally(() => setLoadingStatus(false)));

    tasks.push(api.alerts
      .list({ limit: 10, exclude_bundled_action_lifecycle: true })
      .then((page) => setAlerts(page.rows))
      .then(() => setErrors((value) => { const next = { ...value }; delete next.alerts; return next; }))
      .catch(() => setErrors((value) => ({ ...value, alerts: "Recent alerts could not be refreshed." })))
      .finally(() => setLoadingAlerts(false)));

    tasks.push(api.rules
      .list()
      .then((rules) => setFiringRules(rules.filter((r) => r.current_state === "firing" || r.current_state === "recovered_awaiting_revert")))
      .then(() => setErrors((value) => { const next = { ...value }; delete next.rules; return next; }))
      .catch(() => setErrors((value) => ({ ...value, rules: "Active rule matches could not be refreshed." }))));

    tasks.push(api.settings
      .get()
      .then(setSettings)
      .then(() => setErrors((value) => { const next = { ...value }; delete next.settings; return next; }))
      .catch(() => setErrors((value) => ({ ...value, settings: "Operating mode could not be refreshed." }))));

    tasks.push(api.bundles.list({ lifecycle: "active", page: 1, per_page: 20 }).then((response) => {
      setActiveRuns(Array.isArray(response) ? response : response.items);
      setErrors((value) => { const next = { ...value }; delete next.runs; return next; });
    }).catch(() => setErrors((value) => ({ ...value, runs: "Active mitigation runs could not be refreshed." }))));
    tasks.push(api.bundles.list({ lifecycle: "all", logical_only: true, page: 1, per_page: 10 }).then((response) => {
      setRecentRuns(Array.isArray(response) ? response : response.items);
      setErrors((value) => { const next = { ...value }; delete next.activity; return next; });
    }).catch(() => setErrors((value) => ({ ...value, activity: "Recent mitigation activity could not be refreshed." }))));
    return Promise.allSettled(tasks).then(() => undefined).finally(() => { if (manual) setRefreshing(false); });
  }, []);

  useEffect(() => {
    void loadData();
    const timer = setInterval(() => void loadData(), 30_000);
    return () => clearInterval(timer);
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

      {Object.keys(errors).length > 0 && <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"><span>{Object.values(errors).join(" ")} Existing values may be stale.</span><Button size="sm" variant="outline" loading={refreshing} loadingLabel="Retrying dashboard…" onClick={() => void loadData(true)}>Try again</Button></div>}

      {(activeRuns.length > 0 || errors.runs) && <Card>
        <CardHeader><CardTitle className="text-lg">Active mitigations</CardTitle><CardDescription>Router changes that remain active or need operator review.</CardDescription></CardHeader>
        <CardContent className="space-y-3">
          {errors.runs && <p className="text-sm text-destructive">Active runs are unavailable; this is not confirmation that no changes remain.</p>}
          {activeRuns.map((run) => { const state = presentMitigationRun(run); const devices = run.affected_devices?.map((device) => device.name ?? device.device_name ?? `Device ${device.id ?? device.device_id}`).join(", "); return <div key={run.id} className="flex flex-wrap items-center gap-2 text-sm"><strong>{runSourceName(run)}</strong><ToneBadge tone={state.tone}>{state.label}</ToneBadge><span className="text-xs text-muted-foreground">{state.detail}</span>{devices && <span className="text-xs text-muted-foreground">{devices}</span>}<span className="text-xs text-muted-foreground">{run.triggered_by ?? "system"} · {run.started_at ? new Date(run.started_at).toLocaleString() : "not started"}</span><span className="text-xs text-muted-foreground">{run.recovery_deadline ? `Revert scheduled for ${new Date(run.recovery_deadline).toLocaleString()} · pending until automatic recovery is allowed` : "Until manually reverted"}</span><Button asChild size="sm" variant="outline" className="ml-auto"><Link to={`/mitigations?tab=active&run=${run.id}`}>{run.revert?.available ? "Review & revert" : "Review run"}</Link></Button></div>; })}
        </CardContent>
      </Card>}

      <Card><CardHeader><CardTitle className="text-lg">Recent mitigation activity</CardTitle><CardDescription>One row per mitigation run. Recovery work is shown with its original run.</CardDescription></CardHeader><CardContent className="space-y-3">{errors.activity && recentRuns.length === 0 ? <p role="alert" className="text-sm text-destructive">Recent mitigation activity is unavailable. This does not confirm that no runs exist.</p> : recentRuns.length === 0 ? <p className="text-sm text-muted-foreground">No mitigation runs yet.</p> : <>{errors.activity && <p role="alert" className="text-sm text-amber-700 dark:text-amber-300">Refresh failed. Showing the most recently loaded mitigation activity.</p>}{recentRuns.map((run) => { const state = presentMitigationRun(run); const devices = run.affected_devices?.map((device) => device.name ?? device.device_name ?? `Device ${device.id ?? device.device_id}`).join(", "); return <div key={run.id} className="flex flex-wrap items-center gap-2 text-sm"><strong>{runSourceName(run)}</strong><ToneBadge tone={state.tone}>{state.label}</ToneBadge>{devices && <span className="text-xs text-muted-foreground">{devices}</span>}<span className="ml-auto text-xs text-muted-foreground">{run.triggered_by ?? "system"} · {run.started_at ? new Date(run.started_at).toLocaleString() : "not started"}</span><Button asChild size="sm" variant="outline"><Link to={`/mitigations?tab=active&run=${run.id}`}>Review run</Link></Button></div>; })}</>}</CardContent></Card>

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
            <CardDescription>Alert events (24 h)</CardDescription>
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
      {(firingRules.length > 0 || errors.rules) && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg text-destructive">
              Active and held matches ({firingRules.length})
            </CardTitle>
            <CardDescription>
              Rules currently firing or recovered while router changes still await revert.
              Manual apply is available only for firing rules where enabled.
            </CardDescription>
          </CardHeader>
          <CardContent>
            {errors.rules && <p className="text-sm text-destructive">Active matches are unavailable; this is not confirmation that no rules are firing.</p>}
            <ul className="divide-y">
              {firingRules.map((rule) => {
                const target =
                  rule.interface_name ?? (rule.interface_id != null ? `iface #${rule.interface_id}` : null);
                const device = rule.device_name ?? (rule.device_id != null ? `device #${rule.device_id}` : null);
                const canShowApply = canApply && rule.manual_apply_enabled && rule.current_state === "firing";
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
            Latest alert events. Bundled action progress appears in mitigation activity.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {loadingAlerts ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : errors.alerts && alerts.length === 0 ? (
            <p role="alert" className="text-sm text-destructive">Recent alert events are unavailable. This does not confirm that no alerts occurred.</p>
          ) : alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">No other alert events in this period.</p>
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
                      <Link to={`/devices/${alert.device_id}`} className="hover:underline">{alert.device_name ?? `device #${alert.device_id}`}</Link>
                    </span>
                  )}
                  {alert.interface_id !== null && alert.device_id !== null && (
                    <span className="text-xs text-muted-foreground">
                      <Link to={`/devices/${alert.device_id}/interfaces/${alert.interface_id}`} className="hover:underline">{alert.interface_name ?? `interface #${alert.interface_id}`}</Link>
                    </span>
                  )}
                  {alert.rule_id !== null && <span className="text-xs text-muted-foreground">{alert.rule_name ?? `rule #${alert.rule_id}`}</span>}
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
          operatingMode={settings?.operating_mode ?? "unknown"}
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
