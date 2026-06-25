/**
 * /alerts — governed by docs/email-alerts.md and docs/doctrine.md §8, §10.
 *
 * Alert events from the last 7 days, paginated. Each row shows severity, the
 * rule that fired and its device/interface (by NAME, falling back to #id), the
 * metric value vs threshold from payload, the timestamp, and the would-run
 * action plan from payload when present (observe mode).
 *
 * For rule_fired alerts where the rule is still firing AND manual_apply_enabled,
 * an "Apply mitigation" button opens ApplyMitigationDialog.
 */
import { useEffect, useState, useCallback } from "react";
import { api, type AlertPage, type Rule, type SystemSettings } from "@/lib/api";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/status-badge";
import { ApplyMitigationDialog } from "@/components/apply-mitigation-dialog";
import { useAuth } from "@/lib/auth";

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
            const dn = typeof a.template_display_name === "string" ? a.template_display_name : null;
            const tn = typeof a.template_name === "string" ? a.template_name : "action";
            const displayName = dn || tn;
            const d = typeof a.device_name === "string" ? a.device_name : "device";
            // auto_target may be an object {resolved_cidr, low_confidence, note}
            // or a "skipped" string when the host couldn't be resolved.
            const at = a.auto_target;
            const atObj =
              at !== null &&
              at !== undefined &&
              typeof at === "object" &&
              !Array.isArray(at)
                ? (at as { resolved_cidr?: string; low_confidence?: boolean; note?: string })
                : null;
            const atSkipped = typeof at === "string" ? at : null;
            return (
              <span key={i} className="inline-flex flex-wrap items-center gap-1">
                <code>{displayName}</code>
                {dn && dn !== tn && (
                  <span className="text-muted-foreground/60">({tn})</span>
                )}
                <span className="text-muted-foreground">on {d}</span>
                {atObj?.resolved_cidr && (
                  <span className="inline-flex items-center gap-1">
                    <span className="rounded bg-amber-100 px-1 font-mono text-[10px] text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
                      {atObj.resolved_cidr}
                    </span>
                    {atObj.low_confidence && (
                      <span
                        className="rounded bg-red-100 px-1 text-[10px] text-red-700 dark:bg-red-900/40 dark:text-red-400"
                        title={atObj.note ?? "Low flow-sampling confidence — auto execution blocked; manual apply still works"}
                      >
                        low sampling confidence
                      </span>
                    )}
                  </span>
                )}
                {atSkipped && (
                  <span
                    className="rounded bg-muted px-1 text-[10px] text-muted-foreground"
                    title="Could not resolve target host from flows"
                  >
                    skipped: {atSkipped}
                  </span>
                )}
              </span>
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
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");

  const [page, setPage] = useState<AlertPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [rulesMap, setRulesMap] = useState<Map<number, Rule>>(new Map());
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  const loadAlerts = useCallback(() => {
    setLoading(true);
    api.alerts
      .list({ limit: PAGE_SIZE, offset, days: DAYS })
      .then(setPage)
      .catch(() => setPage(null))
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  // Load rules once (for joining with alert.rule_id to get firing state +
  // manual_apply_enabled). Refresh after apply so button state is up to date.
  const loadRules = useCallback(() => {
    api.rules
      .list()
      .then((rules) => {
        const m = new Map<number, Rule>();
        for (const r of rules) m.set(r.id, r);
        setRulesMap(m);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    loadRules();
    api.settings
      .get()
      .then(setSettings)
      .catch(() => {});
  }, [loadRules]);

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

                  // Show "Apply mitigation" only for rule_fired alerts where the rule
                  // is still firing AND manual_apply_enabled is on AND the operator
                  // has the trigger_manual_reroute permission.
                  const matchedRule =
                    alert.event_type === "rule_fired" && alert.rule_id != null
                      ? (rulesMap.get(alert.rule_id) ?? null)
                      : null;
                  const canShowApply =
                    canApply &&
                    matchedRule !== null &&
                    matchedRule.manual_apply_enabled &&
                    matchedRule.current_state === "firing";

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
                        {canShowApply && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs"
                            onClick={() => setApplyRule(matchedRule)}
                          >
                            Apply mitigation
                          </Button>
                        )}
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

      {applyRule && (
        <ApplyMitigationDialog
          rule={applyRule}
          operatingMode={settings?.operating_mode ?? "observe"}
          onClose={() => setApplyRule(null)}
          onApplied={() => {
            // Refresh rules (state may have changed) and alerts.
            loadRules();
            loadAlerts();
          }}
        />
      )}
    </div>
  );
}
