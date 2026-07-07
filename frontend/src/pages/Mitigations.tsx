/**
 * /mitigations — unified tabbed page (Detections · Alerts · History).
 *
 * Governed by docs/reroute-engine.md, docs/doctrine.md §8, docs/email-alerts.md.
 *
 * Tabs:
 *  1. Detections — rules currently firing, with Mitigate button for eligible
 *     rules (manual_apply_enabled) and detected victim host from most-recent
 *     rule_fired alert payload for flow rules with auto_target.
 *  2. Alerts — the alert event feed (reused from the former Alerts page).
 *  3. History — the reroute history (reused from Reroutes page content).
 *
 * Badge on nav item = active_rule_matches from api.status().
 * The "Manual mitigation" link lives on this page header.
 */
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import {
  api,
  type Alert,
  type AlertPage,
  type Lock,
  type Reroute,
  type RerouteDetail,
  type Rule,
  type SystemSettings,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { PromptDialog } from "@/components/prompt-dialog";
import { ApplyMitigationDialog } from "@/components/apply-mitigation-dialog";
import { SeverityBadge, StateBadge, toneClass } from "@/components/status-badge";
import { humanizeToken, eventTypeLabel, templateLabelFrom, triggerTypeLabel } from "@/lib/labels";
import { useAuth } from "@/lib/auth";
import { ShieldAlert, Shuffle } from "lucide-react";

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

const ALERTS_PAGE_SIZE = 50;
const ALERTS_DAYS = 7;

// ---------------------------------------------------------------------------
// Detections tab
// ---------------------------------------------------------------------------

/**
 * Finds the most-recent rule_fired alert for a rule (from the given alert list)
 * and extracts auto_target resolved CIDRs from payload.would_run_actions[].auto_target.
 * Returns the first resolved_cidr found, or null.
 */
function extractDetectedCidr(alerts: Alert[], ruleId: number): string | null {
  const fired = alerts.filter(
    (a) => a.event_type === "rule_fired" && a.rule_id === ruleId,
  );
  if (fired.length === 0) return null;
  // Most recent first (alerts come newest-first from backend)
  const newest = fired[0];
  const actions = Array.isArray(newest.payload.would_run_actions)
    ? (newest.payload.would_run_actions as Array<Record<string, unknown>>)
    : [];
  for (const action of actions) {
    const at = action.auto_target;
    if (at && typeof at === "object" && !Array.isArray(at)) {
      const cidr = (at as { resolved_cidr?: string }).resolved_cidr;
      if (cidr) return cidr;
    }
  }
  return null;
}

function DetectionsTab({
  firingRules,
  alerts,
  settings,
  onRefresh,
}: {
  firingRules: Rule[];
  alerts: Alert[];
  settings: SystemSettings | null;
  onRefresh: () => void;
}) {
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  if (firingRules.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 text-center">
          <p className="text-sm text-muted-foreground">
            No rules are currently firing. The system is operating normally.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <>
      <div className="space-y-3">
        {firingRules.map((rule) => {
          const isFlowRule = Boolean(rule.flow_direction);
          const hasAutoTargetAction = (rule.actions ?? []).some(
            (a) => a.auto_target === "flow_dst_host",
          );
          const detectedCidr =
            isFlowRule && hasAutoTargetAction
              ? extractDetectedCidr(alerts, rule.id)
              : null;

          const target =
            rule.interface_name ||
            (rule.interface_id ? `interface #${rule.interface_id}` : null);
          const device = rule.device_name;

          return (
            <Card key={rule.id} className="border-red-300 dark:border-red-800/60">
              <CardContent className="py-4">
                <div className="flex flex-wrap items-start gap-3">
                  {/* Left: rule info */}
                  <div className="flex-1 space-y-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-semibold">{rule.name}</span>
                      <SeverityBadge severity={rule.severity} />
                      <Badge
                        variant="outline"
                        className={`text-[10px] ${toneClass("bad")}`}
                      >
                        firing
                      </Badge>
                    </div>
                    {(target || device) && (
                      <p className="text-xs text-muted-foreground font-mono">
                        {target}
                        {target && device ? " · " : ""}
                        {device}
                      </p>
                    )}
                    {rule.current_value != null && (
                      <p className="text-xs text-muted-foreground">
                        <span className="font-medium text-foreground">
                          {rule.metric}
                        </span>{" "}
                        = {rule.current_value.toLocaleString()} (threshold{" "}
                        {rule.operator} {rule.threshold_value.toLocaleString()})
                      </p>
                    )}
                    {detectedCidr && (
                      <p className="text-xs">
                        <span className="text-muted-foreground">Detected: </span>
                        <span className="rounded bg-amber-100 px-1 font-mono text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
                          {detectedCidr}
                        </span>
                      </p>
                    )}
                  </div>

                  {/* Right: apply button */}
                  <div className="flex shrink-0 items-center">
                    {canApply && rule.manual_apply_enabled ? (
                      <Button
                        size="sm"
                        variant="destructive"
                        className="h-8"
                        onClick={() => setApplyRule(rule)}
                      >
                        Mitigate
                      </Button>
                    ) : canApply ? (
                      <span className="text-xs text-muted-foreground italic">
                        manual apply not enabled
                      </span>
                    ) : null}
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {applyRule && (
        <ApplyMitigationDialog
          rule={applyRule}
          operatingMode={settings?.operating_mode ?? "observe"}
          onClose={() => setApplyRule(null)}
          onApplied={() => {
            setApplyRule(null);
            onRefresh();
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Alerts tab (extracted from former Alerts.tsx)
// ---------------------------------------------------------------------------

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
            const displayName = dn || humanizeToken(tn);
            const d = typeof a.device_name === "string" ? a.device_name : "device";
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
                <span className="font-medium">{displayName}</span>
                {dn && dn !== tn && (
                  <span className="text-muted-foreground/60 text-[10px]">({tn})</span>
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

function labelStr(name: string | null, id: number | null, prefix: string): string | null {
  if (name) return name;
  if (id !== null) return `${prefix} #${id}`;
  return null;
}

function AlertsTab({
  rulesMap,
  settings,
  onRulesRefresh,
}: {
  rulesMap: Map<number, Rule>;
  settings: SystemSettings | null;
  onRulesRefresh: () => void;
}) {
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");

  const [page, setPage] = useState<AlertPage | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  const loadAlerts = useCallback(() => {
    setLoading(true);
    api.alerts
      .list({ limit: ALERTS_PAGE_SIZE, offset, days: ALERTS_DAYS })
      .then(setPage)
      .catch(() => setPage(null))
      .finally(() => setLoading(false));
  }, [offset]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const alerts = page?.rows ?? [];
  const total = page?.total ?? 0;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + ALERTS_PAGE_SIZE, total);

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Alert events</CardTitle>
          <p className="text-sm text-muted-foreground">
            Last {ALERTS_DAYS} days{total > 0 ? ` · ${total} total` : ""}
          </p>
        </CardHeader>
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : alerts.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No alerts in the last {ALERTS_DAYS} days.
            </p>
          ) : (
            <>
              <ul className="divide-y">
                {alerts.map((alert) => {
                  const rule = labelStr(alert.rule_name, alert.rule_id, "rule");
                  const dev = labelStr(alert.device_name, alert.device_id, "device");
                  const iface = labelStr(alert.interface_name, alert.interface_id, "iface");

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
                        <span className="text-xs font-medium">
                          {eventTypeLabel(alert.event_type)}
                        </span>
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
                    onClick={() => setOffset(Math.max(0, offset - ALERTS_PAGE_SIZE))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={to >= total}
                    onClick={() => setOffset(offset + ALERTS_PAGE_SIZE)}
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
            onRulesRefresh();
            loadAlerts();
          }}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// History tab (extracted from Reroutes.tsx)
// ---------------------------------------------------------------------------

function RerouteDrawer({
  id,
  onClose,
  onChanged,
}: {
  id: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [detail, setDetail] = useState<RerouteDetail | null>(null);
  const [busy, setBusy] = useState(false);
  const [ackOpen, setAckOpen] = useState(false);
  const [rollbackOpen, setRollbackOpen] = useState(false);

  const load = useCallback(() => {
    api.reroutes.get(id).then(setDetail).catch(() => setDetail(null));
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>) {
    setBusy(true);
    try {
      await fn();
      load();
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "action failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <Dialog open onOpenChange={(v) => !v && onClose()}>
        <DialogContent className="sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              Mitigation #{id}
              {detail && <StateBadge state={detail.state} />}
            </DialogTitle>
          </DialogHeader>
          {!detail ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <div className="max-h-[70vh] space-y-4 overflow-y-auto">
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  <span className="text-muted-foreground">Template: </span>
                  {templateLabelFrom(detail.template_display_name, detail.template_name)}
                </div>
                <div>
                  <span className="text-muted-foreground">Device: </span>
                  {detail.device_name ?? "—"}
                </div>
                <div>
                  <span className="text-muted-foreground">Trigger: </span>
                  {triggerTypeLabel(detail.trigger_type)}
                </div>
                <div>
                  <span className="text-muted-foreground">By: </span>
                  {detail.triggered_by ?? "—"}
                </div>
                <div className="col-span-2">
                  <span className="text-muted-foreground">Verification: </span>
                  {detail.verification_status ?? "—"}
                </div>
                {detail.reason && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Reason: </span>
                    {detail.reason}
                  </div>
                )}
                {detail.failure_reason && (
                  <div className="col-span-2 text-destructive">
                    {detail.failure_reason}
                  </div>
                )}
              </div>

              {detail.outputs.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Commands &amp; output
                  </div>
                  {detail.outputs.map((o, i) => (
                    <div key={i} className="rounded-md border border-border">
                      <div className="border-b border-border bg-muted/40 px-2 py-1 font-mono text-xs">
                        $ {o.request}
                        {o.status && o.status !== "ok" && (
                          <span className="ml-2 text-destructive">[{o.status}]</span>
                        )}
                      </div>
                      {o.response && (
                        <pre className="overflow-x-auto p-2 text-xs">{o.response}</pre>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {detail.verifications.length > 0 && (
                <div className="space-y-1 text-xs">
                  <div className="font-medium uppercase tracking-wide text-muted-foreground">
                    Verification
                  </div>
                  {detail.verifications.map((v, i) => (
                    <div key={i}>
                      <Badge
                        variant={v.result === "pass" ? "default" : "destructive"}
                        className="mr-2"
                      >
                        {v.result}
                      </Badge>
                      <code>{v.expected}</code>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex flex-wrap gap-2 border-t border-border pt-3">
                {(detail.state === "planned" || detail.state === "pending") && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => void act(() => api.reroutes.cancel(detail.id))}
                  >
                    Cancel
                  </Button>
                )}
                {detail.state === "uncertain" && (
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={busy}
                    onClick={() => setAckOpen(true)}
                  >
                    Acknowledge uncertain (clears device lock)
                  </Button>
                )}
                {detail.state === "succeeded" && (
                  <Button
                    size="sm"
                    variant="outline"
                    disabled={busy}
                    onClick={() => setRollbackOpen(true)}
                  >
                    Roll back
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {detail && (
        <PromptDialog
          open={ackOpen}
          onOpenChange={setAckOpen}
          title="Acknowledge uncertain mitigation"
          description="This resolves the action and clears the device lock so reroutes can resume."
          label="Acknowledgement note (what did you verify on the router?)"
          multiline
          submitLabel="Acknowledge"
          onSubmit={async (note) => {
            setAckOpen(false);
            await act(() => api.reroutes.acknowledgeUncertain(detail.id, note));
          }}
        />
      )}
      {detail && (
        <ConfirmDialog
          open={rollbackOpen}
          onOpenChange={setRollbackOpen}
          title="Roll back this action"
          description="Runs the template's rollback against the same router and parameters now."
          confirmLabel="Roll back"
          onConfirm={async () => {
            setRollbackOpen(false);
            await act(() => api.reroutes.rollback(detail.id));
          }}
        />
      )}
    </>
  );
}

function HistoryTab() {
  const [reroutes, setReroutes] = useState<Reroute[]>([]);
  const [locks, setLocks] = useState<Lock[]>([]);
  const [openId, setOpenId] = useState<number | null>(null);

  const load = useCallback(() => {
    api.reroutes.list().then(setReroutes).catch(() => setReroutes([]));
    api.locks.list().then(setLocks).catch(() => setLocks([]));
  }, []);
  useEffect(() => {
    load();
  }, [load]);

  const safetyLocks = locks.filter((l) => l.kind !== "manual" || l.scope === "device");

  return (
    <>
      {safetyLocks.length > 0 && (
        <Card className="border-destructive/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base text-destructive">
              <ShieldAlert className="size-4" />
              Safety locks active
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-1 text-sm">
            {safetyLocks.map((l) => (
              <div key={l.id}>
                <Badge variant="destructive" className="mr-2">
                  {l.scope}
                  {l.scope_ref ? ` #${l.scope_ref}` : ""}
                </Badge>
                <span className="text-muted-foreground">
                  {humanizeToken(l.kind)} — {l.reason ?? ""}
                </span>
              </div>
            ))}
            <p className="pt-1 text-xs text-muted-foreground">
              A locked device blocks mitigations until the related uncertain action is acknowledged.
            </p>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent className="px-0 py-2">
          {reroutes.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">
              No mitigation actions yet.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-6">#</TableHead>
                  <TableHead>Template</TableHead>
                  <TableHead>Device</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>When</TableHead>
                  <TableHead className="pr-6 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reroutes.map((r) => (
                  <TableRow key={r.id} className="hover:bg-muted/50">
                    <TableCell className="pl-6 font-medium">{r.id}</TableCell>
                    <TableCell>
                      {templateLabelFrom(r.template_display_name, r.template_name)}
                    </TableCell>
                    <TableCell>{r.device_name ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {triggerTypeLabel(r.trigger_type)}
                    </TableCell>
                    <TableCell>
                      <StateBadge state={r.state} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(r.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="pr-6 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setOpenId(r.id)}
                      >
                        View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {openId !== null && (
        <RerouteDrawer
          id={openId}
          onClose={() => setOpenId(null)}
          onChanged={load}
        />
      )}
    </>
  );
}

// ---------------------------------------------------------------------------
// Main Mitigations page
// ---------------------------------------------------------------------------

export default function Mitigations() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);

  // Read ?tab= from the URL (for redirect from old /alerts route).
  const params = new URLSearchParams(window.location.search);
  const initialTab = params.get("tab") === "alerts" ? "alerts" : "detections";
  const [tab, setTab] = useState(initialTab);

  const loadRules = useCallback(() => {
    api.rules
      .list()
      .then(setRules)
      .catch(() => setRules([]));
  }, []);

  // Load a recent alert slice once for detecting victim hosts in firing rules.
  // We only need the most recent batch — 100 items is ample.
  const loadRecentAlerts = useCallback(() => {
    api.alerts
      .list({ limit: 100, offset: 0, days: 7 })
      .then((page) => setAlerts(page.rows))
      .catch(() => setAlerts([]));
  }, []);

  useEffect(() => {
    loadRules();
    loadRecentAlerts();
    api.settings
      .get()
      .then(setSettings)
      .catch(() => {});
  }, [loadRules, loadRecentAlerts]);

  function refresh() {
    loadRules();
    loadRecentAlerts();
  }

  const firingRules = rules.filter((r) => r.current_state === "firing");
  const rulesMap = new Map<number, Rule>(rules.map((r) => [r.id, r]));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight">Mitigations</h1>
          {firingRules.length > 0 && (
            <Badge variant="destructive" className="text-xs">
              {firingRules.length} firing
            </Badge>
          )}
        </div>
        <Button asChild variant="outline">
          <Link to="/mitigations/manual">
            <Shuffle className="size-4" />
            New manual mitigation
          </Link>
        </Button>
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="detections" className="gap-2">
            Detections
            {firingRules.length > 0 && (
              <span className="inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-destructive px-1.5 text-[11px] font-semibold text-white">
                {firingRules.length}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="alerts">Alerts</TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="detections" className="mt-4 space-y-3">
          <DetectionsTab
            firingRules={firingRules}
            alerts={alerts}
            settings={settings}
            onRefresh={refresh}
          />
        </TabsContent>

        <TabsContent value="alerts" className="mt-4">
          <AlertsTab
            rulesMap={rulesMap}
            settings={settings}
            onRulesRefresh={loadRules}
          />
        </TabsContent>

        <TabsContent value="history" className="mt-4 space-y-4">
          <HistoryTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}
