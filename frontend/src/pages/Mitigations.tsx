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
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import {
  api,
  type Alert,
  type AlertPage,
  type Lock,
  type Reroute,
  type RerouteDetail,
  type RerouteResult,
  type RerouteBundle,
  type RunSummary,
  type Rule,
  type SystemSettings,
  type ManualMitigationPreview,
} from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { PromptDialog } from "@/components/prompt-dialog";
import { RowActionButton } from "@/components/row-action-button";
import { AsyncRetryButton } from "@/components/async-retry-button";
import { ApplyMitigationDialog, ApplyResultRow, BundleProgressView, ExecutionStartStatus, type ExecutionStartStage } from "@/components/apply-mitigation-dialog";
import { SeverityBadge, StateBadge, ToneBadge, toneClass } from "@/components/status-badge";
import { humanizeToken, eventTypeLabel, templateLabelFrom, triggerTypeLabel } from "@/lib/labels";
import { useAuth } from "@/lib/auth";
import { Eye, ShieldAlert, Shuffle } from "lucide-react";
import { chooseRecoveryChildId, presentMitigationRun, recoveryFieldLabel, recoveryProgressHeading, runSourceName } from "@/lib/mitigation-run-state";

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
  loadError,
}: {
  firingRules: Rule[];
  alerts: Alert[];
  settings: SystemSettings | null;
  onRefresh: () => void;
  loadError?: string | null;
}) {
  const { hasPermission } = useAuth();
  const canApply = hasPermission("trigger_manual_reroute");
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  if (loadError && firingRules.length === 0) return <Card><CardContent className="py-8"><p role="alert" className="text-sm text-destructive">Detections are unavailable: {loadError}. An empty result would not prove normal operation.</p><Button className="mt-3" size="sm" variant="outline" onClick={onRefresh}>Try again</Button></CardContent></Card>;
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
          operatingMode={settings?.operating_mode ?? "unknown"}
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

/** Extracts a non-empty `commands: string[]` from a would-run action's
 *  `rendered` or `rollback` sub-object (each `{ commands: string[] } | null`). */
function actionCommands(
  action: Record<string, unknown>,
  key: "rendered" | "rollback",
): string[] | null {
  const obj = action[key];
  if (obj && typeof obj === "object" && !Array.isArray(obj)) {
    const commands = (obj as { commands?: unknown }).commands;
    if (
      Array.isArray(commands) &&
      commands.length > 0 &&
      commands.every((c) => typeof c === "string")
    ) {
      return commands as string[];
    }
  }
  return null;
}

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
      {wouldRunActions.some((a) => actionCommands(a, "rendered")) && (
        <div className="space-y-1.5 pt-1">
          {wouldRunActions.map((a, i) => {
            const commands = actionCommands(a, "rendered");
            if (!commands) return null;
            const rollbackCommands = actionCommands(a, "rollback");
            return (
              <div key={i}>
                <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
                  {commands.join("\n")}
                </pre>
                {rollbackCommands && (
                  <>
                    <div className="mt-1 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
                      Rollback (to undo by hand)
                    </div>
                    <pre className="mt-0.5 overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
                      {rollbackCommands.join("\n")}
                    </pre>
                  </>
                )}
              </div>
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
          operatingMode={settings?.operating_mode ?? "unknown"}
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

export function ActiveRunsTab() {
  const [pageParams, setPageParams] = useSearchParams();
  const presetFilter = Number(pageParams.get("preset_id")) || undefined;
  const requestedRun = Number(pageParams.get("run")) || undefined;
  const ruleFilter = Number(pageParams.get("rule_id")) || undefined;
  const { hasPermission } = useAuth();
  const canAct = hasPermission("trigger_manual_reroute");
  const [runs, setRuns] = useState<RunSummary[]>([]);
  const [runTotal, setRunTotal] = useState(0);
  const [selected, setSelected] = useState<RerouteBundle | null>(null);
  const [recoveryRun, setRecoveryRun] = useState<RerouteBundle | null>(null);
  const [recoveryError, setRecoveryError] = useState<string | null>(null);
  const recoveryIdRef = useRef<number | null>(null);
  const recoveryRunRef = useRef<RerouteBundle | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ManualMitigationPreview | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [pendingAction, setPendingAction] = useState<"preview_revert" | "confirm_revert" | "direct_revert" | "take_control" | null>(null);
  const [directRevertStage, setDirectRevertStage] = useState<ExecutionStartStage | null>(null);
  const [openingRunId, setOpeningRunId] = useState<number | null>(null);
  const selectedIdRef = useRef<number | null>(null);
  const closedRunRef = useRef<number | null>(null);
  const lastSelectedRunRef = useRef<number | null>(null);
  const previewGeneration = useRef(0);
  const actionGeneration = useRef(0);
  const listAbort = useRef<AbortController | null>(null);
  const detailAbort = useRef<AbortController | null>(null);
  const recoveryAbort = useRef<AbortController | null>(null);
  const requestGeneration = useRef(0);
  const [previewReason, setPreviewReason] = useState<string | null>(null);
  const query = pageParams.get("run_search") ?? "";
  const statusFilter = pageParams.get("status") ?? "";
  const sourceFilter = pageParams.get("source") ?? "";
  const deviceFilter = pageParams.get("device") ?? "";
  const afterFilter = pageParams.get("after") ?? "";
  const beforeFilter = pageParams.get("before") ?? "";
  const page = Math.max(1, Number(pageParams.get("page")) || 1);
  const setFilter = (name: string, value: string) => { const next = new URLSearchParams(pageParams); if (value) next.set(name, value); else next.delete(name); if (name !== "page") next.set("page", "1"); setPageParams(next, { replace: true }); };

  async function refreshRecovery(source: RerouteBundle, generation?: number) {
    const parentChildId = source.latest_recovery_bundle_id ?? source.recovery_bundle_id ?? null;
    const acceptedChildId = recoveryIdRef.current;
    const childId = chooseRecoveryChildId(acceptedChildId, parentChildId);
    if (!childId) return;
    if (recoveryRunRef.current?.id !== childId) { recoveryRunRef.current = null; setRecoveryRun(null); }
    recoveryIdRef.current = childId;
    try {
      recoveryAbort.current?.abort(); const controller=new AbortController(); recoveryAbort.current=controller;
      const child = await api.bundles.get(childId,controller.signal);
      if (child.parent_bundle_id !== source.id) throw new Error("Recovery run does not belong to this mitigation");
      if (selectedIdRef.current === source.id && (generation === undefined || generation === previewGeneration.current) && recoveryIdRef.current === childId) { recoveryRunRef.current = child; setRecoveryRun(child); setRecoveryError(null); }
    } catch {
      if (selectedIdRef.current === source.id && (generation === undefined || generation === previewGeneration.current) && recoveryIdRef.current === childId) { if (recoveryRunRef.current?.id !== childId) { recoveryRunRef.current = null; setRecoveryRun(null); } setRecoveryError(recoveryRunRef.current?.id === childId ? "Revert progress could not be refreshed. Showing retained evidence." : "Revert progress is unavailable for this recovery run."); }
    }
  }

  const load = useCallback(async (force = false) => {
    if (!force && listAbort.current && !listAbort.current.signal.aborted) return;
    listAbort.current?.abort(); const controller=new AbortController(); listAbort.current=controller; const generation=++requestGeneration.current;
    try {
      const localBound=(value:string,next:boolean)=>{if(!value)return undefined;const date=new Date(`${value}T00:00:00`);if(next)date.setDate(date.getDate()+1);return date.toISOString();};
      const response = await api.bundles.list({ lifecycle: statusFilter||"active", logical_only:true, page, per_page: 25, preset_id: presetFilter, rule_id: ruleFilter,q:query||undefined,source_kind:sourceFilter||undefined,device:deviceFilter||undefined,created_from:localBound(afterFilter,false),created_to:localBound(beforeFilter,true),signal:controller.signal });
      if(generation!==requestGeneration.current)return;
      const items=Array.isArray(response)?response:response.items; setRuns(items); setRunTotal(Array.isArray(response)?items.length:response.total); setError(null);
      if (!Array.isArray(response) && response.page !== page) { const next=new URLSearchParams(pageParams); next.set("page",String(response.page)); setPageParams(next,{replace:true}); }
      if (requestedRun && selectedIdRef.current !== requestedRun && closedRunRef.current !== requestedRun) void open(requestedRun);
      const selectedId=selectedIdRef.current;
      if(selectedId!==null){detailAbort.current?.abort();const detailController=new AbortController();detailAbort.current=detailController;try{const current=await api.bundles.get(selectedId,detailController.signal);if(generation===requestGeneration.current&&selectedIdRef.current===selectedId){setSelected(current);await refreshRecovery(current);}}catch(detailCause){if(!detailController.signal.aborted&&generation===requestGeneration.current){setError(`Selected run could not be refreshed. Showing retained evidence.${detailCause instanceof Error?` ${detailCause.message}`:""}`);}}}
    } catch (cause) { if(!controller.signal.aborted&&generation===requestGeneration.current)setError(cause instanceof Error ? cause.message : "Could not refresh active runs"); }
    finally { if (listAbort.current === controller) listAbort.current = null; }
  }, [presetFilter, ruleFilter, requestedRun,page,query,statusFilter,sourceFilter,deviceFilter,afterFilter,beforeFilter]);
  useEffect(() => { void load(); const timer = setInterval(() => void load(), 5000); return () => {clearInterval(timer);listAbort.current?.abort();detailAbort.current?.abort();recoveryAbort.current?.abort();requestGeneration.current+=1;previewGeneration.current+=1;}; }, [load]);
  useEffect(() => {
    if (selected) lastSelectedRunRef.current = selected.id;
    else if (lastSelectedRunRef.current !== null) closedRunRef.current = lastSelectedRunRef.current;
  }, [selected]);

  async function open(id: number) { if (busy || openingRunId !== null) return; detailAbort.current?.abort(); const controller=new AbortController();detailAbort.current=controller; recoveryIdRef.current = null; recoveryRunRef.current = null; setRecoveryRun(null); setRecoveryError(null); setOpeningRunId(id); const next = new URLSearchParams(pageParams); next.set("tab", "active"); next.set("run", String(id)); setPageParams(next, { replace: true }); const generation = ++previewGeneration.current; selectedIdRef.current = id; setBusy(true); setPreview(null); setPreviewReason(null); try { const value = await api.bundles.get(id,controller.signal); if (generation === previewGeneration.current && selectedIdRef.current === id) { setSelected(value); await refreshRecovery(value, generation); } } catch (cause) { if(!controller.signal.aborted)toast.error(cause instanceof Error ? cause.message : "Could not load run"); } finally { setBusy(false); setOpeningRunId(null); } }
  function closeSelectedRun() { previewGeneration.current += 1; actionGeneration.current += 1; detailAbort.current?.abort(); recoveryAbort.current?.abort(); closedRunRef.current = selectedIdRef.current ?? selected?.id ?? null; selectedIdRef.current = null; recoveryIdRef.current = null; recoveryRunRef.current = null; setSelected(null); setRecoveryRun(null); setRecoveryError(null); setPreview(null); setPreviewReason(null); setDirectRevertStage(null); setBusy(false); setPendingAction(null); const next = new URLSearchParams(pageParams); next.delete("run"); setPageParams(next, { replace: true }); }
  async function previewRevert() { if (!selected || busy || pendingAction) return; const runId = selected.id; const requestedReason = reason; const generation = ++actionGeneration.current; setBusy(true); setPendingAction("preview_revert"); setPreview(null); setPreviewReason(null); try { const value = await api.bundles.revert(runId, { dry_run: true, reason: requestedReason || undefined }); if (generation === actionGeneration.current && selectedIdRef.current === runId && reason === requestedReason && "plan_id" in value) { setPreview(value); setPreviewReason(requestedReason); } } catch (cause) { if (generation === actionGeneration.current) toast.error(cause instanceof Error ? cause.message : "Revert preview failed"); } finally { if (generation === actionGeneration.current) { setBusy(false); setPendingAction(null); } } }
  async function confirmRevert() { if (!selected || busy || pendingAction || !preview?.plan_id || !preview.preview_token || previewReason !== reason) return; const generation=++actionGeneration.current; setBusy(true); setPendingAction("confirm_revert"); try { const value = await api.bundles.revert(selected.id, { dry_run: false, reason: previewReason || undefined, plan_id: preview.plan_id, preview_token: preview.preview_token }); if(generation!==actionGeneration.current)return; setPreview(null); setPreviewReason(null); if ("bundle_id" in value) { recoveryIdRef.current = value.bundle_id; recoveryRunRef.current = null; setRecoveryRun(null); setRecoveryError(null); toast.success(`Revert run #${value.bundle_id} started`); } await load(true); } catch (cause) { if(generation===actionGeneration.current){setPreview(null); setPreviewReason(null); toast.error(`${cause instanceof Error ? cause.message : "Revert failed"}. Prepare a fresh preview.`);} } finally { if(generation===actionGeneration.current){setBusy(false); setPendingAction(null);} } }
  async function revertNow() {
    if (!selected || busy || pendingAction || selected.revert?.available === false) return;
    const runId = selected.id;
    const requestedReason = reason;
    const generation = ++actionGeneration.current;
    setBusy(true);
    setPendingAction("direct_revert");
    setDirectRevertStage("calculating");
    setPreview(null);
    setPreviewReason(null);
    let prepared = false;
    try {
      const exact = await api.bundles.revert(runId, {
        dry_run: true,
        reason: requestedReason || undefined,
      });
      if (generation !== actionGeneration.current || selectedIdRef.current !== runId || reason !== requestedReason) return;
      if (!("plan_id" in exact) || !exact.plan_id || !exact.preview_token) {
        if ("plan_id" in exact) {
          setPreview(exact);
          setPreviewReason(requestedReason);
        }
        toast.error("The controller did not authorize this prepared revert. Nothing was started.");
        return;
      }
      prepared = true;
      setDirectRevertStage("starting");
      const value = await api.bundles.revert(runId, {
        dry_run: false,
        reason: requestedReason || undefined,
        plan_id: exact.plan_id,
        preview_token: exact.preview_token,
      });
      if (generation !== actionGeneration.current || selectedIdRef.current !== runId) return;
      if ("bundle_id" in value) {
        recoveryIdRef.current = value.bundle_id;
        recoveryRunRef.current = null;
        setRecoveryRun(null);
        setRecoveryError(null);
        toast.success(`Revert run #${value.bundle_id} started`);
      }
      await load(true);
    } catch (cause) {
      if (generation === actionGeneration.current) {
        toast.error(prepared
          ? `${cause instanceof Error ? cause.message : "Revert failed"}. Prepare a fresh exact plan before retrying.`
          : cause instanceof Error ? cause.message : "The exact revert could not be calculated.");
      }
    } finally {
      if (generation === actionGeneration.current) {
        setDirectRevertStage(null);
        setBusy(false);
        setPendingAction(null);
      }
    }
  }
  async function takeControl() { if (!selected || busy || pendingAction) return; const generation=++actionGeneration.current; setBusy(true); setPendingAction("take_control"); try { await api.bundles.takeControl(selected.id); if(generation!==actionGeneration.current)return; toast.success("Automatic recovery cancelled. Revert remains available manually."); await load(true); } catch (cause) { if(generation===actionGeneration.current)toast.error(cause instanceof Error ? cause.message : "Automatic recovery could not be cancelled"); } finally { if(generation===actionGeneration.current){setBusy(false); setPendingAction(null);} } }
  const shown = runs; const pages = Math.max(1, Math.ceil(runTotal / 25));
  const displayedRecoveryId = selected ? recoveryIdRef.current ?? selected.recovery_bundle_id ?? selected.latest_recovery_bundle_id ?? null : null;
  const displayedRecoveryState = displayedRecoveryId === null ? undefined : recoveryRun?.id === displayedRecoveryId ? recoveryRun.state : selected?.latest_recovery?.id === displayedRecoveryId ? selected.latest_recovery.state : undefined;

  return <>
    {error && <div role="alert" className="mb-3 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">Refresh failed. Showing retained run data. {error} <AsyncRetryButton onRetry={() => load(true)} /></div>}
    {presetFilter && <p className="text-sm text-muted-foreground">Showing active runs for saved mitigation #{presetFilter}. Choose the exact run to inspect before reverting.</p>}
    {ruleFilter && <p className="text-sm text-muted-foreground">Showing active runs owned by rule #{ruleFilter}. Choose the original run to inspect before reverting.</p>}
    <div className="grid gap-2 md:grid-cols-3 xl:grid-cols-6"><Input aria-label="Search active mitigation runs" placeholder="Search run or operator…" value={query} onChange={(event) => setFilter("run_search", event.target.value)} /><select className="rounded-md border bg-background px-3 py-2 text-sm" aria-label="Lifecycle status" value={statusFilter} onChange={(event) => setFilter("status", event.target.value)}><option value="">All statuses</option><option value="active">Active</option><option value="recovery_scheduled">Recovery scheduled</option></select><select className="rounded-md border bg-background px-3 py-2 text-sm" aria-label="Run source" value={sourceFilter} onChange={(event) => setFilter("source", event.target.value)}><option value="">All sources</option><option value="manual">Manual</option><option value="preset">Saved mitigation</option><option value="rule">Rule</option></select><Input aria-label="Filter by device" placeholder="Device name or ID" value={deviceFilter} onChange={(event) => setFilter("device", event.target.value)} /><Input type="date" aria-label="Started after" value={afterFilter} onChange={(event) => setFilter("after", event.target.value)} /><Input type="date" aria-label="Started before" value={beforeFilter} onChange={(event) => setFilter("before", event.target.value)} /></div>
    <Card><CardContent className="px-0 py-2">{shown.length === 0 && !error ? <p className="px-6 py-5 text-sm text-muted-foreground">No active runs match these filters.</p> : <Table><TableHeader><TableRow><TableHead className="pl-6">Run</TableHead><TableHead>Source</TableHead><TableHead>Operator / started</TableHead><TableHead>Current state</TableHead><TableHead>Changes</TableHead><TableHead className="pr-6 text-right">Action</TableHead></TableRow></TableHeader><TableBody>{shown.map((run) => { const state = presentMitigationRun(run); return <TableRow key={run.id}><TableCell className="pl-6 font-medium tabular-nums">#{run.id}</TableCell><TableCell>{runSourceName(run)}{run.verification_mode === "configuration_only" && <span className="block text-xs text-muted-foreground">Configuration only</span>}</TableCell><TableCell className="text-xs">{run.triggered_by ?? "system"}<span className="block text-muted-foreground">{run.created_at ? new Date(run.created_at).toLocaleString() : "—"}</span></TableCell><TableCell><ToneBadge tone={state.tone}>{state.label}</ToneBadge><span className="block max-w-sm text-xs text-muted-foreground">{state.detail}</span></TableCell><TableCell className="tabular-nums">{state.known} known{state.unknown > 0 && <span className="block text-xs text-destructive">{state.unknown} unknown</span>}</TableCell><TableCell className="pr-6 text-right"><RowActionButton label={openingRunId === run.id ? `Opening run ${run.id}…` : `Review run ${run.id}`} onClick={() => void open(run.id)} disabled={busy || openingRunId !== null} loading={openingRunId === run.id} loadingLabel={`Opening run ${run.id}…`}><Eye className="size-4" /></RowActionButton></TableCell></TableRow>; })}</TableBody></Table>}<div className="flex items-center justify-end gap-2 px-6 py-3 text-sm"><Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setFilter("page", String(page - 1))}>Previous</Button><span>Page {Math.min(page, pages)} of {pages}</span><Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setFilter("page", String(page + 1))}>Next</Button></div></CardContent></Card>
    <Dialog open={selected !== null} onOpenChange={(open) => { if (!open && !busy) closeSelectedRun(); }}><DialogContent className="sm:max-w-3xl"><DialogHeader><DialogTitle>Mitigation run #{selected?.id}</DialogTitle><DialogDescription>Execution outcome and current router changes are separate. Revert always targets this explicitly selected run.</DialogDescription></DialogHeader>{selected && <div className="max-h-[70vh] space-y-4 overflow-y-auto">
      <div className="grid gap-2 text-sm sm:grid-cols-2"><p>Current state: <ToneBadge tone={presentMitigationRun(selected).tone}>{presentMitigationRun(selected).label}</ToneBadge></p><p>Lifecycle: <strong>{humanizeToken(selected.lifecycle_state ?? "unknown")}</strong></p><p>Known changes: <strong>{selected.remaining_changes ?? selected.remaining_mutations ?? selected.still_applied_reroute_ids.length}</strong></p><p>Unknown effects: <strong>{selected.unknown_effects ?? 0}</strong></p><p>Recovery: {recoveryFieldLabel(selected, recoveryRun, displayedRecoveryId)}</p></div>
      <p className="text-xs text-muted-foreground">{presentMitigationRun(selected).detail}</p>
      {selected.revert?.block_reasons?.length ? <div role="status" className="rounded-md border p-3 text-sm"><strong>Manual revert unavailable</strong><ul className="mt-1 list-disc pl-5 text-muted-foreground">{selected.revert.block_reasons.map((blockReason)=><li key={blockReason}>{blockReason}</li>)}</ul></div>:null}
      {selected.automatic_recovery_block_reason && <div role="alert" className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100"><strong>Automatic recovery blocked</strong><p className="mt-1 break-words">{selected.automatic_recovery_block_reason}</p></div>}
      {canAct && selected.take_control?.available && <div role="status" className="rounded-md border border-border bg-muted/40 p-3 text-sm"><strong>Automatic recovery is still eligible</strong><p className="mt-1 text-muted-foreground">Cancel automatic recovery to keep the current router changes in place until an operator starts a manual revert. Cancelling it does not send router commands.</p></div>}
      {displayedRecoveryId ? <section className="space-y-3"><h3 className="text-sm font-semibold">{recoveryProgressHeading(displayedRecoveryState)} · recovery #{displayedRecoveryId}</h3>{recoveryError && <p role="alert" className="text-sm text-amber-700 dark:text-amber-300">{recoveryError}</p>}{recoveryRun?.id === displayedRecoveryId ? <><h4 className="text-sm font-medium">Revert progress</h4><BundleProgressView bundle={recoveryRun} bundleId={recoveryRun.id} totalHint={selected.total_actions} pollError={recoveryError} /></> : <p role="status" className="text-sm text-muted-foreground">Revert accepted · loading progress…</p>}<details><summary className="cursor-pointer text-sm font-medium">Original application</summary><div className="mt-2"><BundleProgressView bundle={selected} bundleId={selected.id} totalHint={selected.total_actions} pollError={null} /></div></details></section> : selected.lifecycle_state === "recovery_claimed" ? <div role="status" className="rounded-md border p-3 text-sm"><strong>Preparing revert</strong><p className="text-xs text-muted-foreground">The recovery run is being created.</p></div> : <BundleProgressView bundle={selected} bundleId={selected.id} totalHint={selected.total_actions} pollError={null} />}
      {directRevertStage && <ExecutionStartStatus kind="revert" stage={directRevertStage} />}
      {!preview && <p className="text-xs text-muted-foreground">The controller always reads current router configuration and calculates the exact inverse first. Preview revert pauses for review; Revert now prepares and starts the same exact plan.</p>}
      {preview && <div className="space-y-2 rounded-md border p-3"><strong>Review the exact revert</strong>{preview.results.map((result, index) => <ApplyResultRow key={index} r={result} />)}<p className="text-xs text-muted-foreground">The persisted inverses run in reverse order with the original verification scope. Apply reviewed revert submits this exact prepared plan.</p></div>}
      {canAct && <label className="block space-y-1 text-sm font-medium">Audit reason<Input value={reason} disabled={busy} onChange={(event) => { actionGeneration.current += 1; setReason(event.target.value); setPreview(null); setPreviewReason(null); setDirectRevertStage(null); setBusy(false); setPendingAction(null); }} placeholder="Why is this run being reverted?" /></label>}
      <DialogFooter className="flex-wrap items-center gap-2"><Button variant="outline" onClick={closeSelectedRun} disabled={busy}>Close</Button>{canAct && selected.take_control?.available && <Button variant="outline" onClick={() => void takeControl()} disabled={busy} loading={pendingAction === "take_control"} loadingLabel="Cancelling automatic recovery…">Cancel automatic recovery</Button>}{canAct && !preview && <Button variant="outline" onClick={() => void previewRevert()} disabled={busy || selected.revert?.available === false} loading={pendingAction === "preview_revert"} loadingLabel="Preparing revert preview…">Preview revert</Button>}{canAct && !preview && <Button variant="destructive" onClick={() => void revertNow()} disabled={busy || selected.revert?.available === false} loading={pendingAction === "direct_revert"} loadingLabel={directRevertStage === "starting" ? "Starting revert…" : "Calculating exact revert…"}>Revert now</Button>}{canAct && preview && <Button variant="destructive" onClick={() => void confirmRevert()} disabled={busy || !preview.plan_id || !preview.preview_token} loading={pendingAction === "confirm_revert"} loadingLabel="Starting revert…">Apply reviewed revert</Button>}</DialogFooter>
    </div>}</DialogContent></Dialog>
  </>;
}

function RerouteDrawer({
  id,
  onClose,
  onChanged,
}: {
  id: number;
  onClose: () => void;
  onChanged: () => void;
}) {
  const { hasPermission } = useAuth();
  const [detail, setDetail] = useState<RerouteDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [rollbackPending, setRollbackPending] = useState<"preview" | "confirm" | "cancel" | null>(null);
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackPreview, setRollbackPreview] = useState<RerouteResult | null>(null);
  const [rollbackToken, setRollbackToken] = useState<string | null>(null);
  const [rollbackExecuted, setRollbackExecuted] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [reconcileOpen, setReconcileOpen] = useState(false);
  const [reconcileResult, setReconcileResult] = useState<{
    outcome: "changed" | "not_applied" | "conflict";
    message: string;
  } | null>(null);

  const load = useCallback(() => {
    return api.reroutes.get(id).then((value) => { setDetail(value); setDetailError(null); }).catch((cause) => setDetailError(cause instanceof Error ? cause.message : "Could not load mitigation action"));
  }, [id]);
  useEffect(() => {
    load();
  }, [load]);

  async function act(fn: () => Promise<unknown>, pending?: "cancel") {
    setBusy(true);
    if (pending) setRollbackPending(pending);
    try {
      await fn();
      load();
      onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "action failed");
    } finally {
      setBusy(false);
      if (pending) setRollbackPending(null);
    }
  }

  async function previewRollback() {
    if (!detail) return;
    setBusy(true);
    setRollbackPending("preview");
    try {
      const response = await api.reroutes.rollback(detail.id, { dry_run: true });
      setRollbackPreview(response.result);
      setRollbackToken(response.preview_token ?? null);
      setRollbackExecuted(false);
      setRollbackError(null);
      setRollbackOpen(true);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "rollback preview failed");
    } finally {
      setBusy(false);
      setRollbackPending(null);
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
          {detailError ? (
            <div role="alert" className="text-sm text-destructive">{detailError}. <AsyncRetryButton onRetry={load} /></div>
          ) : !detail ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : (
            <div className="max-h-[70vh] space-y-4 overflow-y-auto">
              {(detail.verification_mode ?? detail.source?.verification_mode ?? "routing") === "configuration_only" && (
                <p className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">
                  Configuration-only action — routing was not verified. Review the action state and device output for its configuration outcome.
                </p>
              )}
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
                {(detail.source?.preset_name || detail.source_preset_name) && (
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Source: </span>
                    Manual mitigation “{detail.source?.preset_name ?? detail.source_preset_name}”
                    {(detail.source?.preset_revision ?? detail.source_preset_revision) != null
                      ? ` · revision ${detail.source?.preset_revision ?? detail.source_preset_revision}`
                      : ""}
                  </div>
                )}
                {detail.bundle_id != null && (
                  <div className="col-span-2">
                    <Link className="font-medium text-primary underline-offset-4 hover:underline" to={`/mitigations?tab=active&run=${detail.bundle_id}`}>
                      View complete bundle #{detail.bundle_id}
                    </Link>
                  </div>
                )}
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
                {reconcileResult && (
                  <div className={`col-span-2 rounded-md border p-3 ${reconcileResult.outcome === "conflict" ? "border-destructive bg-destructive/10 text-destructive" : "border-border bg-muted/30"}`} role="status">
                    <span className="font-medium">Reconciliation: {humanizeToken(reconcileResult.outcome)}.</span>{" "}
                    {reconcileResult.message}
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
                    onClick={() => void act(() => api.reroutes.cancel(detail.id), "cancel")}
                    loading={rollbackPending === "cancel"}
                    loadingLabel="Cancelling…"
                  >
                    Cancel
                  </Button>
                )}
                {detail.reconcile_available && hasPermission("acknowledge_uncertain_reroute") && (
                  <>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busy}
                      onClick={() => setReconcileOpen(true)}
                    >
                      Reconcile device state
                    </Button>
                  </>
                )}
                {(detail.state === "succeeded" ||
                  (detail.state === "failed" && detail.started_at !== null)) && (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void previewRollback()}
                    loading={rollbackPending === "preview"}
                    loadingLabel="Preparing rollback preview…"
                  >
                    Preview rollback
                  </Button>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>

      {detail && (
        <PromptDialog
          open={reconcileOpen}
          onOpenChange={setReconcileOpen}
          title="Reconcile mitigation evidence"
          description="The controller will read the router and compare it with the action's intended before/after state. This does not push configuration."
          label="Operator note"
          multiline
          submitLabel="Read and reconcile"
          onSubmit={async (note) => {
            setBusy(true);
            try {
              const result = await api.reroutes.reconcile(detail.id, note);
              setReconcileResult({ outcome: result.outcome, message: result.message });
              setReconcileOpen(false);
              load();
              onChanged();
            } catch (error) {
              setReconcileResult({
                outcome: "conflict",
                message: error instanceof Error ? error.message : "Reconciliation failed",
              });
            } finally {
              setBusy(false);
            }
          }}
        />
      )}
      {detail && (
        <Dialog
          open={rollbackOpen}
          onOpenChange={(open) => {
            if (busy) return;
            setRollbackOpen(open);
            if (!open) {
              setRollbackPreview(null);
              setRollbackToken(null);
              setRollbackExecuted(false);
              setRollbackError(null);
            }
          }}
        >
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>Review rollback commands</DialogTitle>
              <DialogDescription>
                Step 2 · Review and explicitly confirm this rollback. The preview
                read current router configuration and made no configuration changes. Execution rechecks locks, reachability,
                and verification.
              </DialogDescription>
            </DialogHeader>
            {rollbackPreview?.would_run ? (
              <div className="max-h-[55vh] space-y-2 overflow-y-auto">
                <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                  {rollbackPreview.would_run.commands.join("\n")}
                </pre>
                {rollbackPreview.would_run.verify && (
                  <p className="text-xs text-muted-foreground">
                    Verify: <code>{rollbackPreview.would_run.verify.command}</code>
                  </p>
                )}
              </div>
            ) : rollbackPreview ? (
              <div
                className={`space-y-2 rounded-md border p-3 text-sm ${
                  rollbackPreview.state === "uncertain" || rollbackPreview.blocked_reason
                    ? "border-destructive bg-destructive/10"
                    : "border-border"
                }`}
                role="status"
              >
                <div className="flex items-center gap-2">
                  <StateBadge
                    state={rollbackPreview.state ?? (rollbackPreview.executed ? "succeeded" : "blocked")}
                  />
                  {rollbackExecuted && <span className="font-medium">Rollback result</span>}
                </div>
                <p className="break-words">
                  {rollbackPreview.blocked_reason ?? rollbackPreview.message}
                </p>
                {rollbackPreview.reroute_id && (
                  <p className="text-xs text-muted-foreground">
                    New rollback action #{rollbackPreview.reroute_id}. Its state and evidence are now in history.
                  </p>
                )}
              </div>
            ) : (
              <p className="text-sm text-destructive">No rollback plan is available.</p>
            )}
            {rollbackError && (
              <div className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">
                {rollbackError} The one-use approval may be spent. Close this dialog, refresh history, and prepare a new rollback preview before retrying.
              </div>
            )}
            <DialogFooter>
              <Button
                variant="outline"
                disabled={busy}
                onClick={() => setRollbackOpen(false)}
              >
                Cancel
              </Button>
              {!rollbackExecuted && (
                <Button
                  variant="destructive"
                  disabled={!rollbackPreview?.would_run || !rollbackToken}
                  loading={rollbackPending === "confirm"}
                  loadingLabel="Starting rollback…"
                  onClick={() => {
                    setBusy(true);
                    setRollbackPending("confirm");
                    void api.reroutes
                      .rollback(detail.id, { preview_token: rollbackToken ?? undefined })
                      .then((response) => {
                        setRollbackPreview(response.result);
                        setRollbackToken(null);
                        setRollbackExecuted(true);
                        load();
                        onChanged();
                      })
                      .catch((e) =>
                        {
                          setRollbackToken(null);
                          setRollbackExecuted(true);
                          setRollbackError(e instanceof Error ? e.message : "Rollback response was not confirmed.");
                        },
                      )
                      .finally(() => { setBusy(false); setRollbackPending(null); });
                  }}
                >
                  Apply reviewed rollback
                </Button>
              )}
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}

export function HistoryTab({ initialOpenId }: { initialOpenId?: number | null }) {
  const [historyParams, setHistoryParams] = useSearchParams();
  const historyPage = Math.max(1, Number(historyParams.get("history_page")) || 1);
  const historyTrigger = historyParams.get("history_trigger") ?? "";
  const historyRule = Number(historyParams.get("history_rule")) || undefined;
  const historyPreset = Number(historyParams.get("history_preset")) || undefined;
  const setHistoryFilter = (name: string, value: string) => { const next = new URLSearchParams(historyParams); if (value) next.set(name, value); else next.delete(name); next.set("history_page", "1"); setHistoryParams(next, { replace: true }); };
  const [reroutes, setReroutes] = useState<Reroute[]>([]);
  const [bundles, setBundles] = useState<RunSummary[]>([]);
  const [bundleError, setBundleError] = useState<string | null>(null);
  const [rerouteError, setRerouteError] = useState<string | null>(null);
  const [lockError, setLockError] = useState<string | null>(null);
  const [locks, setLocks] = useState<Lock[]>([]);
  const [bundleTotal, setBundleTotal] = useState(0);
  // ?reroute=<id> deep-links straight to one action (the bundle-progress dialog
  // links here when a sibling is left applied and needs a manual rollback).
  const [openId, setOpenId] = useState<number | null>(initialOpenId ?? null);

  const load = useCallback(() => {
    return Promise.allSettled([
      api.reroutes.list().then((value) => { setReroutes(value); setRerouteError(null); }).catch((cause) => setRerouteError(cause instanceof Error ? cause.message : "Could not load action history")),
      api.locks.list().then((value) => { setLocks(value); setLockError(null); }).catch((cause) => setLockError(cause instanceof Error ? cause.message : "Could not load safety locks")),
      api.bundles.list({ lifecycle: "all", page: historyPage, per_page: 50, trigger_type: historyTrigger || undefined, rule_id: historyRule, preset_id: historyPreset }).then((response) => { const items = Array.isArray(response) ? response : response.items; setBundles(items); setBundleTotal(Array.isArray(response) ? response.length : response.total); setBundleError(null); }).catch((error) => setBundleError(error instanceof Error ? error.message : "Could not load mitigation runs")),
    ]);
  }, [historyPage, historyTrigger, historyRule, historyPreset]);
  useEffect(() => {
    load();
  }, [load]);

  const safetyLocks = locks.filter((l) => l.kind !== "manual" || l.scope === "device");

  return (
    <>
      {(rerouteError || lockError) && <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">Some history safety data could not be refreshed. Retained data remains visible. {[lockError, rerouteError].filter(Boolean).join(" · ")} <AsyncRetryButton onRetry={load} /></div>}
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
        <CardHeader><CardTitle className="text-base">Mitigation runs</CardTitle></CardHeader>
        <CardContent className="px-0 py-2">
          <div className="grid gap-2 px-6 pb-3 sm:grid-cols-3"><select aria-label="History trigger type" className="rounded-md border bg-background px-3 py-2 text-sm" value={historyTrigger} onChange={(event) => setHistoryFilter("history_trigger", event.target.value)}><option value="">All trigger types</option><option value="manual">Manual</option><option value="automatic">Automatic</option><option value="rollback">Revert</option></select><Input aria-label="History rule ID" inputMode="numeric" placeholder="Rule ID" value={historyRule ?? ""} onChange={(event) => setHistoryFilter("history_rule", event.target.value)} /><Input aria-label="History saved mitigation ID" inputMode="numeric" placeholder="Saved mitigation ID" value={historyPreset ?? ""} onChange={(event) => setHistoryFilter("history_preset", event.target.value)} /></div>
          {bundleError ? (
            <div className="mx-6 rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">{bundleError}. Run history is unavailable; an empty list would be unsafe to assume.</div>
          ) : bundles.length === 0 ? (
            <p className="px-6 py-4 text-sm text-muted-foreground">No mitigation runs yet.</p>
          ) : (
            <Table><TableHeader><TableRow className="hover:bg-transparent"><TableHead className="pl-6">Bundle</TableHead><TableHead>Source</TableHead><TableHead>Progress</TableHead><TableHead>State</TableHead><TableHead>When</TableHead><TableHead className="pr-6 text-right">Actions</TableHead></TableRow></TableHeader>
              <TableBody>{bundles.map((run) => <TableRow key={run.id}><TableCell className="pl-6 font-medium tabular-nums">#{run.id}</TableCell><TableCell className="text-xs">{run.source?.preset_name ?? run.source?.name ?? triggerTypeLabel(run.trigger_type)}{run.verification_mode === "configuration_only" && <span className="block text-muted-foreground">Configuration only</span>}</TableCell><TableCell className="text-xs tabular-nums">{run.completed_actions}/{run.total_actions}</TableCell><TableCell><StateBadge state={run.state} /></TableCell><TableCell className="text-xs text-muted-foreground">{run.created_at ? new Date(run.created_at).toLocaleString() : "—"}</TableCell><TableCell className="pr-6 text-right"><RowActionButton asChild label={`View run ${run.id}`}><Link to={`/mitigations?tab=active&run=${run.id}`}><Eye className="size-4" /></Link></RowActionButton></TableCell></TableRow>)}</TableBody>
            </Table>
          )}
          <div className="flex items-center justify-end gap-2 px-6 py-3 text-sm"><Button size="sm" variant="outline" disabled={historyPage <= 1} onClick={() => { const next = new URLSearchParams(historyParams); next.set("history_page", String(historyPage - 1)); setHistoryParams(next); }}>Previous</Button><span>Page {historyPage} of {Math.max(1, Math.ceil(bundleTotal / 50))}</span><Button size="sm" variant="outline" disabled={historyPage * 50 >= bundleTotal} onClick={() => { const next = new URLSearchParams(historyParams); next.set("history_page", String(historyPage + 1)); setHistoryParams(next); }}>Next</Button></div>
        </CardContent>
      </Card>

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
                      <span className="block">{triggerTypeLabel(r.trigger_type)}</span>
                      {(r.source?.preset_name || r.source_preset_name) && (
                        <span className="block max-w-44 truncate" title={r.source?.preset_name ?? r.source_preset_name ?? undefined}>
                          {r.source?.preset_name ?? r.source_preset_name}
                          {(r.source?.preset_revision ?? r.source_preset_revision) != null
                            ? ` · r${r.source?.preset_revision ?? r.source_preset_revision}`
                            : ""}
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <StateBadge state={r.state} />
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {new Date(r.created_at).toLocaleString()}
                    </TableCell>
                    <TableCell className="pr-6 text-right">
                      <RowActionButton
                        label={`View action ${r.id}`}
                        onClick={() => setOpenId(r.id)}
                      >
                        <Eye className="size-4" />
                      </RowActionButton>
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
  const [searchParams, setSearchParams] = useSearchParams();
  const [rules, setRules] = useState<Rule[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [alertsError, setAlertsError] = useState<string | null>(null);
  const [settingsError, setSettingsError] = useState<string | null>(null);

  // Read ?tab= from the URL (redirect from the old /alerts route, and the
  // ?tab=history&reroute=<id> deep link used by bundle progress).
  const tabParam = searchParams.get("tab");
  const rerouteParam = Number(searchParams.get("reroute"));
  const initialReroute = Number.isFinite(rerouteParam) && rerouteParam > 0 ? rerouteParam : null;
  const initialTab =
    tabParam === "alerts"
      ? "alerts"
      : tabParam === "history" || initialReroute !== null
        ? "history"
        : tabParam === "detections" ? "detections" : "active";
  const tab = initialTab;

  const loadRules = useCallback(() => {
    api.rules
      .list()
      .then((value) => { setRules(value); setRulesError(null); })
      .catch((cause) => setRulesError(cause instanceof Error ? cause.message : "Rules unavailable"));
  }, []);

  // Load a recent alert slice once for detecting victim hosts in firing rules.
  // We only need the most recent batch — 100 items is ample.
  const loadRecentAlerts = useCallback(() => {
    api.alerts
      .list({ limit: 100, offset: 0, days: 7 })
      .then((page) => { setAlerts(page.rows); setAlertsError(null); })
      .catch((cause) => setAlertsError(cause instanceof Error ? cause.message : "Recent alerts unavailable"));
  }, []);

  useEffect(() => {
    loadRules();
    loadRecentAlerts();
    api.settings
      .get()
      .then((value) => { setSettings(value); setSettingsError(null); })
      .catch((cause) => setSettingsError(cause instanceof Error ? cause.message : "Settings unavailable"));
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
          <Link to="/manual-mitigations/new">
            <Shuffle className="size-4" />
            New manual mitigation
          </Link>
        </Button>
      </div>

      {(alertsError || settingsError) && <div role="status" className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">Some supporting data is stale or unavailable. {[alertsError, settingsError].filter(Boolean).join(" · ")}</div>}
      <Tabs value={tab} onValueChange={(value) => { const next = new URLSearchParams(searchParams); next.set("tab", value); setSearchParams(next); }}>
        <TabsList>
          <TabsTrigger value="active">Active</TabsTrigger>
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

        <TabsContent value="active" className="mt-4 space-y-3"><ActiveRunsTab /></TabsContent>

        <TabsContent value="detections" className="mt-4 space-y-3">
          <DetectionsTab
            firingRules={firingRules}
            alerts={alerts}
            settings={settings}
            onRefresh={refresh}
            loadError={rulesError}
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
          <HistoryTab initialOpenId={initialReroute} />
        </TabsContent>
      </Tabs>
    </div>
  );
}
