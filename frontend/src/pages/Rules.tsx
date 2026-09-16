/**
 * /rules — threshold rules on SNMP interfaces.
 *
 * Governed by docs/detection-engine.md and docs/doctrine.md §8.
 *
 * Polished shadcn Table with icon, badges, sortable Name header, and ghost
 * icon-button actions (toggle enable/disable + delete). Create-rule form
 * preserved. RBAC: edit_rules permission gates toggle and delete (both
 * roles have it — current behaviour kept).
 */
import { useEffect, useState } from "react";
import {
  SlidersHorizontal,
  Pencil,
  Trash2,
  ArrowUp,
  ArrowDown,
  ChevronUp,
  ChevronDown,
  ChevronsUpDown,
  Workflow,
  Plus,
  X,
  Info,
} from "lucide-react";
import { toast } from "sonner";
import {
  api,
  type Rule,
  type Device,
  type Template,
  type SystemSettings,
  ApiError,
} from "@/lib/api";
import { Label } from "@/components/ui/label";
import { ActionParamsForm } from "@/components/action-params-form";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ApplyMitigationDialog } from "@/components/apply-mitigation-dialog";
import { Switch } from "@/components/ui/switch";
import { SeverityBadge, toneClass } from "@/components/status-badge";
import { RuleDialog } from "./rules/rule-dialog";
import { metricLabel, isFlowMetric } from "./rules/rule-constants";
import { templateLabel, templateLabelFrom, automationStatus } from "@/lib/labels";
import { useAuth } from "@/lib/auth";
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
  DialogDescription,
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

/**
 * Manage a rule's reroute actions (template + target router + params). The
 * params form is schema-driven: a BGP-neighbor param renders a dropdown of the
 * device's discovered sessions and auto-fills the local AS.
 *
 * Template visibility rules:
 * - MSS templates (iface_tcp_adjust_mss / iface_tcp_adjust_mss_remove) are
 *   hidden from the dropdown; they're only attached as the second action in the
 *   BGP-advertise MSS-clamp bundle (see (d) below).
 * - blackhole_prefix / null_route_prefix on a FLOW rule: auto-detect mode is
 *   forced (auto_target: "flow_dst_host"); no prefix input is shown.
 * - blackhole_prefix / null_route_prefix on a non-flow rule: normal prefix input
 *   with helper text ("Manual target: a prefix you choose ...").
 * - bgp_advertise_add / bgp_advertise_remove: optional MSS-clamp bundle checkbox
 *   (one clamp per selected router, right after that router's BGP actions).
 *
 * Ordering and bulk add (plans/015):
 * - `position` is always sent explicitly (max existing + 1). Execution order is a
 *   safety property: additive actions must be able to run before destructive ones.
 * - Up/down controls rewrite the affected suffix via delete + re-add; the API has
 *   no PATCH on rule_actions.
 * - Routers and announced prefixes are multi-selects; submitting posts the
 *   cartesian product sequentially. A mid-sequence failure stops, reports exactly
 *   how many landed, and re-reads the rule (audit finding FE-06).
 */
type PlannedAction = {
  reroute_template_id: number;
  device_id: number;
  params: Record<string, unknown>;
  position: number;
  auto_target?: string | null;
  label: string;
};

function RuleActionsDialog({
  rule,
  onClose,
  onChanged,
}: {
  rule: Rule;
  onClose: () => void;
  onChanged: (updated: Rule) => void;
}) {
  const [current, setCurrent] = useState<Rule>(rule);
  const [allTemplates, setAllTemplates] = useState<Template[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [templateId, setTemplateId] = useState<string>("");
  /** Bulk add: every checked router gets the same action set. */
  const [deviceIds, setDeviceIds] = useState<number[]>([]);
  /** Inventory params are validated per device, so each router keeps its own
   *  value set (different upstream neighbours, prefix-lists, interfaces). */
  const [valuesByDevice, setValuesByDevice] = useState<Record<number, Record<string, string>>>({});
  /** Bulk add: the announced-prefix parameter takes a multi-selection; the
   *  submitted action set is routers x prefixes. */
  const [selectedPrefixes, setSelectedPrefixes] = useState<string[]>([]);
  const [networksByDevice, setNetworksByDevice] = useState<Record<number, string[]>>({});
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  /** What a partially-failed add still owes, pinned to the form it came from.
   *  The API has no batch endpoint and no idempotency key, so re-submitting the
   *  whole routers x prefixes product would duplicate everything that already
   *  landed. The button therefore re-arms as "Retry remaining N" instead. */
  const [pendingRetry, setPendingRetry] = useState<{
    items: PlannedAction[];
    signature: string;
  } | null>(null);

  // BGP + MSS bundle state (only relevant for bgp_advertise_* templates)
  const [mssBundle, setMssBundle] = useState(false);
  const [mssIfaceByDevice, setMssIfaceByDevice] = useState<Record<number, string>>({});
  const [mssValue, setMssValue] = useState<string>("1436");
  const [ifacesByDevice, setIfacesByDevice] = useState<
    Record<number, Array<{ id: number; if_name: string; if_alias: string | null }>>
  >({});

  const isFlowRule = Boolean(current.flow_direction);

  // Template names that support auto-targeting (host-route templates).
  const HOST_TARGET_TEMPLATES = ["null_route_prefix", "blackhole_prefix"];
  // MSS templates — hidden from the dropdown; only used in the BGP bundle.
  const MSS_TEMPLATE_NAMES = ["iface_tcp_adjust_mss", "iface_tcp_adjust_mss_remove"];
  // BGP advertise templates that support the MSS-clamp bundle.
  const BGP_ADVERTISE_ADD = "bgp_advertise_add";
  const BGP_ADVERTISE_REMOVE = "bgp_advertise_remove";

  useEffect(() => {
    api.templates
      .list()
      .then((ts) => setAllTemplates(ts.filter((t) => t.provider_type === "device_cli" && t.enabled)))
      .catch(() => setAllTemplates([]));
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]));
  }, []);

  // Per-device inventory needed by the bulk form: announced prefixes (the
  // multi-select) and interfaces (the MSS bundle selector).
  useEffect(() => {
    let cancelled = false;
    for (const id of deviceIds) {
      api.devices
        .bgpNetworks(id)
        .then((ns) => {
          if (!cancelled) setNetworksByDevice((p) => ({ ...p, [id]: ns.map((n) => n.prefix) }));
        })
        .catch(() => {
          if (!cancelled) setNetworksByDevice((p) => ({ ...p, [id]: [] }));
        });
      api.devices
        .interfaces(id)
        .then((ifs) => {
          if (!cancelled)
            setIfacesByDevice((p) => ({
              ...p,
              [id]: ifs.map((i) => ({ id: i.id, if_name: i.if_name, if_alias: i.if_alias })),
            }));
        })
        .catch(() => {
          if (!cancelled) setIfacesByDevice((p) => ({ ...p, [id]: [] }));
        });
    }
    return () => {
      cancelled = true;
    };
  }, [deviceIds]);

  // Templates shown in the dropdown: hide MSS templates (they're only used via the bundle).
  const visibleTemplates = allTemplates.filter((t) => !MSS_TEMPLATE_NAMES.includes(t.name));

  const template = allTemplates.find((t) => String(t.id) === templateId) ?? null;
  const schema = template?.parameter_schema ?? {};

  // Is the selected template a host-targeting blackhole/null-route?
  const isHostTargetTemplate =
    template !== null && HOST_TARGET_TEMPLATES.includes(template.name);

  // Is the selected template a BGP advertise (add or remove)?
  const isBgpAdvertise =
    template !== null &&
    (template.name === BGP_ADVERTISE_ADD || template.name === BGP_ADVERTISE_REMOVE);

  // For host-targeting templates on a flow rule: always auto-detect (no prefix input).
  const autoDetectMode = isHostTargetTemplate && isFlowRule;

  /** The one parameter fed from the router's announced prefixes; it becomes the
   *  multi-select that drives the routers x prefixes product. */
  const prefixParam =
    Object.entries(schema).find(([, spec]) => spec.source === "announced_prefix")?.[0] ?? null;
  const bulkPrefixParam = autoDetectMode ? null : prefixParam;

  // Params rendered by the shared schema form: skip the auto-target prefix and
  // the bulk-selected prefix (both are handled here).
  const omitFromParamsForm = new Set<string>();
  if (autoDetectMode) omitFromParamsForm.add("prefix");
  if (bulkPrefixParam) omitFromParamsForm.add(bulkPrefixParam);

  /** Union of announced prefixes across the selected routers, with the routers
   *  that did NOT announce each one — the backend validates per device, so a
   *  prefix missing on one router makes that action fail. */
  const prefixChoices = (() => {
    const seen = new Map<string, number[]>();
    for (const id of deviceIds) {
      for (const p of networksByDevice[id] ?? []) {
        if (!seen.has(p)) seen.set(p, []);
        seen.get(p)!.push(id);
      }
    }
    return Array.from(seen.entries())
      .map(([prefix, onDevices]) => ({
        prefix,
        missingOn: deviceIds.filter((d) => !onDevices.includes(d)),
      }))
      .sort((a, b) => a.prefix.localeCompare(b.prefix));
  })();

  const actions = current.actions ?? [];
  /** Next free rank. Order is a safety property — additive actions (advertise)
   *  must be able to run BEFORE destructive ones (withdraw / shutdown) — so new
   *  actions append instead of all collapsing onto position 0. */
  const nextPosition =
    actions.length === 0 ? 0 : Math.max(...actions.map((a) => a.position ?? 0)) + 1;

  function toggleDevice(id: number) {
    if (!deviceIds.includes(id)) {
      setDeviceIds((prev) => [...prev, id]);
      return;
    }
    // Unchecking a router DROPS its parameter set. Keeping it would let a
    // re-check silently restore values discovered earlier — e.g. a prefix-list
    // or neighbor that no longer exists on that router — and those values are
    // validated per device, so they must be re-derived from live inventory.
    setDeviceIds((prev) => prev.filter((d) => d !== id));
    setValuesByDevice(({ [id]: _dropped, ...rest }) => rest);
    setMssIfaceByDevice(({ [id]: _dropped, ...rest }) => rest);
  }

  function setDeviceValues(id: number, next: Record<string, string>) {
    setValuesByDevice((prev) => ({ ...prev, [id]: next }));
  }

  function resetAddForm() {
    setPendingRetry(null);
    setTemplateId("");
    setDeviceIds([]);
    setValuesByDevice({});
    setSelectedPrefixes([]);
    setMssBundle(false);
    setMssIfaceByDevice({});
    setMssValue("1436");
  }

  /** Re-read the rule so the list always shows what is really persisted, never
   *  what this component hoped happened (audit finding FE-06). */
  async function reconcile(fallback: Rule) {
    try {
      const fresh = await api.rules.get(current.id);
      setCurrent(fresh);
      onChanged(fresh);
    } catch {
      setCurrent(fallback);
      onChanged(fallback);
    }
  }

  /** Build the routers x prefixes product for the current form. */
  function buildPlan(): PlannedAction[] | string {
    if (!template) return "Pick a template and at least one target router.";
    if (deviceIds.length === 0) return "Pick at least one target router.";
    if (bulkPrefixParam && selectedPrefixes.length === 0)
      return "Pick at least one prefix (each selected prefix becomes its own action).";

    const mssTemplateName =
      template.name === BGP_ADVERTISE_ADD
        ? "iface_tcp_adjust_mss"
        : "iface_tcp_adjust_mss_remove";
    const mssTemplate = allTemplates.find((t) => t.name === mssTemplateName) ?? null;
    if (isBgpAdvertise && mssBundle && !mssTemplate)
      return `MSS template "${mssTemplateName}" not found. Enable it in Templates.`;

    const plan: PlannedAction[] = [];
    let pos = nextPosition;
    for (const deviceId of deviceIds) {
      const deviceName = devices.find((d) => d.id === deviceId)?.name ?? `device ${deviceId}`;
      const base: Record<string, unknown> = {};
      const raw = valuesByDevice[deviceId] ?? {};
      for (const name of Object.keys(schema)) {
        if (omitFromParamsForm.has(name)) continue;
        if (raw[name]) base[name] = raw[name];
      }
      const prefixes: (string | null)[] = bulkPrefixParam ? selectedPrefixes : [null];
      for (const prefix of prefixes) {
        const params = { ...base };
        if (bulkPrefixParam && prefix !== null) params[bulkPrefixParam] = prefix;
        plan.push({
          reroute_template_id: template.id,
          device_id: deviceId,
          params,
          position: pos++,
          ...(autoDetectMode ? { auto_target: "flow_dst_host" } : {}),
          label: `${templateLabel(template)} on ${deviceName}${prefix ? ` · ${prefix}` : ""}`,
        });
      }
      // The MSS clamp is an interface-level action, so it is attached ONCE per
      // router, right after that router's BGP actions.
      if (isBgpAdvertise && mssBundle && mssTemplate) {
        const mssParams: Record<string, unknown> = { interface: mssIfaceByDevice[deviceId] ?? "" };
        if (template.name === BGP_ADVERTISE_ADD && mssValue) mssParams.mss = mssValue;
        plan.push({
          reroute_template_id: mssTemplate.id,
          device_id: deviceId,
          params: mssParams,
          position: pos++,
          label: `${templateLabel(mssTemplate)} on ${deviceName}`,
        });
      }
    }
    return plan;
  }

  async function add(retry?: PlannedAction[]) {
    // A retry re-sends ONLY what did not land, re-ranked from the current tail
    // of the (re-read) action list so it cannot collide with what is saved.
    const plan = retry
      ? retry.map((item, i) => ({ ...item, position: nextPosition + i }))
      : buildPlan();
    if (typeof plan === "string") {
      setError(plan);
      return;
    }
    setBusy(true);
    setError(null);
    setNotice(null);
    let written = 0;
    let latest = current;
    try {
      // Sequential, one commit each: the API has no batch endpoint. If one write
      // fails we stop immediately and report exactly how many landed — a silent
      // partial rule is how a mitigation ends up half-configured.
      for (const item of plan) {
        const { label: _label, ...body } = item;
        latest = await api.rules.addAction(current.id, body);
        written++;
      }
      setCurrent(latest);
      onChanged(latest);
      setPendingRetry(null);
      resetAddForm();
      setNotice(
        `Added ${plan.length} action${plan.length === 1 ? "" : "s"} at position ${nextPosition}+.`,
      );
    } catch (e) {
      const failed = plan[written];
      const remaining = plan.slice(written);
      // Disarm the full plan: pressing Add again must NOT re-send the actions
      // that already succeeded. Only the remainder stays queued.
      setPendingRetry({ items: remaining, signature: formSignature });
      setError(
        `Added ${written} of ${plan.length} action(s), then failed on "${failed?.label ?? "next action"}": ` +
          `${e instanceof ApiError ? e.message : "request failed"}. The list above is the real saved state — ` +
          `the actions already written were NOT rolled back. Use "Retry remaining ${remaining.length}" ` +
          `to finish; editing the form starts a fresh plan.`,
      );
      await reconcile(latest);
    } finally {
      setBusy(false);
    }
  }

  async function remove(actionId: number) {
    try {
      const updated = await api.rules.removeAction(current.id, actionId);
      setCurrent(updated);
      onChanged(updated);
    } catch {
      /* ignore */
    }
  }

  /**
   * Move one action up/down. The whole order is renumbered server-side in one
   * transaction, so a reorder cannot lose an action the way a delete-and-re-add
   * could. On failure the rule is re-read, so the list is always the persisted
   * truth rather than an optimistic guess.
   */
  async function move(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= actions.length || busy) return;
    const desired = [...actions];
    const [moved] = desired.splice(index, 1);
    desired.splice(target, 0, moved);

    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      await api.rules.reorderActions(
        current.id,
        desired.map((a) => a.id),
      );
      const latest = await api.rules.get(current.id);
      setCurrent(latest);
      onChanged(latest);
    } catch (e) {
      setError(
        `Reorder failed: ${e instanceof ApiError ? e.message : "request failed"}. ` +
          `The list above is the real saved state.`,
      );
      await reconcile(current);
    } finally {
      setBusy(false);
    }
  }

  async function toggleAuto() {
    try {
      const updated = await api.rules.update(current.id, {
        automatic_reroute_enabled: !current.automatic_reroute_enabled,
      });
      setCurrent(updated);
      onChanged(updated);
    } catch {
      /* ignore */
    }
  }

  async function toggleManualApply() {
    try {
      const updated = await api.rules.update(current.id, {
        manual_apply_enabled: !current.manual_apply_enabled,
      });
      setCurrent(updated);
      onChanged(updated);
    } catch {
      /* ignore */
    }
  }

  /** Identity of the current add form. A retry is only offered while the form
   *  is byte-for-byte the one that failed; any edit falls back to a normal add. */
  const formSignature = JSON.stringify([
    templateId,
    deviceIds,
    valuesByDevice,
    selectedPrefixes,
    mssBundle,
    mssIfaceByDevice,
    mssValue,
  ]);
  const retryItems =
    pendingRetry && pendingRetry.signature === formSignature ? pendingRetry.items : null;

  const plannedCount = (() => {
    if (!template || deviceIds.length === 0) return 0;
    const prefixes = bulkPrefixParam ? selectedPrefixes.length : 1;
    if (prefixes === 0) return 0;
    return deviceIds.length * prefixes + (isBgpAdvertise && mssBundle ? deviceIds.length : 0);
  })();

  return (
    <Dialog open onOpenChange={(v) => !v && !busy && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Mitigation actions — {current.name}</DialogTitle>
          <DialogDescription>
            When this rule fires (its sliding window holds), these mitigations run
            on the selected routers, <strong>in the order shown</strong>. Observe
            mode always renders a plan only.
          </DialogDescription>
        </DialogHeader>

        {/* Auto vs manual */}
        <div className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2">
          <div className="text-sm">
            <div className="font-medium">Run automatically when fired</div>
            <div className="text-xs text-muted-foreground">
              In <strong>enforce</strong> mode, execute these actions the moment
              the rule fires (gated by device locks &amp; cooldowns). In observe
              mode nothing runs. Off = the operator runs them manually.
            </div>
          </div>
          <Switch
            checked={current.automatic_reroute_enabled}
            onCheckedChange={() => void toggleAuto()}
            disabled={actions.length === 0}
            aria-label="Toggle automatic execution"
            title={
              actions.length === 0
                ? "Attach an action first"
                : "Run these actions automatically when the rule fires (enforce mode only)"
            }
          />
        </div>

        {/* Allow manual apply */}
        <div className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2">
          <div className="text-sm">
            <div className="font-medium">Allow manual apply</div>
            <div className="text-xs text-muted-foreground">
              Operators can manually apply this rule's actions from a firing alert.
              Independent of automatic execution; still blocked in observe mode
              and gated by the manual-reroute permission, locks and cooldowns.
            </div>
          </div>
          <Switch
            checked={current.manual_apply_enabled}
            onCheckedChange={() => void toggleManualApply()}
            disabled={actions.length === 0}
            aria-label="Toggle manual apply"
            title={
              actions.length === 0
                ? "Attach an action first"
                : "Allow operators to manually apply this rule's actions from a firing alert"
            }
          />
        </div>

        {/* Existing actions, in execution order */}
        <div className="space-y-2">
          {actions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No actions attached yet.</p>
          ) : (
            <>
              <div className="flex items-start gap-2 rounded-md border border-border bg-muted/30 px-3 py-2">
                <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">
                  Execution order matters: put additive actions (advertise to a
                  scrubber) <strong>before</strong> destructive ones (withdraw from
                  an upstream, shut an interface), so an abort never leaves a
                  black-hole. Reordering rewrites the affected actions (delete +
                  re-add) because the API has no position-update endpoint.
                </p>
              </div>
              {actions.map((a, i) => (
                <div
                  key={a.id}
                  className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-sm"
                >
                  <span
                    className="w-8 shrink-0 text-xs tabular-nums text-muted-foreground"
                    title={`execution rank ${a.position ?? 0}`}
                  >
                    {i + 1}.
                  </span>
                  <span className="font-medium">{templateLabelFrom(a.template_display_name, a.template_name)}</span>
                  <span className="text-muted-foreground">on</span>
                  <span className="font-medium">{a.device_name}</span>
                  {(() => {
                    const dev = devices.find((d) => d.id === a.device_id);
                    const auto = dev ? automationStatus(dev) : null;
                    return auto ? (
                      <Badge
                        variant="outline"
                        className={
                          auto.tone === "bad"
                            ? "text-[10px] border-red-400 text-red-700 dark:text-red-400"
                            : "text-[10px] border-amber-400 text-amber-700 dark:text-amber-400"
                        }
                        title="Automatic mitigation on this device is currently held (SSH unhealthy or stabilizing). Detection still fires and alerts; a manual reroute may still be allowed."
                      >
                        {auto.label}
                      </Badge>
                    ) : null;
                  })()}
                  {a.auto_target === "flow_dst_host" ? (
                    <Badge
                      variant="outline"
                      className="text-[10px] border-amber-400 text-amber-700 dark:text-amber-400"
                      title="Target resolved at mitigation time: top attacked destination IP from this rule's flows, null-routed as /32 or /128"
                    >
                      target: attacked dst IP (auto /32·/128)
                    </Badge>
                  ) : (
                    <span className="text-xs text-muted-foreground">
                      {Object.entries(a.params ?? {})
                        .map(([k, v]) => `${k}=${String(v)}`)
                        .join(", ")}
                    </span>
                  )}
                  {/* Show non-prefix params even when auto-targeting (e.g. blackhole tag) */}
                  {a.auto_target === "flow_dst_host" &&
                    Object.entries(a.params ?? {}).filter(([k]) => k !== "prefix").length > 0 && (
                      <span className="text-xs text-muted-foreground">
                        {Object.entries(a.params ?? {})
                          .filter(([k]) => k !== "prefix")
                          .map(([k, v]) => `${k}=${String(v)}`)
                          .join(", ")}
                      </span>
                    )}
                  <span className="flex-1" />
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => void move(i, -1)}
                    disabled={busy || i === 0}
                    title="Run earlier"
                  >
                    <ChevronUp className="size-4" />
                    <span className="sr-only">Move up</span>
                  </Button>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    onClick={() => void move(i, 1)}
                    disabled={busy || i === actions.length - 1}
                    title="Run later"
                  >
                    <ChevronDown className="size-4" />
                    <span className="sr-only">Move down</span>
                  </Button>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    className="text-destructive hover:text-destructive"
                    onClick={() => void remove(a.id)}
                    disabled={busy}
                    title="Remove action"
                  >
                    <X className="size-4" />
                  </Button>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Add actions (bulk: routers x prefixes) */}
        <div className="space-y-3 rounded-md border border-dashed border-border p-3">
          <label className="block space-y-1 text-sm font-medium">
            Template
            <select
              className={inputClass}
              value={templateId}
              onChange={(e) => {
                setTemplateId(e.target.value);
                setValuesByDevice({});
                setSelectedPrefixes([]);
                setMssBundle(false);
                setMssIfaceByDevice({});
                setMssValue("1436");
              }}
            >
              <option value="">Select template…</option>
              {visibleTemplates.map((t) => (
                <option key={t.id} value={t.id}>
                  {templateLabel(t)}
                </option>
              ))}
            </select>
          </label>

          {/* Target routers — multi-select */}
          <div className="space-y-1 text-sm font-medium">
            Target routers
            <div className="max-h-36 space-y-1 overflow-y-auto rounded-md border border-input p-2">
              {devices.length === 0 ? (
                <p className="text-xs font-normal text-muted-foreground">No devices enrolled.</p>
              ) : (
                devices.map((d) => (
                  <label key={d.id} className="flex items-center gap-2 text-sm font-normal">
                    <input
                      type="checkbox"
                      className="h-4 w-4 rounded border-border"
                      checked={deviceIds.includes(d.id)}
                      onChange={() => toggleDevice(d.id)}
                    />
                    {d.name}
                  </label>
                ))
              )}
            </div>
            <p className="text-xs font-normal text-muted-foreground">
              Every checked router gets the same action set. Neighbour,
              prefix-list and interface values are discovered per router, so they
              are asked for once per router below.
            </p>
          </div>

          {/* Auto-detect note for flow-rule host-targeting templates */}
          {autoDetectMode && (
            <div className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 dark:border-amber-700 dark:bg-amber-950/30">
              <Info className="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-400" />
              <p className="text-xs text-amber-800 dark:text-amber-300">
                Auto-detects the attacked destination /32&middot;/128 from this rule's flows.
                The backend resolves the victim host at mitigation time — no prefix input needed.
              </p>
            </div>
          )}

          {/* Normal prefix-input note for host-targeting templates on non-flow rules */}
          {isHostTargetTemplate && !isFlowRule && (
            <p className="text-xs text-muted-foreground">
              Manual target: a prefix you choose (down to /8 for IPv4, /29 for IPv6).
              The backend enforces this bound.
            </p>
          )}

          {/* Announced prefixes — multi-select, one action per prefix per router */}
          {template && bulkPrefixParam && (
            <div className="space-y-1 text-sm font-medium">
              {schema[bulkPrefixParam]?.label ?? bulkPrefixParam}{" "}
              <span className="font-normal text-muted-foreground">
                (multi-select — one action per prefix, per router)
              </span>
              <div className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-input p-2">
                {deviceIds.length === 0 ? (
                  <p className="text-xs font-normal text-muted-foreground">Pick a router first.</p>
                ) : prefixChoices.length === 0 ? (
                  <p className="text-xs font-normal text-muted-foreground">
                    No prefixes discovered on the selected router(s).
                  </p>
                ) : (
                  prefixChoices.map((c) => (
                    <label key={c.prefix} className="flex items-center gap-2 text-sm font-normal">
                      <input
                        type="checkbox"
                        className="h-4 w-4 rounded border-border"
                        checked={selectedPrefixes.includes(c.prefix)}
                        onChange={() =>
                          setSelectedPrefixes((prev) =>
                            prev.includes(c.prefix)
                              ? prev.filter((p) => p !== c.prefix)
                              : [...prev, c.prefix],
                          )
                        }
                      />
                      <span className="font-mono text-xs">{c.prefix}</span>
                      {c.missingOn.length > 0 && (
                        <span className="text-[11px] text-amber-700 dark:text-amber-400">
                          not announced on{" "}
                          {c.missingOn
                            .map((id) => devices.find((d) => d.id === id)?.name ?? `#${id}`)
                            .join(", ")}{" "}
                          — that action will be refused
                        </span>
                      )}
                    </label>
                  ))
                )}
              </div>
            </div>
          )}

          {/* Per-router parameters (inventory is validated per device) */}
          {template &&
            deviceIds.map((id) => {
              const dev = devices.find((d) => d.id === id);
              const hasFormParams = Object.keys(schema).some((n) => !omitFromParamsForm.has(n));
              if (!hasFormParams && !(isBgpAdvertise && mssBundle)) return null;
              return (
                <div key={id} className="space-y-2 rounded-md border border-border p-3">
                  <div className="text-sm font-medium">{dev?.name ?? `device ${id}`}</div>
                  {hasFormParams && (
                    <ActionParamsForm
                      schema={schema}
                      deviceId={id}
                      values={valuesByDevice[id] ?? {}}
                      onChange={(next) => setDeviceValues(id, next)}
                      omitParams={omitFromParamsForm}
                    />
                  )}
                  {isBgpAdvertise && mssBundle && (
                    <label className="block space-y-1 text-sm font-medium">
                      MSS-clamp interface
                      <select
                        className={inputClass}
                        value={mssIfaceByDevice[id] ?? ""}
                        onChange={(e) =>
                          setMssIfaceByDevice((p) => ({ ...p, [id]: e.target.value }))
                        }
                      >
                        <option value="">
                          {(ifacesByDevice[id] ?? []).length
                            ? "Select interface…"
                            : "no interfaces discovered"}
                        </option>
                        {(ifacesByDevice[id] ?? []).map((i) => (
                          <option key={i.id} value={i.if_name}>
                            {i.if_name}
                            {i.if_alias ? ` · ${i.if_alias}` : ""}
                          </option>
                        ))}
                      </select>
                    </label>
                  )}
                </div>
              );
            })}

          {/* BGP Advertise MSS-clamp bundle (rule editor only) */}
          {isBgpAdvertise && template && (
            <div className="space-y-2 rounded-md border border-border bg-muted/30 px-3 py-2">
              <div className="flex items-center gap-3">
                <input
                  type="checkbox"
                  id="mss-bundle-toggle"
                  checked={mssBundle}
                  onChange={(e) => {
                    setMssBundle(e.target.checked);
                    if (!e.target.checked) {
                      setMssIfaceByDevice({});
                      setMssValue("1436");
                    }
                  }}
                  className="h-4 w-4 rounded border-border"
                />
                <Label htmlFor="mss-bundle-toggle" className="cursor-pointer text-sm font-medium">
                  Also clamp TCP MSS on an interface
                </Label>
              </div>
              {mssBundle && (
                <div className="grid gap-3 pl-7 sm:grid-cols-2">
                  {template.name === BGP_ADVERTISE_ADD && (
                    <label className="block space-y-1 text-sm font-medium">
                      MSS value (bytes)
                      <input
                        className={inputClass}
                        type="number"
                        min={64}
                        max={9000}
                        value={mssValue}
                        onChange={(e) => setMssValue(e.target.value)}
                        placeholder="1436"
                      />
                    </label>
                  )}
                  <p className="col-span-2 pl-0 text-xs text-muted-foreground">
                    Attaches one{" "}
                    <strong>
                      {template.name === BGP_ADVERTISE_ADD
                        ? "TCP MSS clamp"
                        : "TCP MSS clamp remove"}
                    </strong>{" "}
                    action per selected router, immediately after that router's BGP
                    actions. Pick the interface in each router's block above.
                  </p>
                </div>
              )}
            </div>
          )}

          {error && (
            <div
              className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}
          {notice && !error && (
            <p className="text-sm text-emerald-700 dark:text-emerald-400">{notice}</p>
          )}
          <Button
            size="sm"
            onClick={() => void add(retryItems ?? undefined)}
            disabled={busy || (retryItems === null && plannedCount === 0)}
          >
            <Plus className="size-4" />
            {busy
              ? "Adding…"
              : retryItems
                ? `Retry remaining ${retryItems.length}`
                : plannedCount > 1
                  ? `Add ${plannedCount} actions`
                  : "Add action"}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";



/** Human-readable condition string: "rx_bps > 8000000000" */
function conditionLabel(rule: Rule): string {
  return `${metricLabel(rule.metric)} ${rule.operator} ${rule.threshold_value.toLocaleString()}`;
}

/** Format a metric value with its natural unit. */
function fmtMetric(metric: string, v: number): string {
  if (metric.includes("util_percent")) return `${v.toFixed(1)}%`;
  if (metric.includes("pps")) return `${Math.round(v).toLocaleString()} pps`;
  if (metric.includes("bps")) {
    const units = ["bps", "Kbps", "Mbps", "Gbps", "Tbps"];
    let n = v;
    let i = 0;
    while (n >= 1000 && i < units.length - 1) {
      n /= 1000;
      i++;
    }
    return `${n.toFixed(n < 10 && i > 0 ? 2 : 0)} ${units[i]}`;
  }
  if (metric === "oper_status") return v >= 1 ? "up" : "down";
  return v.toLocaleString();
}

/** Is the current value breaching the rule's condition right now? */
function breaches(op: string, v: number, t: number): boolean {
  switch (op) {
    case ">":
      return v > t;
    case ">=":
      return v >= t;
    case "<":
      return v < t;
    case "<=":
      return v <= t;
    case "==":
      return v === t;
    case "!=":
      return v !== t;
    default:
      return false;
  }
}

/** The active persistence control for the rule's metric family. */
function persistenceLabel(rule: Rule): string {
  if (isFlowMetric(rule.metric)) {
    if (rule.duration_seconds <= 0) return "immediate";
    const m = rule.duration_seconds / 60;
    return `${m.toLocaleString(undefined, { maximumFractionDigits: 1 })} min window`;
  }
  return rule.consecutive_samples > 0 ? `${rule.consecutive_samples} samples` : "immediate";
}

/** Live progression toward firing: consecutive samples (SNMP) or minutes held
 *  (flows). A single sample crossing back resets this to zero, server-side. */
function RuleProgress({ rule }: { rule: Rule }) {
  const state = rule.current_state;
  if (state !== "matching" && state !== "firing") return null;
  const cls = state === "firing" ? "text-red-600 dark:text-red-400" : "text-amber-600 dark:text-amber-400";

  let label: string;
  if (isFlowMetric(rule.metric)) {
    const heldMin = rule.first_matched_at
      ? (Date.now() - new Date(rule.first_matched_at).getTime()) / 60000
      : 0;
    const target = rule.duration_seconds / 60;
    label =
      state === "firing"
        ? `firing · ${heldMin.toFixed(1)} min`
        : `held ${heldMin.toFixed(1)} / ${target.toFixed(1)} min`;
  } else {
    const n = rule.consecutive_match_count ?? 0;
    label = state === "firing" ? `firing · ${n} samples` : `${n} / ${rule.consecutive_samples} samples`;
  }
  return <span className={`text-[11px] font-medium ${cls}`}>{label}</span>;
}

/** Colored live status: current value, above/below the threshold, breach = red. */
function RuleStatus({ rule }: { rule: Rule }) {
  const v = rule.current_value;
  if (v === null || v === undefined) {
    return <span className="text-[11px] text-muted-foreground">no data yet</span>;
  }
  const stale =
    rule.last_evaluated_at != null &&
    Date.now() - new Date(rule.last_evaluated_at).getTime() > 180_000;
  const breaching = breaches(rule.operator, v, rule.threshold_value);
  const above = v > rule.threshold_value;
  const Arrow = above ? ArrowUp : ArrowDown;
  const dir = above ? "above" : v < rule.threshold_value ? "below" : "at";
  const cls = stale ? "bg-muted text-muted-foreground" : toneClass(breaching ? "bad" : "good");
  return (
    <span
      className={`inline-flex w-fit items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-medium ${cls}`}
      title={`last evaluated ${rule.last_evaluated_at ? new Date(rule.last_evaluated_at).toLocaleString() : "—"}`}
    >
      <Arrow className="size-3" />
      now {fmtMetric(rule.metric, v)} · {stale ? "stale" : dir}
    </span>
  );
}

type SortDir = "asc" | "desc";

export default function Rules() {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission("edit_rules");
  const canApply = hasPermission("trigger_manual_reroute");

  const [rules, setRules] = useState<Rule[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [manageRule, setManageRule] = useState<Rule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null);
  const [editRule, setEditRule] = useState<Rule | null>(null);
  // Firing rule the operator chose to mitigate from this page (same guarded
  // preview -> token -> execute dialog as Dashboard and Mitigations).
  const [applyRule, setApplyRule] = useState<Rule | null>(null);

  const [nameSortDir, setNameSortDir] = useState<SortDir | null>(null);

  function loadRules() {
    setLoading(true);
    api.rules
      .list()
      .then(setRules)
      .catch(() => setRules([]))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadRules();
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]));
    // Operating mode drives the mitigation dialog's copy (observe = nothing runs).
    api.settings
      .get()
      .then(setSettings)
      .catch(() => setSettings(null));
  }, []);

  // Quietly refresh the live above/below status every 20s (no loading flicker).
  useEffect(() => {
    const t = setInterval(() => {
      api.rules
        .list()
        .then(setRules)
        .catch(() => {});
    }, 20000);
    return () => clearInterval(t);
  }, []);

  async function clearRule(rule: Rule) {
    try {
      const res = await api.rules.clear(rule.id);
      if (res.cleared) toast.success(`Cleared "${rule.name}"`);
      loadRules();
    } catch {
      toast.error("Failed to clear rule");
    }
  }

  async function toggleRule(rule: Rule) {
    try {
      const updated = await api.rules.update(rule.id, {
        enabled: !rule.enabled,
      });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch {
      // ignore
    }
  }

  async function deleteRule(rule: Rule) {
    try {
      await api.rules.remove(rule.id);
      setRules((prev) => prev.filter((r) => r.id !== rule.id));
      toast.success(`Deleted rule "${rule.name}"`);
    } catch {
      toast.error("Failed to delete rule");
    }
  }

  function toggleNameSort() {
    setNameSortDir((d) => {
      if (d === null || d === "desc") return "asc";
      return "desc";
    });
  }

  const sorted = nameSortDir
    ? [...rules].sort((a, b) => {
        const cmp = a.name.localeCompare(b.name);
        return nameSortDir === "asc" ? cmp : -cmp;
      })
    : rules;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Threshold rules</h1>
        <Button variant="outline" size="sm" onClick={() => setAddOpen(true)} disabled={!canEdit}>
          Add rule
        </Button>
      </div>


      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Rules</CardTitle>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {loading ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">Loading…</p>
          ) : rules.length === 0 ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">
              No rules yet. Add a threshold rule to start monitoring interfaces.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead
                    className="cursor-pointer select-none pl-6"
                    onClick={toggleNameSort}
                  >
                    Name
                    {nameSortDir === null ? (
                      <ChevronsUpDown className="ml-1 inline-block size-3.5 text-muted-foreground" />
                    ) : nameSortDir === "asc" ? (
                      <ArrowUp className="ml-1 inline-block size-3.5" />
                    ) : (
                      <ArrowDown className="ml-1 inline-block size-3.5" />
                    )}
                  </TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Condition</TableHead>
                  <TableHead>Persistence</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Enabled</TableHead>
                  <TableHead>Mitigation</TableHead>
                  <TableHead className="pr-6 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sorted.map((rule) => (
                  <TableRow key={rule.id} className="hover:bg-muted/50">
                    {/* Name + icon */}
                    <TableCell className="pl-6">
                      <div className="flex items-center gap-2">
                        <SlidersHorizontal className="size-4 shrink-0 text-muted-foreground" />
                        <span className="font-medium">{rule.name}</span>
                      </div>
                    </TableCell>

                    {/* Target — interface name (+ device) */}
                    <TableCell className="text-xs">
                      <div className="flex flex-col">
                        <span className="font-mono">
                          {rule.interface_name ||
                            (rule.interface_id ? `interface #${rule.interface_id}` : "interface")}
                        </span>
                        {rule.device_name && (
                          <span className="text-[11px] text-muted-foreground">
                            {rule.device_name}
                          </span>
                        )}
                      </div>
                    </TableCell>

                    {/* Condition + live above/below status */}
                    <TableCell>
                      <div className="flex flex-col gap-1">
                        <code className="text-xs">{conditionLabel(rule)}</code>
                        <RuleStatus rule={rule} />
                      </div>
                    </TableCell>

                    {/* Persistence (per family) + live progression toward firing */}
                    <TableCell className="text-xs text-muted-foreground">
                      <div className="flex flex-col gap-1">
                        <span>{persistenceLabel(rule)}</span>
                        <RuleProgress rule={rule} />
                      </div>
                    </TableCell>

                    {/* Severity badge */}
                    <TableCell>
                      <SeverityBadge severity={rule.severity} />
                    </TableCell>

                    {/* Enabled — green/check on, red/X off (disabled when read-only) */}
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <Switch
                        checked={rule.enabled}
                        onCheckedChange={() => void toggleRule(rule)}
                        disabled={!canEdit}
                        aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                        title={
                          canEdit
                            ? rule.enabled
                              ? "Enabled — click to disable"
                              : "Disabled — click to enable"
                            : rule.enabled
                              ? "Enabled"
                              : "Disabled"
                        }
                      />
                    </TableCell>

                    {/* Mitigation — attached reroute actions + auto/manual */}
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1.5">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 gap-1.5"
                          onClick={() => setManageRule(rule)}
                          disabled={!canEdit}
                          title={canEdit ? "Manage mitigation actions" : "Requires edit_rules"}
                        >
                          <Workflow className="size-3.5 text-muted-foreground" />
                          {rule.action_count
                            ? `${rule.action_count} action${rule.action_count > 1 ? "s" : ""}`
                            : "none"}
                        </Button>
                        {rule.action_count ? (
                          <>
                            <Badge
                              variant={rule.automatic_reroute_enabled ? "destructive" : "outline"}
                              className="text-[10px]"
                              title={
                                rule.automatic_reroute_enabled
                                  ? "Runs automatically in enforce mode"
                                  : "Renders a plan only; run manually"
                              }
                            >
                              {rule.automatic_reroute_enabled ? "auto" : "manual"}
                            </Badge>
                            {rule.manual_apply_enabled && (
                              <Badge
                                variant="outline"
                                className="text-[10px] text-sky-700 dark:text-sky-400"
                                title="Operators can manually apply this rule's actions from a firing alert"
                              >
                                apply
                              </Badge>
                            )}
                          </>
                        ) : null}
                      </div>
                    </TableCell>

                    {/* Actions */}
                    <TableCell
                      className="pr-6 text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1">
                        {canApply &&
                          rule.current_state === "firing" &&
                          rule.manual_apply_enabled &&
                          (rule.action_count ?? 0) > 0 && (
                            <Button
                              size="sm"
                              variant="destructive"
                              className="h-7"
                              title="Apply this rule's configured actions (exact preview first; observe mode executes nothing)"
                              onClick={() => setApplyRule(rule)}
                            >
                              Mitigate
                            </Button>
                          )}
                        {canEdit && rule.current_state === "firing" && (
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7"
                            title="Clear this firing rule (resets detection state; executes nothing)"
                            onClick={() => void clearRule(rule)}
                          >
                            Clear
                          </Button>
                        )}
                        {canEdit && (
                          <>
                            <Button
                              size="icon-sm"
                              variant="ghost"
                              title="Edit rule"
                              onClick={() => setEditRule(rule)}
                            >
                              <Pencil className="size-4" />
                              <span className="sr-only">Edit</span>
                            </Button>
                            <Button
                              size="icon-sm"
                              variant="ghost"
                              title="Delete rule"
                              className="text-destructive hover:text-destructive"
                              onClick={() => setDeleteTarget(rule)}
                            >
                              <Trash2 className="size-4" />
                              <span className="sr-only">Delete</span>
                            </Button>
                          </>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {applyRule && (
        <ApplyMitigationDialog
          rule={applyRule}
          operatingMode={settings?.operating_mode ?? "observe"}
          onClose={() => setApplyRule(null)}
          onApplied={() => loadRules()}
        />
      )}

      {manageRule && (
        <RuleActionsDialog
          rule={manageRule}
          onClose={() => setManageRule(null)}
          onChanged={(updated) => {
            setRules((rs) => rs.map((r) => (r.id === updated.id ? updated : r)));
            setManageRule(updated);
          }}
        />
      )}

      {addOpen && (
        <RuleDialog
          devices={devices}
          onClose={() => setAddOpen(false)}
          onSaved={() => loadRules()}
        />
      )}

      {editRule && (
        <RuleDialog
          rule={editRule}
          devices={devices}
          onClose={() => setEditRule(null)}
          onSaved={(updated) =>
            setRules((rs) => rs.map((r) => (r.id === updated.id ? updated : r)))
          }
        />
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onOpenChange={(v) => !v && setDeleteTarget(null)}
        title="Delete rule"
        description={
          <>
            Permanently delete the rule <strong>{deleteTarget?.name}</strong> and its
            attached actions. This cannot be undone.
          </>
        }
        confirmLabel="Delete"
        destructive
        requireText="CONFIRM"
        onConfirm={async () => {
          if (!deleteTarget) return;
          const rule = deleteTarget;
          setDeleteTarget(null);
          await deleteRule(rule);
        }}
      />
    </div>
  );
}
