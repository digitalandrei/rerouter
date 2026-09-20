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
import { useEffect, useRef, useState } from "react";
import {
  SlidersHorizontal,
  Pencil,
  Trash2,
  ArrowUp,
  ArrowDown,
  ChevronsUpDown,
  Workflow,
  Plus,
  Info,
  AlertTriangle,
  ShieldAlert,
  Eye,
  ArrowLeft,
} from "lucide-react";
import { toast } from "sonner";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import {
  api,
  type Rule,
  type RuleAction,
  type Device,
  type Template,
  type SystemSettings,
  type ActionDraft,
  type MitigationPreset,
  ApiError,
} from "@/lib/api";
import { Label } from "@/components/ui/label";
import { ActionParamsForm } from "@/components/action-params-form";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { ApplyMitigationDialog, ApplyResultRow } from "@/components/apply-mitigation-dialog";
import { OrderedActionSetEditor } from "@/components/ordered-action-set-editor";
import { ActionsAndRevert } from "@/components/actions-and-revert";
import { RowActionButton } from "@/components/row-action-button";
import { Switch } from "@/components/ui/switch";
import { SeverityBadge, toneClass } from "@/components/status-badge";
import { RuleDialog } from "./rules/rule-dialog";
import { metricLabel, isFlowMetric } from "./rules/rule-constants";
import { orderTemplatesForChoice, templateGuidance, templateLabel, templateLabelFrom, timeAgo } from "@/lib/labels";
import { useAuth } from "@/lib/auth";
import { expandBulkActions, importActionCopies } from "@/lib/action-sets";
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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
 * - Up/down controls and bulk additions submit the complete ordered set through
 *   one optimistic-revision API call. Validation and persistence are atomic.
 * - Routers and announced prefixes are multi-selects; the UI expands their
 *   cartesian product locally before saving the complete set once.
 */
type PlannedAction = {
  reroute_template_id: number;
  device_id: number;
  params: Record<string, unknown>;
  position: number;
  auto_target?: string | null;
  label: string;
};

function actionDraft(action: RuleAction): ActionDraft {
  return {
    id: action.id,
    reroute_template_id: action.reroute_template_id,
    device_id: action.device_id,
    params: action.params ?? {},
    enabled: action.enabled,
    auto_target: action.auto_target ?? null,
  };
}

/**
 * Inventory drift: when a router's route-map or outbound prefix-list moves
 * under a saved action's parameters, the controller marks that action
 * `drifted` and DISARMS the rule's automatic execution. The rule stays
 * enabled — it keeps detecting and alerting — and re-arming is deliberately
 * never automatic: it goes back through the normal arming gate. So everything
 * below is status, never a control.
 *
 * `automatic_reroute_enabled` is the server's authority on whether the rule is
 * armed right now; a disarm stamp left over from before an operator re-armed
 * must not be rendered as "disarmed". Fields are absent on API builds that
 * predate the check — absent reads as "ok" / "not disarmed".
 */
function autoDisarm(rule: Rule): { at: string; reason: string | null } | null {
  if (rule.automatic_reroute_enabled) return null;
  if (!rule.auto_disarmed_at) return null;
  return { at: rule.auto_disarmed_at, reason: rule.auto_disarmed_reason ?? null };
}

/** Attached actions whose saved params no longer validate against discovered
 *  inventory. Only an explicit "drifted" counts. */
function driftedActions(rule: Rule): RuleAction[] {
  return (rule.actions ?? []).filter((a) => a.inventory_state === "drifted");
}

/** What the disarm actually costs the operator — shown next to every disarm
 *  badge, because the state alone doesn't say what still works. */
const DISARM_CONSEQUENCE =
  "Detection and alerting still run; automatic mitigation does not. " +
  "Manual execution is still possible but will be refused until the parameters are fixed.";

export function RuleActionsDialog({
  rule,
  onClose,
  onChanged,
}: {
  rule: Rule;
  onClose: () => void;
  onChanged: (updated: Rule) => void;
}) {
  const { hasPermission } = useAuth();
  const canEdit = hasPermission("edit_rules");
  const [current, setCurrent] = useState<Rule>(rule);
  const [draftActions, setDraftActions] = useState<RuleAction[]>(rule.actions ?? []);
  const [allTemplates, setAllTemplates] = useState<Template[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [presets, setPresets] = useState<MitigationPreset[]>([]);
  const [presetImportId, setPresetImportId] = useState("");
  const [importMode, setImportMode] = useState<"append" | "replace">("append");
  const [editActionIndex, setEditActionIndex] = useState<number | null>(null);
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
  const [resourcesLoading, setResourcesLoading] = useState(true);
  const [resourcesError, setResourcesError] = useState<string | null>(null);
  /** Set when the operator starts fixing a drifted action: the add form is
   *  primed with that action's template + router and this says what to re-pick. */
  const [fixHint, setFixHint] = useState<string | null>(null);
  const addFormRef = useRef<HTMLDivElement>(null);

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
    let cancelled = false; setResourcesLoading(true);
    Promise.all([api.templates.list(), api.devices.list(), api.mitigationPresets.list()]).then(([templates, loadedDevices, loadedPresets]) => { if (cancelled) return; setAllTemplates(templates.filter((item) => item.provider_type === "device_cli" && item.enabled)); setDevices(loadedDevices); setPresets(loadedPresets.filter((item) => !item.archived_at)); setResourcesError(null); }).catch((cause) => { if (!cancelled) setResourcesError(cause instanceof Error ? cause.message : "Supporting action data unavailable"); }).finally(() => { if (!cancelled) setResourcesLoading(false); });
    return () => { cancelled = true; };
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
  const visibleTemplates = orderTemplatesForChoice(allTemplates.filter((t) => !MSS_TEMPLATE_NAMES.includes(t.name)));

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

  const actions = draftActions;
  const dirty = JSON.stringify(actions.map(actionDraft)) !== JSON.stringify((rule.actions ?? []).map(actionDraft));
  /** Server-reported disarm (null once the rule is armed again). */
  const disarmed = autoDisarm(current);
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

  /** Fixing a drifted action = re-picking its parameters from freshly
   *  discovered inventory. The API has no PATCH on rule_actions, so the fix is
   *  "add the corrected action, then remove the drifted one": this primes the
   *  add form with the same template and router and scrolls to it. The stale
   *  values are deliberately NOT copied — they are exactly what stopped
   *  validating, and inventory params are re-derived per router anyway. */
  function startFix(a: RuleAction) {
    setTemplateId(String(a.reroute_template_id));
    setDeviceIds([a.device_id]);
    setValuesByDevice({});
    setSelectedPrefixes([]);
    setMssBundle(false);
    setMssIfaceByDevice({});
    setMssValue("1436");
    setError(null);
    setNotice(null);
    setFixHint(
      `Re-pick the parameters for “${templateLabelFrom(a.template_display_name, a.template_name)}” ` +
        `on ${a.device_name} from discovered inventory, add it, then remove the drifted action above.`,
    );
    addFormRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function resetAddForm() {
    setFixHint(null);
    setTemplateId("");
    setDeviceIds([]);
    setValuesByDevice({});
    setSelectedPrefixes([]);
    setMssBundle(false);
    setMssIfaceByDevice({});
    setMssValue("1436");
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

    const paramsByDevice = Object.fromEntries(deviceIds.map((id) => [id,
      Object.fromEntries(Object.entries(valuesByDevice[id] ?? {}).filter(([name, value]) => !omitFromParamsForm.has(name) && value)),
    ]));
    const mssParamsByDevice = Object.fromEntries(deviceIds.map((id) => [id, {
      interface: mssIfaceByDevice[id] ?? "",
      ...(template.name === BGP_ADVERTISE_ADD && mssValue ? { mss: mssValue } : {}),
    }]));
    return expandBulkActions({
      templateId: template.id, deviceIds, paramsByDevice,
      prefixParam: bulkPrefixParam, prefixes: selectedPrefixes,
      autoTarget: autoDetectMode ? "flow_dst_host" : null,
      mss: isBgpAdvertise && mssBundle && mssTemplate ? {
        templateId: mssTemplate.id,
        paramsByDevice: mssParamsByDevice,
        placement: template.name === BGP_ADVERTISE_ADD ? "before" : "after",
      } : null,
    }).map((action, index) => ({
      ...action,
      position: nextPosition + index,
      label: `${templateLabel(allTemplates.find((item) => item.id === action.reroute_template_id) ?? template)} on ${devices.find((device) => device.id === action.device_id)?.name ?? `device ${action.device_id}`}`,
    }));
  }

  function add() {
    const plan = buildPlan();
    if (typeof plan === "string") {
      setError(plan);
      return;
    }
    setError(null);
    setNotice(null);
    setDraftActions((existing) => [
          ...existing,
          ...plan.map((item, index) => ({
            id: -(Date.now() + index),
            reroute_template_id: item.reroute_template_id,
            device_id: item.device_id,
            params: item.params,
            enabled: true,
            auto_target: item.auto_target ?? null,
            position: existing.length + index,
            template_name: allTemplates.find((template) => template.id === item.reroute_template_id)?.name ?? "",
            template_display_name: allTemplates.find((template) => template.id === item.reroute_template_id)?.display_name ?? null,
            device_name: devices.find((device) => device.id === item.device_id)?.name ?? `device ${item.device_id}`,
          })),
        ] as RuleAction[]);
      resetAddForm();
      setNotice(
        `Added ${plan.length} draft action${plan.length === 1 ? "" : "s"}. Save the complete set to apply these changes.`,
      );
  }

  function remove(index: number) {
    setDraftActions((existing) => existing.filter((_, itemIndex) => itemIndex !== index));
    setEditActionIndex(null);
  }

  /**
   * Move one action up/down. The whole order is renumbered server-side in one
   * transaction, so a reorder cannot lose an action the way a delete-and-re-add
   * could. On failure the rule is re-read, so the list is always the persisted
   * truth rather than an optimistic guess.
   */
  function move(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= actions.length || busy) return;
    const desired = [...actions];
    const [moved] = desired.splice(index, 1);
    desired.splice(target, 0, moved);

    setDraftActions(desired);
    setEditActionIndex(target);
  }

  function importPreset() {
    const preset = presets.find((item) => String(item.id) === presetImportId);
    if (!preset) return;
    setError(null);
    setNotice(null);
      setDraftActions(importActionCopies(actions.map(actionDraft), preset.actions, importMode).map((action, index) => ({ ...action, id: action.id ?? -(Date.now() + index), position: index, template_name: allTemplates.find((item) => item.id === action.reroute_template_id)?.name ?? "", template_display_name: allTemplates.find((item) => item.id === action.reroute_template_id)?.display_name ?? null, device_name: devices.find((item) => item.id === action.device_id)?.name ?? `device ${action.device_id}` })) as RuleAction[]);
      setPresetImportId("");
      setNotice(
        `Imported a draft copy of “${preset.name}”. Save the complete set when review is finished.`,
      );
  }

  async function saveDraft() {
    setBusy(true); setError(null);
    try {
      const updated = await api.rules.saveActions(current.id, { revision: current.actions_revision ?? 0, actions: actions.map(actionDraft) });
      setCurrent(updated); setDraftActions(updated.actions ?? []); onChanged(updated);
      setNotice("Complete ordered action set saved atomically. Automatic execution was disarmed for review.");
    } catch (cause) { setError(cause instanceof ApiError ? cause.message : "Complete action set could not be saved"); }
    finally { setBusy(false); }
  }

  async function toggleAuto() {
    try {
      const updated = await api.rules.update(current.id, {
        automatic_reroute_enabled: !current.automatic_reroute_enabled,
      });
      setCurrent(updated);
      onChanged(updated);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not change automatic execution");
    }
  }

  async function toggleManualApply() {
    try {
      const updated = await api.rules.update(current.id, {
        manual_apply_enabled: !current.manual_apply_enabled,
      });
      setCurrent(updated);
      onChanged(updated);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not change manual apply");
    }
  }

  const plannedCount = (() => {
    if (!template || deviceIds.length === 0) return 0;
    const prefixes = bulkPrefixParam ? selectedPrefixes.length : 1;
    if (prefixes === 0) return 0;
    return deviceIds.length * prefixes + (isBgpAdvertise && mssBundle ? deviceIds.length : 0);
  })();

  return (
    <Dialog open onOpenChange={(v) => { if (!v && !busy && (!dirty || window.confirm("Discard unsaved action changes?"))) onClose(); }}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Mitigation actions — {current.name}</DialogTitle>
          <DialogDescription>
            When this rule fires (its sliding window holds), these mitigations run
            on the selected routers, <strong>in the order shown</strong>. Observe
            mode disables automatic response; explicit manual runs still require an exact prepared plan.
          </DialogDescription>
        </DialogHeader>
        {resourcesLoading && <p role="status" className="text-sm text-muted-foreground">Loading action templates and router inventory…</p>}
        {resourcesError && <p role="alert" className="text-sm text-destructive">{resourcesError}. Existing saved actions remain visible, but editing is unavailable until this data loads.</p>}
        <fieldset disabled={busy} className="contents">

        {/* Auto-execution disarmed by the controller (inventory drift). Status
            only — re-arming uses the normal switch below, which still goes
            through the arming gate (global enable + step-up re-auth). */}
        {disarmed && (
          <div className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 dark:border-amber-700 dark:bg-amber-950/30">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-400" />
            <div className="space-y-1 text-xs text-amber-800 dark:text-amber-300">
              <div className="font-medium">
                Automatic execution disarmed by the controller — inventory drift,{" "}
                {timeAgo(disarmed.at)}
              </div>
              {disarmed.reason && <div className="break-words">{disarmed.reason}</div>}
              <div>{DISARM_CONSEQUENCE}</div>
              <div>
                Fix the drifted action's parameters below, then re-arm with the
                switch — arming still requires the global enable and step-up re-auth.
              </div>
            </div>
          </div>
        )}

        {/* Auto vs manual */}
        <div className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2">
          <div className="text-sm">
            <div className="font-medium">Run automatically when fired</div>
            <div className="text-xs text-muted-foreground">
              In <strong>enforce</strong> mode, execute these actions the moment
              the rule fires (gated by device locks &amp; cooldowns). In observe
              mode automatic execution is paused. Off = the operator runs them manually.
            </div>
          </div>
          <Switch
            checked={current.automatic_reroute_enabled}
            onCheckedChange={() => void toggleAuto()}
            disabled={!canEdit || actions.length === 0 || dirty}
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
              Operators can manually run this rule's defined actions from its detail page or a firing alert.
              Independent of detection state and automatic execution, and available in Observe after
              an exact preview; still gated by permission, locks and cooldowns.
            </div>
          </div>
          <Switch
            checked={current.manual_apply_enabled}
            onCheckedChange={() => void toggleManualApply()}
            disabled={!canEdit || actions.length === 0 || dirty}
            aria-label="Toggle manual apply"
            title={
              actions.length === 0
                ? "Attach an action first"
                : "Allow operators to manually run this rule's defined actions"
            }
          />
        </div>

        {/* Existing actions, in execution order */}
        <div className="space-y-2">
          <div className="flex items-start gap-2 rounded-md border border-border bg-muted/30 px-3 py-2">
            <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
            <p className="text-xs text-muted-foreground">
              Execution order matters: put additive actions before destructive ones.
              Reorder, add, remove, and import stay in this draft until Save writes the complete set atomically.
            </p>
          </div>
          <OrderedActionSetEditor
            actions={actions.map((action) => ({
              ...actionDraft(action),
              warning:
                action.inventory_state === "drifted"
                  ? action.inventory_drift_reason ?? "Saved parameters no longer match router inventory."
                  : null,
            }))}
            templates={allTemplates}
            devices={devices}
            busy={busy}
            readOnly={!canEdit || Boolean(resourcesError)}
            onMove={canEdit ? (index, delta) => move(index, delta) : undefined}
            onRemove={canEdit ? (index) => remove(index) : undefined}
            selectedIndex={editActionIndex}
            onSelect={canEdit && !resourcesError ? setEditActionIndex : undefined}
            emptyMessage="No actions attached yet. Add actions or import a saved manual mitigation."
          />
          <ActionsAndRevert actions={actions.map(actionDraft)} deviceNames={Object.fromEntries(devices.map((device) => [device.id, device.name]))} />
          {canEdit && editActionIndex !== null && actions[editActionIndex] && (() => {
            const action = actions[editActionIndex];
            const actionTemplate = allTemplates.find((item) => item.id === action.reroute_template_id);
            if (!actionTemplate) return null;
            const omit = action.auto_target === "flow_dst_host" ? new Set(["prefix"]) : undefined;
            const values = Object.fromEntries(Object.entries(action.params ?? {}).map(([key, value]) => [key, String(value)]));
            return <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3">
              <div><div className="text-sm font-medium">Edit action {editActionIndex + 1}</div><p className="text-xs text-muted-foreground">Changing the router clears inventory-bound parameters. Save validates and replaces the complete set atomically.</p></div>
              <label className="block space-y-1 text-sm font-medium">Target router<select className={inputClass} value={action.device_id} onChange={(event) => {
                const next = [...actions]; next[editActionIndex] = { ...action, device_id: Number(event.target.value), params: {} }; setDraftActions(next);
              }}>{devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}</select></label>
              <ActionParamsForm schema={actionTemplate.parameter_schema} deviceId={action.device_id} values={values} omitParams={omit} onChange={(nextValues) => {
                const next = [...actions]; next[editActionIndex] = { ...action, params: Object.fromEntries(Object.entries(nextValues).filter(([, value]) => value.trim() !== "")) }; setDraftActions(next);
              }} />
              <div className="flex justify-end"><Button variant="outline" size="sm" onClick={() => setEditActionIndex(null)}>Done editing step</Button></div>
            </div>;
          })()}
          {driftedActions(current).map((action) => (
            <div key={action.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-amber-400 bg-amber-50 px-3 py-2 text-xs text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">
              <span className="break-words">
                {templateLabelFrom(action.template_display_name, action.template_name)} · last checked {timeAgo(action.inventory_checked_at) || "unknown"}
              </span>
              <Button size="sm" variant="outline" onClick={() => startFix(action)} disabled={busy}>
                Re-pick parameters
              </Button>
            </div>
          ))}
        </div>

        {canEdit && presets.length > 0 && (
          <div className="space-y-3 rounded-md border border-border p-3">
            <div>
              <div className="text-sm font-medium">Import saved manual mitigation</div>
              <p className="text-xs text-muted-foreground">
                Imports an independent copy. Later changes to the saved mitigation do not change this rule.
              </p>
            </div>
            <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_9rem_auto]">
              <select className={inputClass} value={presetImportId} onChange={(event) => setPresetImportId(event.target.value)}>
                <option value="">Select saved mitigation…</option>
                {presets.map((preset) => <option key={preset.id} value={preset.id}>{preset.name} · {preset.actions.length} actions</option>)}
              </select>
              <select className={inputClass} value={importMode} onChange={(event) => setImportMode(event.target.value as "append" | "replace")}>
                <option value="append">Append</option>
                <option value="replace">Replace all</option>
              </select>
              <Button variant="outline" onClick={() => importPreset()} disabled={!canEdit || busy || !presetImportId}>
                Import copy
              </Button>
            </div>
          </div>
        )}

        {/* Add actions (bulk: routers x prefixes) */}
        <div ref={addFormRef} className={canEdit ? "space-y-3 rounded-md border border-dashed border-border p-3" : "hidden"}>
          {/* Where a drifted action gets fixed: same template + router, params
              re-picked from freshly discovered inventory. */}
          {fixHint && (
            <div className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 dark:border-amber-700 dark:bg-amber-950/30">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-400" />
              <p className="text-xs text-amber-800 dark:text-amber-300">{fixHint}</p>
            </div>
          )}
          <label className="block space-y-1 text-sm font-medium">
            Template
            <select
              className={inputClass}
              value={templateId}
              onChange={(e) => {
                setTemplateId(e.target.value);
                setFixHint(null);
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
            {template && templateGuidance(template.name) && <span className="block text-xs font-normal text-muted-foreground">{templateGuidance(template.name)}</span>}
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
            onClick={() => add()}
            disabled={!canEdit || busy || plannedCount === 0}
          >
            <Plus className="size-4" />
            {plannedCount > 1 ? `Add ${plannedCount} actions` : "Add action"}
          </Button>
        </div>
        </fieldset>
        <DialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => { if (!dirty || window.confirm("Discard unsaved action changes?")) onClose(); }}>{canEdit ? "Cancel" : "Close"}</Button>
          {canEdit && <Button disabled={!dirty} loading={busy} loadingLabel="Saving…" onClick={() => void saveDraft()}>Save complete set</Button>}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";



/** Human-readable condition string: "rx_bps > 8000000000" */
function conditionLabel(rule: Rule): string {
  return `${metricLabel(rule.metric)} ${rule.operator} ${fmtMetric(rule.metric, rule.threshold_value)}`;
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

function ClearRuleDialog({ rule, onClose, onChanged }: {
  rule: Rule;
  onClose: () => void;
  onChanged: () => void;
}) {
  const [reason, setReason] = useState("");
  const [phase, setPhase] = useState<"reason" | "preview" | "result">("reason");
  const [busy, setBusy] = useState(false);
  const [response, setResponse] = useState<Awaited<ReturnType<typeof api.rules.clear>> | null>(null);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function submit(dryRun: boolean) {
    setBusy(true);
    setError(null);
    try {
      const result = await api.rules.clear(rule.id, {
        reason: reason.trim() || undefined,
        dry_run: dryRun,
        preview_token: dryRun ? undefined : token ?? undefined,
      });
      setResponse(result);
      if (dryRun) {
        setToken(result.preview_token ?? null);
        setPhase("preview");
      } else {
        setToken(null);
        setPhase("result");
        onChanged();
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Clear request failed");
      if (!dryRun) {
        setToken(null);
        setPhase("reason");
      }
    } finally { setBusy(false); }
  }

  return <Dialog open onOpenChange={(open) => !open && !busy && onClose()}>
    <DialogContent className="sm:max-w-xl">
      <DialogHeader>
        <DialogTitle>Clear firing rule — {rule.name}</DialogTitle>
        <DialogDescription>Step 1 · Preview the exact clear/revert plan. This reads current router configuration; no configuration changes are made. Preview time depends on router response times and actions.</DialogDescription>
      </DialogHeader>
      {phase === "reason" && <label className="block space-y-1 text-sm font-medium">
        Reason <span className="font-normal text-muted-foreground">(recorded in audit history)</span>
        <Input value={reason} maxLength={500} disabled={busy} onChange={(event) => setReason(event.target.value)} />
      </label>}
      {(phase === "preview" || phase === "result") && <div className="max-h-[55vh] space-y-3 overflow-y-auto" aria-live="polite">
        {phase === "preview" && <p className="text-sm font-medium">Step 2 · Review the exact plan and explicitly confirm.</p>}
        {(response?.results ?? []).map((result, index) => <ApplyResultRow key={index} r={result} />)}
        {phase === "preview" && (response?.results?.length ?? 0) === 0 && <p className="text-sm text-muted-foreground">No router rollback is required. Confirmation will clear only the detection state.</p>}
        {phase === "preview" && !token && (response?.results?.length ?? 0) > 0 && <p className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">The server did not issue confirmation authority for this preview. Refresh the rule and prepare a new exact preview before clearing.</p>}
        {phase === "result" && <div className={`rounded-md border p-3 text-sm ${response?.cleared ? "border-border" : "border-destructive bg-destructive/10 text-destructive"}`} role="status">
          {response?.cleared
            ? "The server confirmed that the rule is clear. Review any rollback results above before closing."
            : "The rule was not confirmed clear. It may still be firing; refresh and inspect the rollback results before retrying."}
        </div>}
      </div>}
      {error && <p className="text-sm text-destructive" role="alert">{error}</p>}
      <DialogFooter>
        <Button variant="outline" disabled={busy} onClick={onClose}>{phase === "result" ? "Close" : "Cancel"}</Button>
        {phase === "reason" && <Button loading={busy} loadingLabel="Preparing clear preview…" onClick={() => void submit(true)}>Preview clear changes</Button>}
        {phase === "preview" && <Button variant="destructive" disabled={!token} loading={busy} loadingLabel="Starting clear…" onClick={() => void submit(false)}>Confirm reviewed clear</Button>}
      </DialogFooter>
    </DialogContent>
  </Dialog>;
}

type SortDir = "asc" | "desc";

export default function Rules() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { id: ruleIdRaw } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const ruleId = Number(ruleIdRaw) || null;
  const detailMode = ruleId !== null;
  const ruleTab = location.hash === "#configuration" ? "configuration" : "overview";
  const { hasPermission } = useAuth();
  const canEdit = hasPermission("edit_rules");
  const canApply = hasPermission("trigger_manual_reroute");

  const [rules, setRules] = useState<Rule[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [manageRule, setManageRule] = useState<Rule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null);
  const [editRule, setEditRule] = useState<Rule | null>(null);
  // Rule mitigation the operator chose to run manually (same guarded
  // preview -> token -> execute dialog as Dashboard and Mitigations).
  const [applyRule, setApplyRule] = useState<Rule | null>(null);
  const [clearRuleTarget, setClearRuleTarget] = useState<Rule | null>(null);

  const initialSort = searchParams.get("sort");
  const [nameSortDir, setNameSortDir] = useState<SortDir | null>(initialSort === "asc" || initialSort === "desc" ? initialSort : null);
  const query = searchParams.get("rule") ?? "";

  function loadRules() {
    setLoading(true);
    api.rules
      .list()
      .then((value) => { setRules(value); setLoadError(null); })
      .catch((cause) => setLoadError(cause instanceof Error ? cause.message : "Rules could not be loaded"))
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    loadRules();
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]));
    // Operating mode drives the supervised manual-run copy.
    api.settings
      .get()
      .then(setSettings)
      .catch(() => setSettings(null));
  }, []);

  const detailRule = ruleId === null ? null : rules.find((rule) => rule.id === ruleId) ?? null;
  const editRoute = detailMode && location.pathname.endsWith("/edit");
  useEffect(() => {
    if (editRoute && detailRule && editRule?.id !== detailRule.id) setEditRule(detailRule);
  }, [editRoute, detailRule, editRule?.id]);

  function setRuleTab(next: string) {
    navigate(
      { pathname: location.pathname, search: location.search, hash: next === "configuration" ? "#configuration" : "#overview" },
      { replace: false },
    );
  }

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

  async function toggleRule(rule: Rule) {
    try {
      const updated = await api.rules.update(rule.id, {
        enabled: !rule.enabled,
      });
      setRules((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch (e) {
      toast.error(e instanceof ApiError ? e.message : "Could not change rule state");
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
      const next = d === null || d === "desc" ? "asc" : "desc";
      const params = new URLSearchParams(searchParams); params.set("sort", next); setSearchParams(params, { replace: true });
      return next;
    });
  }

  const filtered = rules.filter((rule) => {
    const device = searchParams.get("device");
    const iface = searchParams.get("interface");
    return (!device || String(rule.device_id) === device) && (!iface || String(rule.interface_id) === iface || rule.member_interface_ids?.includes(Number(iface))) && (!query || `${rule.name} ${rule.device_name ?? ""} ${rule.interface_name ?? ""} ${metricLabel(rule.metric)}`.toLowerCase().includes(query.toLowerCase()));
  });
  const sorted = nameSortDir
    ? [...filtered].sort((a, b) => {
        const cmp = a.name.localeCompare(b.name);
        return nameSortDir === "asc" ? cmp : -cmp;
      })
    : filtered;
  const detailDisarmed = detailRule ? autoDisarm(detailRule) : null;
  const detailDrifted = detailRule ? driftedActions(detailRule) : [];

  return (
    <div className="space-y-6">
      {detailMode ? (
        <>
          <div className="space-y-3">
            <Link to="/rules" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:underline"><ArrowLeft className="size-4" /> Rules</Link>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div><h1 className="text-2xl font-bold tracking-tight">{detailRule?.name ?? (loading ? "Loading rule…" : `Rule #${ruleId}`)}</h1>{detailRule && <p className="mt-1 text-sm text-muted-foreground">{detailRule.metric_aggregation === "sum" ? `Sum of ${detailRule.member_interface_ids?.length ?? 0} interfaces` : `${detailRule.device_name ?? "Device"} · ${detailRule.interface_name ?? `interface #${detailRule.interface_id}`}`}</p>}</div>
              {detailRule && <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={detailRule.severity} /><Badge variant={detailRule.enabled ? "outline" : "secondary"}>{detailRule.enabled ? "enabled" : "disabled"}</Badge>{canEdit && <Button variant="outline" size="sm" asChild><Link to={`/rules/${detailRule.id}/edit#configuration`}><Pencil className="size-4" /> Edit</Link></Button>}{canEdit && <Button variant="outline" size="sm" className="text-destructive hover:text-destructive" onClick={() => setDeleteTarget(detailRule)}><Trash2 className="size-4" /> Delete</Button>}</div>}
            </div>
          </div>

          {loadError && <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">Could not refresh this rule. {detailRule ? "Showing retained data." : "No rule data is available."} {loadError}</div>}
          {!detailRule && !loading && !loadError && <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">Rule not found.</CardContent></Card>}
          {detailRule && <Tabs value={ruleTab} onValueChange={setRuleTab}>
            <TabsList variant="line" aria-label="Rule sections"><TabsTrigger value="overview">Overview &amp; run</TabsTrigger><TabsTrigger value="configuration">Configuration</TabsTrigger></TabsList>
            <TabsContent value="overview" className="mt-4 space-y-4">
              <Card><CardHeader><CardTitle className="text-lg">Current state</CardTitle></CardHeader><CardContent className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Condition</p><p className="mt-1 text-sm font-medium">{conditionLabel(detailRule)}</p><div className="mt-1"><RuleStatus rule={detailRule} /></div></div>
                <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Persistence</p><p className="mt-1 text-sm font-medium">{persistenceLabel(detailRule)}</p><div className="mt-1"><RuleProgress rule={detailRule} /></div></div>
                <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Recovery</p><p className="mt-1 text-sm font-medium">{(detailRule.recovery_mode ?? "auto").replaceAll("_", " ")}</p><p className="text-xs text-muted-foreground">Automatic revert {detailRule.automatic_revert_enabled ? "enabled" : "disabled"}</p></div>
                <div><p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Mitigation</p><p className="mt-1 text-sm font-medium">{detailRule.action_count ?? 0} action{detailRule.action_count === 1 ? "" : "s"}</p><p className="text-xs text-muted-foreground">{detailRule.automatic_reroute_enabled ? "automatic execution armed" : "manual execution"}{detailRule.manual_apply_enabled ? " · manual run allowed" : ""}</p></div>
              </CardContent></Card>
              {detailDisarmed && <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200"><strong>Automatic execution disarmed</strong><p className="mt-1">{detailDisarmed.reason ?? "An attached action no longer matches discovered inventory."} · {timeAgo(detailDisarmed.at)}</p><p className="mt-1 text-xs">{DISARM_CONSEQUENCE}</p></div>}
              {detailDrifted.length > 0 && <div className="rounded-md border p-3 text-sm"><strong>{detailDrifted.length} drifted action{detailDrifted.length === 1 ? "" : "s"}</strong><ul className="mt-1 list-disc pl-5 text-muted-foreground">{detailDrifted.map((action) => <li key={action.id}>{action.inventory_drift_reason ?? "Saved parameters no longer match router inventory."}</li>)}</ul></div>}
              <Card><CardHeader><CardTitle className="text-lg">Operations</CardTitle></CardHeader><CardContent className="space-y-2"><div className="flex flex-wrap gap-2">
                {canApply && (detailRule.action_count ?? 0) > 0 && <Button variant="destructive" disabled={!detailRule.manual_apply_enabled} title={detailRule.manual_apply_enabled ? "Preview and run this rule's defined mitigation manually" : "Enable manual apply in Configuration first"} onClick={() => setApplyRule(detailRule)}>Run manually</Button>}
                {canEdit && detailRule.current_state === "firing" && <Button variant="outline" onClick={() => setClearRuleTarget(detailRule)}>Review &amp; clear</Button>}
                {detailRule.current_state === "recovered_awaiting_revert" && <Button variant="outline" asChild><Link to={`/mitigations?tab=active&rule_id=${detailRule.id}`}>View active run / revert</Link></Button>}
                <Button variant="outline" onClick={() => setManageRule(detailRule)}><Workflow className="size-4" /> {canEdit ? "Manage mitigation actions" : "Inspect mitigation actions"}</Button>
              </div>{(detailRule.action_count ?? 0) > 0 && !detailRule.manual_apply_enabled && <p className="text-xs text-muted-foreground">The mitigation is defined, but manual apply is disabled. Enable it in Configuration before running manually.</p>}{detailRule.manual_apply_enabled && (detailRule.action_count ?? 0) > 0 && <p className="text-xs text-muted-foreground">Manual execution uses the same prepared actions and action-specific verification as automatic execution. Preview changes pauses for review; Run now prepares and starts the exact plan.</p>}</CardContent></Card>
            </TabsContent>
            <TabsContent value="configuration" className="mt-4 space-y-4">
              <Card><CardHeader><div className="flex flex-wrap items-start justify-between gap-3"><div><CardTitle className="text-lg">Detection configuration</CardTitle><p className="mt-1 text-sm text-muted-foreground">Condition, persistence, severity, recovery, and target.</p></div>{canEdit && <Button size="sm" onClick={() => setEditRule(detailRule)}><Pencil className="size-4" /> Edit detection</Button>}</div></CardHeader><CardContent className="grid gap-3 text-sm sm:grid-cols-2"><p>Condition: <strong>{conditionLabel(detailRule)}</strong></p><p>Persistence: <strong>{persistenceLabel(detailRule)}</strong></p><p>Severity: <strong>{detailRule.severity}</strong></p><p>Recovery: <strong>{(detailRule.recovery_mode ?? "auto").replaceAll("_", " ")}</strong></p><p>Target: <strong>{detailRule.metric_aggregation === "sum" ? `${detailRule.member_interface_ids?.length ?? 0} summed interfaces` : `${detailRule.device_name ?? "device"} / ${detailRule.interface_name ?? `interface #${detailRule.interface_id}`}`}</strong></p><p>Metric: <strong>{metricLabel(detailRule.metric)}</strong></p></CardContent></Card>
              <Card><CardHeader><div className="flex flex-wrap items-start justify-between gap-3"><div><CardTitle className="text-lg">Mitigation configuration</CardTitle><p className="mt-1 text-sm text-muted-foreground">Ordered actions and manual/automatic execution preferences.</p></div><Button size="sm" variant="outline" onClick={() => setManageRule(detailRule)}><Workflow className="size-4" /> {canEdit ? "Edit actions" : "Inspect actions"}</Button></div></CardHeader><CardContent className="space-y-3">
                <div className="flex flex-wrap gap-2"><Badge variant={detailRule.automatic_reroute_enabled ? "destructive" : "outline"}>{detailRule.automatic_reroute_enabled ? "automatic armed" : "manual"}</Badge>{detailRule.manual_apply_enabled && <Badge variant="outline">manual apply allowed</Badge>}<Badge variant="secondary">revision {detailRule.actions_revision}</Badge></div>
                {detailRule.actions?.length ? <ol className="space-y-2">{detailRule.actions.map((action, index) => <li key={action.id} className="rounded-md border border-border p-3 text-sm"><div className="flex flex-wrap items-center gap-2"><span className="inline-flex size-6 items-center justify-center rounded bg-muted text-xs font-semibold">{index + 1}</span><strong>{templateLabelFrom(action.template_display_name, action.template_name)}</strong><span className="text-muted-foreground">· {action.device_name ?? `router #${action.device_id}`}</span>{action.inventory_state === "drifted" && <Badge variant="outline" className="border-amber-400 text-amber-700">drifted</Badge>}</div></li>)}</ol> : <p className="text-sm text-muted-foreground">No mitigation actions attached.</p>}
              </CardContent></Card>
            </TabsContent>
          </Tabs>}
        </>
      ) : (
        <>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Threshold rules</h1>
        <Button variant="outline" size="sm" onClick={() => setAddOpen(true)} disabled={!canEdit}>
          Add rule
        </Button>
      </div>

      <Input aria-label="Search rules" placeholder="Search rules, devices, interfaces, or metrics…" value={query} onChange={(event) => { const params = new URLSearchParams(searchParams); if (event.target.value) params.set("rule", event.target.value); else params.delete("rule"); setSearchParams(params, { replace: true }); }} />

      {loadError && <div role="alert" className="flex flex-wrap items-center gap-3 rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"><span>Could not refresh rules. {rules.length ? "Showing retained data." : "No rule data is available."} {loadError}</span><Button size="sm" variant="outline" loading={loading} loadingLabel="Retrying…" onClick={loadRules}>Try again</Button></div>}


      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Rules</CardTitle>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          {loading ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">Loading…</p>
          ) : !loadError && rules.length === 0 ? (
            <p className="px-6 pb-6 text-sm text-muted-foreground">
              No rules yet. Add a threshold rule to start monitoring interfaces.
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-6">
                    <button type="button" className="inline-flex items-center font-medium hover:underline" onClick={toggleNameSort} aria-label={`Sort rules by name ${nameSortDir === "asc" ? "descending" : "ascending"}`}>Name
                    {nameSortDir === null ? (
                      <ChevronsUpDown className="ml-1 inline-block size-3.5 text-muted-foreground" />
                    ) : nameSortDir === "asc" ? (
                      <ArrowUp className="ml-1 inline-block size-3.5" />
                    ) : (
                      <ArrowDown className="ml-1 inline-block size-3.5" />
                    )}</button>
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
                {sorted.map((rule) => {
                  // "The system turned automation off" vs "a human never armed
                  // it": only a server disarm stamp on a currently-unarmed rule
                  // is the former. An operator-disabled rule is the Enabled
                  // switch, a separate column.
                  const disarmed = autoDisarm(rule);
                  const drifted = driftedActions(rule);
                  return (
                    <TableRow key={rule.id} className="hover:bg-muted/50">
                      {/* Name + icon */}
                      <TableCell className="pl-6">
                        <div className="flex items-center gap-2">
                          <SlidersHorizontal className="size-4 shrink-0 text-muted-foreground" />
                          <Link className="font-medium hover:underline" to={`/rules/${rule.id}#overview`}>{rule.name}</Link>
                          {rule.current_state === "recovered_awaiting_revert" && <Badge variant="outline" className="border-amber-400 text-amber-800 dark:text-amber-300">recovered · awaiting revert</Badge>}
                        </div>
                      </TableCell>

                      {/* Target — interface name (+ device) */}
                      <TableCell className="text-xs">
                        <div className="flex flex-col">
                          <span className="font-mono">{rule.metric_aggregation === "sum" ? `Sum of ${rule.member_interface_ids?.length ?? 0} interfaces` : rule.interface_name || (rule.interface_id ? `interface #${rule.interface_id}` : "interface")}</span>
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

                      {/* Mitigation — attached reroute actions + auto/manual/disarmed */}
                      <TableCell onClick={(e) => e.stopPropagation()}>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 gap-1.5"
                            asChild
                            title={canEdit ? "Manage mitigation actions" : "Inspect mitigation actions"}
                          >
                            <Link to={`/rules/${rule.id}#configuration`}><Workflow className="size-3.5 text-muted-foreground" />{rule.action_count ? `${rule.action_count} action${rule.action_count > 1 ? "s" : ""}` : "none"}</Link>
                          </Button>
                          {rule.action_count ? (
                            <>
                              {disarmed ? (
                                // Amber, not the neutral "manual" outline: the
                                // controller switched this off, an operator did not.
                                <Badge
                                  variant="outline"
                                  className="gap-1 text-[10px] border-amber-400 text-amber-700 dark:text-amber-400"
                                  title={
                                    `Disarmed by the controller ${timeAgo(disarmed.at)}` +
                                    (disarmed.reason ? ` — ${disarmed.reason}` : "") +
                                    `. ${DISARM_CONSEQUENCE}`
                                  }
                                >
                                  <ShieldAlert className="size-3" />
                                  auto-execution disarmed
                                </Badge>
                              ) : (
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
                              )}
                              {!disarmed && drifted.length > 0 && (
                                // Drift on a rule that was never armed: nothing was
                                // switched off, but the params still won't validate.
                                <Badge
                                  variant="outline"
                                  className="gap-1 text-[10px] border-amber-400 text-amber-700 dark:text-amber-400"
                                  title={drifted
                                    .map((a) => a.inventory_drift_reason ?? "parameters no longer match discovered inventory")
                                    .join(" · ")}
                                >
                                  <AlertTriangle className="size-3" />
                                  {drifted.length} drifted
                                </Badge>
                              )}
                              {rule.manual_apply_enabled && (
                                <Badge
                                  variant="outline"
                                  className="text-[10px] text-sky-700 dark:text-sky-400"
                                  title="Operators can manually run this rule's defined actions"
                                >
                                  apply
                                </Badge>
                              )}
                            </>
                          ) : null}
                        </div>
                        {disarmed && (
                          // State + consequence together: a badge alone doesn't
                          // say what the operator still has.
                          <div className="mt-1 max-w-[22rem] space-y-0.5 text-[11px] leading-snug">
                            <p className="break-words text-amber-700 dark:text-amber-400">
                              {disarmed.reason ?? "An attached action no longer matches discovered inventory."}{" "}
                              <span className="text-muted-foreground">
                                (disarmed {timeAgo(disarmed.at)})
                              </span>
                            </p>
                            <p className="text-muted-foreground">{DISARM_CONSEQUENCE}</p>
                            {drifted.length > 0 && (
                              <p className="text-muted-foreground">
                                {drifted.length === 1
                                  ? "1 action needs"
                                  : `${drifted.length} actions need`}{" "}
                                new parameters — open the actions editor to re-pick them.
                              </p>
                            )}
                          </div>
                        )}
                      </TableCell>

                      {/* Actions */}
                      <TableCell
                        className="pr-6 text-right"
                        onClick={(e) => e.stopPropagation()}
                      >
                        <div className="flex items-center justify-end gap-1">
                          <RowActionButton label={`View ${rule.name}`} asChild><Link to={`/rules/${rule.id}#overview`}><Eye className="size-4" /></Link></RowActionButton>
                          {canEdit && (
                            <>
                              <RowActionButton
                                label={`Edit ${rule.name}`}
                                asChild
                              >
                                <Link to={`/rules/${rule.id}/edit#configuration`}><Pencil className="size-4" /></Link>
                              </RowActionButton>
                              <RowActionButton
                                label={`Delete ${rule.name}`}
                                tone="destructive"
                                onClick={() => setDeleteTarget(rule)}
                              >
                                <Trash2 className="size-4" />
                              </RowActionButton>
                            </>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
        </>
      )}

      {applyRule && (
        <ApplyMitigationDialog
          rule={applyRule}
          operatingMode={settings?.operating_mode ?? "unknown"}
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
          onClose={() => { setEditRule(null); if (editRoute) navigate(`/rules/${editRule.id}#configuration`, { replace: true }); }}
          onSaved={(updated) => { setRules((rs) => rs.map((r) => (r.id === updated.id ? updated : r))); if (editRoute) navigate(`/rules/${updated.id}#configuration`, { replace: true }); }}
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
          if (ruleId === rule.id) navigate("/rules");
        }}
      />
      {clearRuleTarget && (
        <ClearRuleDialog
          rule={clearRuleTarget}
          onClose={() => setClearRuleTarget(null)}
          onChanged={loadRules}
        />
      )}
    </div>
  );
}
