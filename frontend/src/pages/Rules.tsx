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
  ToggleLeft,
  ToggleRight,
  Pencil,
  Trash2,
  ArrowUp,
  ArrowDown,
  ChevronsUpDown,
  Workflow,
  Plus,
  X,
} from "lucide-react";
import { toast } from "sonner";
import {
  api,
  type Rule,
  type Device,
  type Template,
  ApiError,
} from "@/lib/api";
import { ActionParamsForm } from "@/components/action-params-form";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Toggle } from "@/components/ui/toggle";
import { SeverityBadge, ToneBadge, toneClass } from "@/components/status-badge";
import { RuleDialog } from "./rules/rule-dialog";
import { metricLabel, isFlowMetric } from "./rules/rule-constants";
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
 */
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
  const [templates, setTemplates] = useState<Template[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [templateId, setTemplateId] = useState<string>("");
  const [deviceId, setDeviceId] = useState<string>("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.templates
      .list()
      .then((ts) => setTemplates(ts.filter((t) => t.provider_type === "device_cli" && t.enabled)))
      .catch(() => setTemplates([]));
    api.devices
      .list()
      .then(setDevices)
      .catch(() => setDevices([]));
  }, []);

  const template = templates.find((t) => String(t.id) === templateId) ?? null;
  const schema = template?.parameter_schema ?? {};

  async function add() {
    if (!template || !deviceId) {
      setError("Pick a template and a target router.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const params: Record<string, unknown> = {};
      for (const name of Object.keys(schema)) {
        if (values[name]) params[name] = values[name];
      }
      const updated = await api.rules.addAction(current.id, {
        reroute_template_id: template.id,
        device_id: parseInt(deviceId, 10),
        params,
      });
      setCurrent(updated);
      onChanged(updated);
      setTemplateId("");
      setDeviceId("");
      setValues({});
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Failed to add action");
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

  const actions = current.actions ?? [];

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Mitigation actions — {current.name}</DialogTitle>
          <DialogDescription>
            When this rule fires (its sliding window holds), these mitigations run
            on the selected routers. Observe mode always renders a plan only.
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
          <Button
            size="sm"
            variant={current.automatic_reroute_enabled ? "destructive" : "outline"}
            onClick={() => void toggleAuto()}
            disabled={actions.length === 0}
            title={actions.length === 0 ? "Attach an action first" : undefined}
          >
            {current.automatic_reroute_enabled ? "Auto: ON" : "Auto: OFF"}
          </Button>
        </div>

        {/* Existing actions */}
        <div className="space-y-2">
          {actions.length === 0 ? (
            <p className="text-sm text-muted-foreground">No actions attached yet.</p>
          ) : (
            actions.map((a) => (
              <div
                key={a.id}
                className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-sm"
              >
                <span className="font-medium">{a.template_display_name || a.template_name}</span>
                <span className="text-muted-foreground">on</span>
                <span className="font-medium">{a.device_name}</span>
                <span className="text-xs text-muted-foreground">
                  {Object.entries(a.params ?? {})
                    .map(([k, v]) => `${k}=${String(v)}`)
                    .join(", ")}
                </span>
                <span className="flex-1" />
                <Button
                  size="icon-sm"
                  variant="ghost"
                  className="text-destructive hover:text-destructive"
                  onClick={() => void remove(a.id)}
                  title="Remove action"
                >
                  <X className="size-4" />
                </Button>
              </div>
            ))
          )}
        </div>

        {/* Add an action */}
        <div className="space-y-3 rounded-md border border-dashed border-border p-3">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Template
              <select
                className={inputClass}
                value={templateId}
                onChange={(e) => {
                  setTemplateId(e.target.value);
                  setValues({});
                }}
              >
                <option value="">Select template…</option>
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.display_name || t.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Target router
              <select
                className={inputClass}
                value={deviceId}
                onChange={(e) => {
                  setDeviceId(e.target.value);
                  setValues({});
                }}
              >
                <option value="">Select router…</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {template && (
            <ActionParamsForm
              schema={schema}
              deviceId={deviceId ? parseInt(deviceId, 10) : null}
              values={values}
              onChange={setValues}
            />
          )}

          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
          <Button size="sm" onClick={() => void add()} disabled={busy}>
            <Plus className="size-4" />
            {busy ? "Adding…" : "Add action"}
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

  const [rules, setRules] = useState<Rule[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [addOpen, setAddOpen] = useState(false);
  const [manageRule, setManageRule] = useState<Rule | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null);
  const [editRule, setEditRule] = useState<Rule | null>(null);

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

                    {/* Enabled — Toggle with text, green when on / red when off */}
                    <TableCell onClick={(e) => e.stopPropagation()}>
                      {canEdit ? (
                        <Toggle
                          variant="outline"
                          size="sm"
                          pressed={rule.enabled}
                          onPressedChange={() => void toggleRule(rule)}
                          aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                          className="data-[state=on]:border-emerald-300 data-[state=on]:bg-emerald-100 data-[state=on]:text-emerald-700 data-[state=off]:text-red-600 dark:data-[state=on]:bg-emerald-950/60 dark:data-[state=on]:text-emerald-300 dark:data-[state=off]:text-red-400"
                        >
                          {rule.enabled ? <ToggleRight className="size-4" /> : <ToggleLeft className="size-4" />}
                          {rule.enabled ? "Enabled" : "Disabled"}
                        </Toggle>
                      ) : (
                        <ToneBadge tone={rule.enabled ? "good" : "bad"}>
                          {rule.enabled ? "enabled" : "disabled"}
                        </ToneBadge>
                      )}
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
                        ) : null}
                      </div>
                    </TableCell>

                    {/* Actions */}
                    <TableCell
                      className="pr-6 text-right"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <div className="flex items-center justify-end gap-1">
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
