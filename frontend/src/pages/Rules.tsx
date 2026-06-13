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
import { useEffect, useState, type FormEvent } from "react";
import {
  SlidersHorizontal,
  ToggleLeft,
  ToggleRight,
  Trash2,
  ArrowUp,
  ArrowDown,
  ChevronsUpDown,
  Workflow,
  Plus,
  X,
} from "lucide-react";
import {
  api,
  type Rule,
  type Device,
  type Interface,
  type Template,
  type BgpPeer,
  ApiError,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
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
  const [peers, setPeers] = useState<BgpPeer[]>([]);
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

  useEffect(() => {
    if (!deviceId) {
      setPeers([]);
      return;
    }
    api.devices
      .bgpPeers(parseInt(deviceId, 10))
      .then(setPeers)
      .catch(() => setPeers([]));
  }, [deviceId]);

  const template = templates.find((t) => String(t.id) === templateId) ?? null;
  const schema = template?.parameter_schema ?? {};

  function selectNeighbor(name: string, addr: string) {
    setValues((v) => {
      const next = { ...v, [name]: addr };
      // Auto-fill a local-AS param from the chosen peer.
      const peer = peers.find((p) => p.peer_remote_addr === addr);
      if (peer?.local_as != null) {
        for (const [pname, spec] of Object.entries(schema)) {
          if (spec.source === "bgp_local_as") next[pname] = String(peer.local_as);
        }
      }
      return next;
    });
  }

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
          <DialogTitle>Reroute actions — {current.name}</DialogTitle>
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
                <code className="text-xs">{a.template_name}</code>
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
                    {t.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Target router
              <select
                className={inputClass}
                value={deviceId}
                onChange={(e) => setDeviceId(e.target.value)}
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
            <div className="grid gap-3 sm:grid-cols-2">
              {Object.entries(schema).map(([name, spec]) => (
                <label key={name} className="block space-y-1 text-sm font-medium">
                  {spec.label ?? name}{" "}
                  <span className="text-muted-foreground">({spec.type})</span>
                  {spec.source === "bgp_peer" ? (
                    <select
                      className={inputClass}
                      value={values[name] ?? ""}
                      onChange={(e) => selectNeighbor(name, e.target.value)}
                      disabled={!deviceId}
                    >
                      <option value="">
                        {deviceId ? "Select neighbor…" : "Pick a router first"}
                      </option>
                      {peers.map((p) => (
                        <option key={p.id} value={p.peer_remote_addr}>
                          {p.peer_remote_addr}
                          {p.peer_remote_as ? ` · AS${p.peer_remote_as}` : ""}
                          {p.label ? ` · ${p.label}` : ""}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      className={inputClass}
                      value={values[name] ?? ""}
                      placeholder={
                        spec.type === "cidr"
                          ? "e.g. 192.0.2.0/24"
                          : spec.type === "asn"
                            ? "e.g. 65001"
                            : ""
                      }
                      onChange={(e) =>
                        setValues((v) => ({ ...v, [name]: e.target.value }))
                      }
                    />
                  )}
                </label>
              ))}
            </div>
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

const METRICS = [
  { value: "rx_bps", label: "Rx bps" },
  { value: "tx_bps", label: "Tx bps" },
  { value: "rx_pps", label: "Rx pps" },
  { value: "tx_pps", label: "Tx pps" },
  { value: "rx_util_percent", label: "Rx utilization %" },
  { value: "tx_util_percent", label: "Tx utilization %" },
];

interface RuleForm {
  name: string;
  device_id: string;
  interface_id: string;
  metric: string;
  operator: ">" | "<";
  threshold_value: string;
  window_minutes: string;
  consecutive_samples: string;
  severity: string;
}

const DEFAULT_FORM: RuleForm = {
  name: "",
  device_id: "",
  interface_id: "",
  metric: "rx_bps",
  operator: ">",
  threshold_value: "",
  window_minutes: "1",
  consecutive_samples: "3",
  severity: "warning",
};

function severityVariant(
  severity: string,
): "default" | "secondary" | "destructive" | "outline" {
  switch (severity) {
    case "critical":
      return "destructive";
    case "warning":
      return "secondary";
    default:
      return "outline";
  }
}

/** Human-readable condition string: "rx_bps > 8000000000" */
function conditionLabel(rule: Rule): string {
  const metricLabel =
    METRICS.find((m) => m.value === rule.metric)?.label ?? rule.metric;
  return `${metricLabel} ${rule.operator} ${rule.threshold_value.toLocaleString()}`;
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
  const cls = stale
    ? "bg-muted text-muted-foreground"
    : breaching
      ? "bg-red-100 text-red-700 dark:bg-red-950/60 dark:text-red-300"
      : "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300";
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
  const [deviceInterfaces, setDeviceInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<RuleForm>(DEFAULT_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);
  const [manageRule, setManageRule] = useState<Rule | null>(null);

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

  function setField(field: keyof RuleForm, value: string) {
    setForm((f) => {
      const next = { ...f, [field]: value };
      if (field === "device_id") {
        next.interface_id = "";
      }
      return next;
    });
    if (field === "device_id" && value) {
      api.devices
        .interfaces(parseInt(value, 10))
        .then(setDeviceInterfaces)
        .catch(() => setDeviceInterfaces([]));
    }
  }

  async function handleAdd(e: FormEvent) {
    e.preventDefault();
    setAddError(null);
    if (!form.interface_id) {
      setAddError("Select a device and interface.");
      return;
    }
    setAddBusy(true);
    try {
      await api.rules.create({
        name: form.name.trim(),
        target_kind: "interface",
        interface_id: parseInt(form.interface_id, 10),
        device_id: parseInt(form.device_id, 10),
        asset_id: null,
        metric: form.metric,
        operator: form.operator,
        threshold_value: parseFloat(form.threshold_value),
        duration_seconds: Math.max(0, Math.round(parseFloat(form.window_minutes || "0") * 60)),
        consecutive_samples: parseInt(form.consecutive_samples, 10),
        severity: form.severity,
        enabled: true,
        automatic_reroute_enabled: false,
        reroute_template_id: null,
      });
      setForm(DEFAULT_FORM);
      setShowAdd(false);
      loadRules();
    } catch (err) {
      setAddError(err instanceof ApiError ? err.message : "Failed to create rule");
    } finally {
      setAddBusy(false);
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
    if (!confirm(`Delete rule "${rule.name}"?`)) return;
    try {
      await api.rules.remove(rule.id);
      setRules((prev) => prev.filter((r) => r.id !== rule.id));
    } catch {
      // ignore
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
        <Button
          variant="outline"
          size="sm"
          onClick={() => setShowAdd((v) => !v)}
        >
          {showAdd ? "Cancel" : "Add rule"}
        </Button>
      </div>

      <div className="rounded-md border border-yellow-300 bg-yellow-50 px-4 py-2 text-sm text-yellow-800">
        In <strong>observe mode</strong>, rule matches generate alerts only — no
        reroute action executes. Alerts include the would-run action plan.
      </div>

      {showAdd && (
        <Card>
          <CardHeader>
            <CardTitle className="text-lg">New threshold rule</CardTitle>
            <CardDescription>
              Select a device and interface, then configure the threshold.
              Automatic reroutes are off by default (doctrine §8).
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAdd} className="space-y-4">
              <label className="block space-y-1 text-sm font-medium">
                Rule name
                <input
                  required
                  className={inputClass}
                  value={form.name}
                  onChange={(e) => setField("name", e.target.value)}
                  placeholder="High Rx utilization on core uplink"
                />
              </label>
              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block space-y-1 text-sm font-medium">
                  Device
                  <select
                    required
                    className={inputClass}
                    value={form.device_id}
                    onChange={(e) => setField("device_id", e.target.value)}
                  >
                    <option value="">Select device…</option>
                    {devices.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name} ({d.hostname})
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Interface
                  <select
                    required
                    className={inputClass}
                    value={form.interface_id}
                    onChange={(e) => setField("interface_id", e.target.value)}
                    disabled={!form.device_id}
                  >
                    <option value="">
                      {form.device_id
                        ? "Select interface…"
                        : "Select device first"}
                    </option>
                    {deviceInterfaces.map((iface) => (
                      <option key={iface.id} value={iface.id}>
                        {iface.if_name}
                        {iface.if_alias ? ` — ${iface.if_alias}` : ""}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Metric
                  <select
                    className={inputClass}
                    value={form.metric}
                    onChange={(e) => setField("metric", e.target.value)}
                  >
                    {METRICS.map((m) => (
                      <option key={m.value} value={m.value}>
                        {m.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Operator
                  <select
                    className={inputClass}
                    value={form.operator}
                    onChange={(e) =>
                      setField("operator", e.target.value as ">" | "<")
                    }
                  >
                    <option value=">">above (&gt;)</option>
                    <option value="<">below (&lt;)</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Threshold value
                  <input
                    type="number"
                    step="any"
                    required
                    className={inputClass}
                    value={form.threshold_value}
                    onChange={(e) => setField("threshold_value", e.target.value)}
                    placeholder="e.g. 1000000000 for 1 Gbps"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Sliding window (minutes)
                  <input
                    type="number"
                    min={0}
                    step="0.5"
                    required
                    className={inputClass}
                    value={form.window_minutes}
                    onChange={(e) => setField("window_minutes", e.target.value)}
                  />
                  <span className="text-[11px] font-normal text-muted-foreground">
                    how long the metric must stay over/under the threshold
                  </span>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  …or consecutive samples (poll cycles)
                  <input
                    type="number"
                    min={1}
                    required
                    className={inputClass}
                    value={form.consecutive_samples}
                    onChange={(e) =>
                      setField("consecutive_samples", e.target.value)
                    }
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Severity
                  <select
                    className={inputClass}
                    value={form.severity}
                    onChange={(e) => setField("severity", e.target.value)}
                  >
                    <option value="info">info</option>
                    <option value="warning">warning</option>
                    <option value="critical">critical</option>
                  </select>
                </label>
              </div>
              {addError && (
                <p className="text-sm text-destructive" role="alert">
                  {addError}
                </p>
              )}
              <Button type="submit" disabled={addBusy}>
                {addBusy ? "Creating…" : "Create rule"}
              </Button>
            </form>
          </CardContent>
        </Card>
      )}

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
                  <TableHead>Duration</TableHead>
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

                    {/* Target — interface name (+ device) or asset */}
                    <TableCell className="text-xs">
                      <div className="flex flex-col">
                        <span className="font-mono">
                          {rule.target_kind === "interface"
                            ? (rule.interface_name ||
                              (rule.interface_id ? `interface #${rule.interface_id}` : "interface"))
                            : rule.asset_id
                              ? `asset #${rule.asset_id}`
                              : rule.target_kind}
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

                    {/* Sliding window */}
                    <TableCell className="text-xs text-muted-foreground">
                      {rule.duration_seconds >= 60
                        ? `${(rule.duration_seconds / 60).toLocaleString(undefined, { maximumFractionDigits: 1 })} min`
                        : `${rule.duration_seconds}s`}{" "}
                      / {rule.consecutive_samples} cycles
                    </TableCell>

                    {/* Severity badge */}
                    <TableCell>
                      <Badge variant={severityVariant(rule.severity)}>
                        {rule.severity}
                      </Badge>
                    </TableCell>

                    {/* Enabled badge */}
                    <TableCell>
                      <Badge variant={rule.enabled ? "default" : "outline"}>
                        {rule.enabled ? "enabled" : "disabled"}
                      </Badge>
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
                          title={canEdit ? "Manage reroute actions" : "Requires edit_rules"}
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
                        {canEdit && (
                          <>
                            <Button
                              size="icon-sm"
                              variant="ghost"
                              title={rule.enabled ? "Disable rule" : "Enable rule"}
                              onClick={() => void toggleRule(rule)}
                            >
                              {rule.enabled ? (
                                <ToggleRight className="size-4 text-primary" />
                              ) : (
                                <ToggleLeft className="size-4 text-muted-foreground" />
                              )}
                              <span className="sr-only">
                                {rule.enabled ? "Disable" : "Enable"}
                              </span>
                            </Button>
                            <Button
                              size="icon-sm"
                              variant="ghost"
                              title="Delete rule"
                              className="text-destructive hover:text-destructive"
                              onClick={() => void deleteRule(rule)}
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
    </div>
  );
}
