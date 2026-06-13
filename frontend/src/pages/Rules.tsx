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
} from "lucide-react";
import { api, type Rule, type Device, type Interface, ApiError } from "@/lib/api";
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

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
  duration_seconds: string;
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
  duration_seconds: "60",
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
        duration_seconds: parseInt(form.duration_seconds, 10),
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
                  Duration (seconds)
                  <input
                    type="number"
                    min={10}
                    required
                    className={inputClass}
                    value={form.duration_seconds}
                    onChange={(e) => setField("duration_seconds", e.target.value)}
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Consecutive samples
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

                    {/* Target — interface id or asset id */}
                    <TableCell className="text-xs text-muted-foreground">
                      {rule.target_kind === "interface" && rule.interface_id
                        ? `interface #${rule.interface_id}`
                        : rule.target_kind === "asset" && rule.asset_id
                          ? `asset #${rule.asset_id}`
                          : rule.target_kind}
                    </TableCell>

                    {/* Condition */}
                    <TableCell>
                      <code className="text-xs">{conditionLabel(rule)}</code>
                    </TableCell>

                    {/* Duration */}
                    <TableCell className="text-xs text-muted-foreground">
                      {rule.duration_seconds}s / {rule.consecutive_samples}{" "}
                      samples
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
    </div>
  );
}
