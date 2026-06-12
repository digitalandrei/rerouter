/**
 * /rules — threshold rules on SNMP interfaces.
 *
 * Governed by docs/detection-engine.md and docs/doctrine.md §8.
 *
 * Operators pick device → interface, then configure: metric
 * (rx_bps/tx_bps/rx_pps/tx_pps/rx_util_percent/tx_util_percent),
 * operator (> above / < below), threshold value, duration, consecutive
 * samples. In observe mode, firing only generates alerts (no reroute).
 */
import { useEffect, useState, type FormEvent } from "react";
import { api, type Rule, type Device, type Interface, ApiError } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

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

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [deviceInterfaces, setDeviceInterfaces] = useState<Interface[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState<RuleForm>(DEFAULT_FORM);
  const [addError, setAddError] = useState<string | null>(null);
  const [addBusy, setAddBusy] = useState(false);

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
      // When device changes, reset interface selection and reload interfaces
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
        <CardContent>
          {loading ? (
            <p className="text-sm text-muted-foreground">Loading…</p>
          ) : rules.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No rules yet. Add a threshold rule to start monitoring interfaces.
            </p>
          ) : (
            <div className="divide-y">
              {rules.map((rule) => (
                <div
                  key={rule.id}
                  className="flex flex-wrap items-center gap-3 py-3 text-sm"
                >
                  <span className="font-medium">{rule.name}</span>
                  <Badge variant={severityVariant(rule.severity)}>
                    {rule.severity}
                  </Badge>
                  <code className="text-xs text-muted-foreground">
                    {rule.metric} {rule.operator} {rule.threshold_value}
                  </code>
                  <span className="text-xs text-muted-foreground">
                    {rule.duration_seconds}s / {rule.consecutive_samples} samples
                  </span>
                  <span className="flex-1" />
                  <Badge variant={rule.enabled ? "default" : "outline"}>
                    {rule.enabled ? "enabled" : "disabled"}
                  </Badge>
                  <Badge
                    variant={
                      rule.automatic_reroute_enabled ? "destructive" : "secondary"
                    }
                  >
                    auto-reroute: {rule.automatic_reroute_enabled ? "ON" : "off"}
                  </Badge>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void toggleRule(rule)}
                  >
                    {rule.enabled ? "Disable" : "Enable"}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => void deleteRule(rule)}
                  >
                    Delete
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
