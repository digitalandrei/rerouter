/**
 * Edit an existing detection rule. Shows the full rule menu (same fields as
 * Add), with the device/interface target read-only — retargeting to another
 * interface needs a recreate. The flow selector, condition, persistence,
 * recovery and severity are all editable; saving resets the rule's evaluation
 * streak so it re-counts fresh against the new condition (server-side).
 */
import { useState, type FormEvent } from "react";
import { toast } from "sonner";
import { api, type Rule, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  METRICS,
  SEVERITIES,
  RECOVERY_MODES,
  FLOW_PROTOCOLS,
  isFlowMetric,
  thresholdHint,
} from "./rule-constants";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function EditRuleDialog({
  rule,
  onClose,
  onSaved,
}: {
  rule: Rule;
  onClose: () => void;
  onSaved: (updated: Rule) => void;
}) {
  const ruleIsFlow = isFlowMetric(rule.metric);
  const [form, setForm] = useState({
    name: rule.name,
    metric: rule.metric,
    flow_protocol: rule.flow_protocol != null ? String(rule.flow_protocol) : "",
    flow_port: rule.flow_port != null ? String(rule.flow_port) : "",
    flow_port_kind: (rule.flow_port_kind ?? "dst") as "src" | "dst",
    operator: rule.operator as ">" | "<",
    threshold_value: String(rule.threshold_value),
    window_minutes: String(rule.duration_seconds / 60),
    consecutive_samples: String(rule.consecutive_samples || 3),
    recovery_mode: (rule.recovery_mode ?? "auto") as "auto" | "threshold" | "manual",
    recovery_threshold_value:
      rule.recovery_threshold_value != null ? String(rule.recovery_threshold_value) : "",
    recovery_window_seconds:
      rule.recovery_window_seconds != null ? String(rule.recovery_window_seconds) : "",
    severity: rule.severity,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const metricOptions = METRICS.filter((m) => isFlowMetric(m.value) === ruleIsFlow);
  const editingIsFlow = isFlowMetric(form.metric);

  function set<K extends keyof typeof form>(field: K, value: (typeof form)[K]) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const flow = editingIsFlow
        ? {
            flow_direction: "ingress" as const,
            flow_protocol: form.flow_protocol ? parseInt(form.flow_protocol, 10) : null,
            flow_port: form.flow_port ? parseInt(form.flow_port, 10) : null,
            flow_port_kind: form.flow_port ? form.flow_port_kind : null,
          }
        : {};
      const updated = await api.rules.update(rule.id, {
        name: form.name.trim(),
        metric: form.metric,
        ...flow,
        operator: form.operator,
        threshold_value: parseFloat(form.threshold_value),
        duration_seconds: editingIsFlow
          ? Math.max(0, Math.round(parseFloat(form.window_minutes || "0") * 60))
          : 0,
        consecutive_samples: editingIsFlow
          ? 0
          : Math.max(1, parseInt(form.consecutive_samples, 10) || 1),
        recovery_mode: form.recovery_mode,
        recovery_threshold_value:
          form.recovery_mode === "threshold" && form.recovery_threshold_value
            ? parseFloat(form.recovery_threshold_value)
            : null,
        recovery_window_seconds:
          form.recovery_mode !== "manual" && form.recovery_window_seconds
            ? Math.max(0, parseInt(form.recovery_window_seconds, 10))
            : null,
        severity: form.severity,
      });
      toast.success(`Updated rule "${updated.name}"`);
      onSaved(updated);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to update rule");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit rule — {rule.name}</DialogTitle>
        </DialogHeader>
        <form id="edit-rule-form" onSubmit={save} className="space-y-4">
          {/* Target is immutable — shown read-only (recreate to retarget). */}
          <p className="text-xs text-muted-foreground">
            Target: <span className="font-medium">{rule.interface_name ?? `interface #${rule.interface_id}`}</span>
            {rule.device_name ? ` on ${rule.device_name}` : ""} · recreate the rule to retarget.
          </p>
          <label className="block space-y-1 text-sm font-medium">
            Name
            <input required className={inputClass} value={form.name} onChange={(e) => set("name", e.target.value)} />
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Metric
              <select className={inputClass} value={form.metric} onChange={(e) => set("metric", e.target.value)}>
                {metricOptions.map((m) => (
                  <option key={m.value} value={m.value}>
                    {m.label}
                  </option>
                ))}
              </select>
            </label>
            {editingIsFlow && (
              <>
                <label className="block space-y-1 text-sm font-medium">
                  Flow direction
                  <select className={`${inputClass} opacity-60`} value="ingress" disabled>
                    <option value="ingress">ingress</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Protocol
                  <select
                    className={inputClass}
                    value={form.flow_protocol}
                    onChange={(e) => set("flow_protocol", e.target.value)}
                  >
                    {FLOW_PROTOCOLS.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Port (optional)
                  <input
                    type="number"
                    min={0}
                    max={65535}
                    className={inputClass}
                    value={form.flow_port}
                    onChange={(e) => set("flow_port", e.target.value)}
                    placeholder="blank = whole interface"
                  />
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Port matches
                  <select
                    className={inputClass}
                    value={form.flow_port_kind}
                    onChange={(e) => set("flow_port_kind", e.target.value as "src" | "dst")}
                    disabled={!form.flow_port}
                  >
                    <option value="dst">destination port</option>
                    <option value="src">source port</option>
                  </select>
                </label>
              </>
            )}
            <label className="block space-y-1 text-sm font-medium">
              Condition
              <select
                className={inputClass}
                value={form.operator}
                onChange={(e) => set("operator", e.target.value as ">" | "<")}
              >
                <option value=">">above (&gt;)</option>
                <option value="<">below (&lt;)</option>
              </select>
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Threshold
              <input
                type="number"
                step="any"
                required
                className={inputClass}
                value={form.threshold_value}
                onChange={(e) => set("threshold_value", e.target.value)}
                placeholder={thresholdHint(form.metric)}
              />
            </label>
            {editingIsFlow ? (
              <label className="block space-y-1 text-sm font-medium">
                Sliding window (minutes)
                <input
                  type="number"
                  min={0}
                  step="0.5"
                  required
                  className={inputClass}
                  value={form.window_minutes}
                  onChange={(e) => set("window_minutes", e.target.value)}
                />
              </label>
            ) : (
              <label className="block space-y-1 text-sm font-medium">
                Consecutive samples
                <input
                  type="number"
                  min={1}
                  required
                  className={inputClass}
                  value={form.consecutive_samples}
                  onChange={(e) => set("consecutive_samples", e.target.value)}
                />
              </label>
            )}
            <label className="block space-y-1 text-sm font-medium">
              Recovery
              <select
                className={inputClass}
                value={form.recovery_mode}
                onChange={(e) => set("recovery_mode", e.target.value as typeof form.recovery_mode)}
              >
                {RECOVERY_MODES.map((m) => (
                  <option key={m.value} value={m.value}>
                    {m.label}
                  </option>
                ))}
              </select>
            </label>
            {form.recovery_mode !== "manual" && (
              <label className="block space-y-1 text-sm font-medium">
                Settle window (seconds)
                <input
                  type="number"
                  min={0}
                  className={inputClass}
                  value={form.recovery_window_seconds}
                  onChange={(e) => set("recovery_window_seconds", e.target.value)}
                  placeholder="blank = global default"
                />
              </label>
            )}
            {form.recovery_mode === "threshold" && (
              <label className="block space-y-1 text-sm font-medium">
                Recovery threshold
                <input
                  type="number"
                  step="any"
                  className={inputClass}
                  value={form.recovery_threshold_value}
                  onChange={(e) => set("recovery_threshold_value", e.target.value)}
                  placeholder="blank = fire threshold"
                />
              </label>
            )}
            <label className="block space-y-1 text-sm font-medium">
              Severity
              <select className={inputClass} value={form.severity} onChange={(e) => set("severity", e.target.value)}>
                {SEVERITIES.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </select>
            </label>
          </div>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button form="edit-rule-form" type="submit" disabled={busy}>
            {busy ? "Saving…" : "Save changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
