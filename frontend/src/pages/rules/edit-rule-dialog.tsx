/**
 * Edit an existing detection rule. The target (interface) is immutable on the
 * server (recreate to retarget), so this edits name / condition / window /
 * severity only.
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
import { METRICS, SEVERITIES } from "./rule-constants";

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
  const [form, setForm] = useState({
    name: rule.name,
    metric: rule.metric,
    operator: rule.operator as ">" | "<",
    threshold_value: String(rule.threshold_value),
    window_minutes: String(rule.duration_seconds / 60),
    consecutive_samples: String(rule.consecutive_samples),
    severity: rule.severity,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function set<K extends keyof typeof form>(field: K, value: (typeof form)[K]) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function save(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const updated = await api.rules.update(rule.id, {
        name: form.name.trim(),
        metric: form.metric,
        operator: form.operator,
        threshold_value: parseFloat(form.threshold_value),
        duration_seconds: Math.max(0, Math.round(parseFloat(form.window_minutes || "0") * 60)),
        consecutive_samples: parseInt(form.consecutive_samples, 10),
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
          <label className="block space-y-1 text-sm font-medium">
            Name
            <input required className={inputClass} value={form.name} onChange={(e) => set("name", e.target.value)} />
          </label>
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Metric
              <select className={inputClass} value={form.metric} onChange={(e) => set("metric", e.target.value)}>
                {METRICS.map((m) => (
                  <option key={m.value} value={m.value}>
                    {m.label}
                  </option>
                ))}
              </select>
            </label>
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
              />
            </label>
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
            <label className="block space-y-1 text-sm font-medium">
              …or consecutive samples
              <input
                type="number"
                min={1}
                required
                className={inputClass}
                value={form.consecutive_samples}
                onChange={(e) => set("consecutive_samples", e.target.value)}
              />
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
