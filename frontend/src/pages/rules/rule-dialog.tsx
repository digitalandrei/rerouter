/**
 * Create or edit a detection rule — one modal for both. In CREATE mode the
 * device + interface are selectable; in EDIT mode the target is read-only
 * (recreate to retarget) and editing the condition resets the rule's evaluation
 * streak server-side. Persistence is per metric family (flows = sliding window,
 * SNMP = consecutive samples); recovery mirrors the trigger unless set to
 * threshold/manual.
 */
import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { api, type Rule, type RuleOperator, type Device, type Interface, ApiError } from "@/lib/api";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { InfoHint } from "@/components/info-hint";
import {
  METRICS,
  SEVERITIES,
  OPERATORS,
  RECOVERY_MODES,
  FLOW_PROTOCOLS,
  SUMMABLE_METRICS,
  isFlowMetric,
  thresholdHint,
} from "./rule-constants";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

interface RuleDialogProps {
  /** null/undefined = create; a rule = edit. */
  rule?: Rule | null;
  devices: Device[];
  onClose: () => void;
  onSaved: (saved: Rule) => void;
}

export function RuleDialog({ rule, devices, onClose, onSaved }: RuleDialogProps) {
  const isCreate = !rule;

  const [form, setForm] = useState({
    name: rule?.name ?? "",
    device_id: rule?.device_id != null ? String(rule.device_id) : "",
    interface_id: rule?.interface_id != null ? String(rule.interface_id) : "",
    metric: rule?.metric ?? "rx_bps",
    flow_protocol: rule?.flow_protocol != null ? String(rule.flow_protocol) : "",
    flow_port: rule?.flow_port != null ? String(rule.flow_port) : "",
    flow_port_kind: (rule?.flow_port_kind ?? "dst") as "src" | "dst",
    operator: (rule?.operator ?? ">") as RuleOperator,
    threshold_value: rule != null ? String(rule.threshold_value) : "",
    window_minutes: rule != null ? String(rule.duration_seconds / 60) : "1",
    consecutive_samples: String(rule?.consecutive_samples || 3),
    recovery_mode: (rule?.recovery_mode ?? "auto") as "auto" | "threshold" | "manual",
    recovery_threshold_value:
      rule?.recovery_threshold_value != null ? String(rule.recovery_threshold_value) : "",
    recovery_window_minutes:
      rule?.recovery_window_seconds != null ? String(rule.recovery_window_seconds / 60) : "",
    recovery_consecutive_samples:
      rule?.recovery_consecutive_samples != null ? String(rule.recovery_consecutive_samples) : "",
    severity: rule?.severity ?? "warning",
  });
  const [deviceInterfaces, setDeviceInterfaces] = useState<Interface[]>([]);
  // Aggregation (`sum`) is create-only. Members are interfaces that may span devices.
  const [aggregation, setAggregation] = useState<"single" | "sum">(
    rule?.metric_aggregation ?? "single",
  );
  const [members, setMembers] = useState<number[]>(rule?.member_interface_ids ?? []);
  const [allInterfaces, setAllInterfaces] = useState<{ device: Device; ifaces: Interface[] }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // In create mode, load the chosen device's interfaces (single-target rules).
  useEffect(() => {
    if (!isCreate || !form.device_id) {
      setDeviceInterfaces([]);
      return;
    }
    api.devices
      .interfaces(parseInt(form.device_id, 10))
      .then(setDeviceInterfaces)
      .catch(() => setDeviceInterfaces([]));
  }, [isCreate, form.device_id]);

  // For a summed rule (create), load every device's interfaces so members can be
  // picked across devices.
  useEffect(() => {
    if (!isCreate || aggregation !== "sum") return;
    let cancelled = false;
    Promise.all(
      devices.map((d) =>
        api.devices
          .interfaces(d.id)
          .then((ifaces) => ({ device: d, ifaces }))
          .catch(() => ({ device: d, ifaces: [] as Interface[] })),
      ),
    ).then((groups) => {
      if (!cancelled) setAllInterfaces(groups);
    });
    return () => {
      cancelled = true;
    };
  }, [isCreate, aggregation, devices]);

  // When switching to sum, coerce the metric to a summable one.
  useEffect(() => {
    if (aggregation === "sum" && !SUMMABLE_METRICS.includes(form.metric)) {
      setForm((f) => ({ ...f, metric: "rx_bps" }));
    }
  }, [aggregation, form.metric]);

  function toggleMember(id: number) {
    setMembers((m) => (m.includes(id) ? m.filter((x) => x !== id) : [...m, id]));
  }

  function set<K extends keyof typeof form>(field: K, value: (typeof form)[K]) {
    setForm((f) => {
      const next = { ...f, [field]: value };
      if (field === "device_id") next.interface_id = "";
      return next;
    });
  }

  const isSum = isCreate ? aggregation === "sum" : rule!.metric_aggregation === "sum";
  // Metric options: summed rules use summable rates only; otherwise the family is
  // fixed in edit mode (recreate to switch families).
  const metricOptions = isSum
    ? METRICS.filter((m) => SUMMABLE_METRICS.includes(m.value))
    : isCreate
      ? METRICS
      : METRICS.filter((m) => isFlowMetric(m.value) === isFlowMetric(rule!.metric));
  const isFlow = !isSum && isFlowMetric(form.metric);

  async function save(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (isCreate && isSum && members.length === 0) {
      setError("Select at least one interface to sum.");
      return;
    }
    if (isCreate && !isSum && !form.interface_id) {
      setError("Select a device and interface.");
      return;
    }
    setBusy(true);

    const flow = isFlow
      ? {
          flow_direction: "ingress" as const, // locked to ingress for now
          flow_protocol: form.flow_protocol ? parseInt(form.flow_protocol, 10) : null,
          flow_port: form.flow_port ? parseInt(form.flow_port, 10) : null,
          flow_port_kind: form.flow_port ? form.flow_port_kind : null,
        }
      : {};
    // Persistence per family: flow = window, SNMP = consecutive samples (the
    // unused control is 0 = disabled).
    const duration_seconds = isFlow
      ? Math.max(0, Math.round(parseFloat(form.window_minutes || "0") * 60))
      : 0;
    const consecutive_samples = isFlow ? 0 : Math.max(1, parseInt(form.consecutive_samples, 10) || 1);
    const common = {
      name: form.name.trim(),
      metric: form.metric,
      ...flow,
      operator: form.operator,
      threshold_value: parseFloat(form.threshold_value),
      duration_seconds,
      consecutive_samples,
      recovery_mode: form.recovery_mode,
      recovery_threshold_value:
        form.recovery_mode === "threshold" && form.recovery_threshold_value
          ? parseFloat(form.recovery_threshold_value)
          : null,
      recovery_window_seconds:
        form.recovery_mode === "threshold" && isFlow && form.recovery_window_minutes
          ? Math.max(0, Math.round(parseFloat(form.recovery_window_minutes) * 60))
          : null,
      recovery_consecutive_samples:
        form.recovery_mode === "threshold" && !isFlow && form.recovery_consecutive_samples
          ? Math.max(1, parseInt(form.recovery_consecutive_samples, 10))
          : null,
      severity: form.severity,
    };

    try {
      const saved = isCreate
        ? await api.rules.create(
            isSum
              ? {
                  ...common,
                  target_kind: "interface_group",
                  metric_aggregation: "sum",
                  interface_ids: members,
                  interface_id: null,
                  device_id: null,
                  enabled: true,
                  automatic_reroute_enabled: false,
                  manual_apply_enabled: false,
                  reroute_template_id: null,
                }
              : {
                  ...common,
                  target_kind: "interface",
                  interface_id: parseInt(form.interface_id, 10),
                  device_id: parseInt(form.device_id, 10),
                  enabled: true,
                  automatic_reroute_enabled: false,
                  manual_apply_enabled: false,
                  reroute_template_id: null,
                },
          )
        : await api.rules.update(rule!.id, common);
      toast.success(`${isCreate ? "Created" : "Updated"} rule "${saved.name}"`);
      onSaved(saved);
      onClose();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : `Failed to ${isCreate ? "create" : "update"} rule`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{isCreate ? "New detection rule" : `Edit rule — ${rule!.name}`}</DialogTitle>
        </DialogHeader>
        <form id="rule-form" onSubmit={save} className="space-y-4">
          <label className="block space-y-1 text-sm font-medium">
            Name
            <input required className={inputClass} value={form.name} onChange={(e) => set("name", e.target.value)} />
          </label>

          {/* Aggregation toggle (create only): one interface, or the sum across many. */}
          {isCreate && (
            <label className="block space-y-1 text-sm font-medium">
              <span className="inline-flex items-center gap-1">
                Target{" "}
                <InfoHint text="Single = one interface. Summed = threshold the total of a rate metric across several interfaces, which may be on different devices." />
              </span>
              <select
                className={inputClass}
                value={aggregation}
                onChange={(e) => setAggregation(e.target.value as "single" | "sum")}
              >
                <option value="single">Single interface</option>
                <option value="sum">Summed across interfaces (multi-device)</option>
              </select>
            </label>
          )}

          {/* Target — selectable on create, read-only on edit. */}
          {isCreate && !isSum && (
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block space-y-1 text-sm font-medium">
                Device
                <select required className={inputClass} value={form.device_id} onChange={(e) => set("device_id", e.target.value)}>
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
                  onChange={(e) => set("interface_id", e.target.value)}
                  disabled={!form.device_id}
                >
                  <option value="">{form.device_id ? "Select interface…" : "Select device first"}</option>
                  {deviceInterfaces.map((iface) => (
                    <option key={iface.id} value={iface.id}>
                      {iface.if_name}
                      {iface.if_alias ? ` — ${iface.if_alias}` : ""}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}

          {/* Summed members — checkboxes grouped by device. */}
          {isCreate && isSum && (
            <div className="space-y-1 text-sm font-medium">
              <span>Interfaces to sum ({members.length} selected)</span>
              <div className="max-h-48 overflow-y-auto rounded-md border border-input p-2">
                {allInterfaces.length === 0 && (
                  <p className="text-xs font-normal text-muted-foreground">Loading interfaces…</p>
                )}
                {allInterfaces.map(({ device, ifaces }) => (
                  <div key={device.id} className="mb-2">
                    <p className="text-xs font-semibold text-muted-foreground">{device.name}</p>
                    {ifaces.map((iface) => (
                      <label key={iface.id} className="flex items-center gap-2 py-0.5 text-sm font-normal">
                        <input
                          type="checkbox"
                          checked={members.includes(iface.id)}
                          onChange={() => toggleMember(iface.id)}
                        />
                        {iface.if_name}
                        {iface.if_alias ? ` — ${iface.if_alias}` : ""}
                      </label>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          )}

          {!isCreate && (
            <p className="text-xs text-muted-foreground">
              Target:{" "}
              <span className="font-medium">
                {isSum
                  ? `${rule!.member_interface_ids?.length ?? 0} interfaces (summed)`
                  : rule!.interface_name ?? `interface #${rule!.interface_id}`}
              </span>
              {!isSum && rule!.device_name ? ` on ${rule!.device_name}` : ""} · recreate the rule to retarget.
            </p>
          )}

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

            {isFlow && (
              <>
                <label className="block space-y-1 text-sm font-medium">
                  <span className="inline-flex items-center gap-1">
                    Flow direction <InfoHint text="Flows are evaluated on ingress only for now." />
                  </span>
                  <select className={`${inputClass} opacity-60`} value="ingress" disabled>
                    <option value="ingress">ingress</option>
                  </select>
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  Protocol
                  <select className={inputClass} value={form.flow_protocol} onChange={(e) => set("flow_protocol", e.target.value)}>
                    {FLOW_PROTOCOLS.map((p) => (
                      <option key={p.value} value={p.value}>
                        {p.label}
                      </option>
                    ))}
                  </select>
                  {form.flow_protocol && !form.flow_port && (
                    <p className="text-xs text-muted-foreground">
                      Add a port selector when filtering by protocol.
                    </p>
                  )}
                </label>
                <label className="block space-y-1 text-sm font-medium">
                  <span className="inline-flex items-center gap-1">
                    Port (optional) <InfoHint text="Match a specific L4 port. Blank = the whole interface." />
                  </span>
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
                onChange={(e) => set("operator", e.target.value as RuleOperator)}
              >
                {OPERATORS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-1 text-sm font-medium">
              <span className="inline-flex items-center gap-1">
                Threshold <InfoHint text={thresholdHint(form.metric)} />
              </span>
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

            {isFlow ? (
              <label className="block space-y-1 text-sm font-medium">
                <span className="inline-flex items-center gap-1">
                  Sliding window (minutes) <InfoHint text="Flows are bucketed per minute — fire once the metric stays past the threshold for this long." />
                </span>
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
                <span className="inline-flex items-center gap-1">
                  Consecutive samples <InfoHint text="Fire after this many consecutive polls past the threshold. A single sample crossing back resets the count to 0." />
                </span>
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

          {/* Recovery — full width, with the two threshold values below it. */}
          <label className="block space-y-1 text-sm font-medium">
            <span className="inline-flex items-center gap-1">
              Recovery{" "}
              <InfoHint
                text={
                  form.recovery_mode === "manual"
                    ? "Stays firing until an operator clears it (the Clear button on the rule)."
                    : form.recovery_mode === "threshold"
                      ? "Clears when the metric crosses back past a separate recovery value (a hysteresis band)."
                      : isFlow
                        ? "Clears once the metric stays back under the threshold for the same sliding window used to fire."
                        : "Clears after the same number of consecutive samples back under the threshold that fired it."
                }
              />
            </span>
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
          {form.recovery_mode === "threshold" && (
            <div className="grid gap-3 sm:grid-cols-2">
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
              {isFlow ? (
                <label className="block space-y-1 text-sm font-medium">
                  Recovery window (minutes)
                  <input
                    type="number"
                    min={0}
                    step="0.5"
                    className={inputClass}
                    value={form.recovery_window_minutes}
                    onChange={(e) => set("recovery_window_minutes", e.target.value)}
                    placeholder="blank = firing window"
                  />
                </label>
              ) : (
                <label className="block space-y-1 text-sm font-medium">
                  Recovery samples
                  <input
                    type="number"
                    min={1}
                    className={inputClass}
                    value={form.recovery_consecutive_samples}
                    onChange={(e) => set("recovery_consecutive_samples", e.target.value)}
                    placeholder="blank = firing samples"
                  />
                </label>
              )}
            </div>
          )}

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
          <Button form="rule-form" type="submit" disabled={busy}>
            {busy ? "Saving…" : isCreate ? "Create rule" : "Save changes"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
