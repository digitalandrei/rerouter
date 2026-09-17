import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Archive, CopyPlus, Play, Plus, RefreshCw, Save, ShieldCheck } from "lucide-react";
import { toast } from "sonner";
import {
  api,
  ApiError,
  isBundleTerminal,
  type ActionDraft,
  type Device,
  type ManualMitigationPreview,
  type MitigationPreset,
  type RerouteBundle,
  type Template,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import {
  actionDraftPayload,
  actionIdentity,
  applyActionOverrides,
  isCurrentPreview,
  moveOrderedAction,
  expandBulkActions,
} from "@/lib/action-sets";
import { templateLabel } from "@/lib/labels";
import { ActionParamsForm } from "@/components/action-params-form";
import { ApplyResultRow, BundleProgressView } from "@/components/apply-mitigation-dialog";
import { OrderedActionSetEditor, type OrderedActionItem } from "@/components/ordered-action-set-editor";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

function stringValues(params: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(Object.entries(params).map(([key, value]) => [key, String(value)]));
}

function cleanValues(values: Record<string, string>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(values)
      .map(([key, value]) => [key, value.trim()])
      .filter(([, value]) => value !== ""),
  );
}

export default function ManualReroute() {
  const [searchParams, setSearchParams] = useSearchParams();
  const initialBundleId = Number(searchParams.get("bundle")) || null;
  const { hasPermission } = useAuth();
  const canEdit = hasPermission("edit_rules");
  const canRun = hasPermission("trigger_manual_reroute");
  const [presets, setPresets] = useState<MitigationPreset[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [actions, setActions] = useState<ActionDraft[]>([]);
  const [selectedAction, setSelectedAction] = useState<number | null>(null);
  const [templateId, setTemplateId] = useState("");
  const [deviceIds, setDeviceIds] = useState<number[]>([]);
  const [newValuesByDevice, setNewValuesByDevice] = useState<Record<number, Record<string, string>>>({});
  const [bulkPrefixes, setBulkPrefixes] = useState("");
  const [includeMss, setIncludeMss] = useState(false);
  const [mssInterfaceByDevice, setMssInterfaceByDevice] = useState<Record<number, string>>({});
  const [mssValue, setMssValue] = useState("1436");
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [runMode, setRunMode] = useState(initialBundleId !== null);
  const [overrides, setOverrides] = useState<Record<string, { device_id: number; params: Record<string, unknown> }>>({});
  const [reason, setReason] = useState("");
  const [preview, setPreview] = useState<ManualMitigationPreview | null>(null);
  const [bundleId, setBundleId] = useState<number | null>(initialBundleId);
  const [bundle, setBundle] = useState<RerouteBundle | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const requestGeneration = useRef(0);

  const selectedPreset = presets.find((preset) => preset.id === selectedId) ?? null;
  const presetInvalid = selectedPreset?.validation_status === "invalid";
  const presetNeedsPreview = selectedPreset?.validation_status === "needs_preview";
  const selectedTemplate = templates.find((template) => String(template.id) === templateId) ?? null;
  const prefixParam = selectedTemplate
    ? Object.entries(selectedTemplate.parameter_schema).find(([, spec]) => spec.source === "announced_prefix")?.[0] ?? null
    : null;
  const effectiveActions = useMemo(
    () => applyActionOverrides(actions, overrides),
    [actions, overrides],
  );
  const dirty = selectedPreset
    ? name !== selectedPreset.name ||
      description !== (selectedPreset.description ?? "") ||
      JSON.stringify(actions.map(actionDraftPayload)) !==
        JSON.stringify(selectedPreset.actions.map(actionDraftPayload))
    : name.length > 0 || description.length > 0 || actions.length > 0;

  function invalidatePreview() {
    requestGeneration.current += 1;
    setPreview(null);
  }

  function leaveBundleView() {
    setBundleId(null);
    setBundle(null);
    setPollError(null);
    const next = new URLSearchParams(searchParams);
    next.delete("bundle");
    setSearchParams(next, { replace: true });
  }

  function selectPreset(preset: MitigationPreset) {
    leaveBundleView();
    setSelectedId(preset.id);
    setName(preset.name);
    setDescription(preset.description ?? "");
    setActions(preset.actions.map((action) => actionDraftPayload(action)));
    setSelectedAction(null);
    setOverrides({});
    setRunMode(false);
    setReason("");
    invalidatePreview();
  }

  async function openPreset(id: number) {
    setBusy(true);
    try {
      const preset = await api.mitigationPresets.get(id);
      setPresets((current) => current.map((item) => item.id === id ? preset : item));
      selectPreset(preset);
    } catch (error) {
      toast.error(error instanceof ApiError ? error.message : "Could not load saved mitigation");
    } finally { setBusy(false); }
  }

  function startNew() {
    leaveBundleView();
    setSelectedId(null);
    setName("");
    setDescription("");
    setActions([]);
    setSelectedAction(null);
    setOverrides({});
    setRunMode(false);
    setReason("");
    invalidatePreview();
  }

  function startAdHoc() {
    startNew();
    setRunMode(true);
  }

  async function load() {
    setLoadError(null);
    try {
      const [saved, actionTemplates, routers] = await Promise.all([
        api.mitigationPresets.list(), api.templates.list(), api.devices.list(),
      ]);
      const available = saved.filter((preset) => !preset.archived_at);
      setPresets(available);
      setTemplates(actionTemplates.filter((template) => template.enabled && template.provider_type === "device_cli"));
      setDevices(routers);
      const initialId = bundleId !== null ? undefined : selectedId && available.some((preset) => preset.id === selectedId)
        ? selectedId
        : available[0]?.id;
      if (initialId) {
        const current = await api.mitigationPresets.get(initialId);
        setPresets(available.map((item) => item.id === current.id ? current : item));
        selectPreset(current);
      }
    } catch (error) {
      setLoadError(error instanceof ApiError ? error.message : "Could not load manual mitigations");
    }
  }

  useEffect(() => { void load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    const fromUrl = Number(searchParams.get("bundle")) || null;
    if (fromUrl !== bundleId) {
      setBundleId(fromUrl);
      setBundle(null);
      setPollError(null);
      if (fromUrl !== null) setRunMode(true);
    }
  }, [searchParams]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (bundleId === null) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    async function tick() {
      try {
        const next = await api.bundles.get(bundleId!);
        if (cancelled) return;
        setBundle(next);
        setPollError(null);
        if (isBundleTerminal(next.state)) return;
      } catch (error) {
        if (cancelled) return;
        setPollError(error instanceof Error ? error.message : "read failed");
      }
      timer = setTimeout(() => void tick(), 2000);
    }
    void tick();
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [bundleId]);

  function moveAction(index: number, delta: -1 | 1) {
    const target = index + delta;
    if (target < 0 || target >= actions.length) return;
    const next = moveOrderedAction(actions, index, delta);
    setActions(next);
    setSelectedAction(target);
    invalidatePreview();
  }

  function addAction() {
    if (actions.length >= 256) return toast.error("A mitigation can contain at most 256 actions.");
    if (!selectedTemplate || deviceIds.length === 0) return toast.error("Choose an action template and at least one target router.");
    const prefixes = prefixParam
      ? bulkPrefixes.split(/[\n,]/).map((value) => value.trim()).filter(Boolean)
      : [null];
    if (prefixParam && prefixes.length === 0) return toast.error("Enter at least one prefix.");
    const mssTemplate = templates.find((item) => item.name === (selectedTemplate.name === "bgp_advertise_remove" ? "iface_tcp_adjust_mss_remove" : "iface_tcp_adjust_mss"));
    const additions = expandBulkActions({
      templateId: selectedTemplate.id, deviceIds,
      paramsByDevice: Object.fromEntries(deviceIds.map((id) => [id, cleanValues(newValuesByDevice[id] ?? {})])),
      prefixParam, prefixes: prefixes.filter((value): value is string => value !== null),
      mss: includeMss && mssTemplate ? {
        templateId: mssTemplate.id,
        paramsByDevice: Object.fromEntries(deviceIds.map((id) => [id, { interface: mssInterfaceByDevice[id] ?? "", ...(mssTemplate.name === "iface_tcp_adjust_mss" ? { mss: mssValue } : {}) }])),
        placement: selectedTemplate.name === "bgp_advertise_add" ? "before" : "after",
      } : null,
    });
    if (actions.length + additions.length > 256) return toast.error("This bulk addition would exceed the 256-action limit.");
    setActions((current) => [...current, ...additions]);
    setTemplateId("");
    setDeviceIds([]);
    setNewValuesByDevice({});
    setBulkPrefixes("");
    setIncludeMss(false);
    invalidatePreview();
  }

  async function save() {
    if (!name.trim()) return toast.error("Name this manual mitigation before saving.");
    if (actions.length === 0) return toast.error("Add at least one action before saving.");
    setBusy(true);
    try {
      const saved = selectedPreset
        ? await api.mitigationPresets.update(selectedPreset.id, {
            name: name.trim(), description: description.trim() || undefined,
            revision: selectedPreset.revision, actions: actions.map(actionDraftPayload),
          })
        : await api.mitigationPresets.create({
            name: name.trim(), description: description.trim() || undefined, actions: actions.map(actionDraftPayload),
          });
      setPresets((current) => selectedPreset
        ? current.map((preset) => preset.id === saved.id ? saved : preset)
        : [...current, saved].sort((a, b) => a.name.localeCompare(b.name)));
      selectPreset(saved);
      toast.success(selectedPreset ? "Manual mitigation saved" : "Manual mitigation created");
    } catch (error) {
      toast.error(error instanceof ApiError ? error.message : "Save failed");
    } finally { setBusy(false); }
  }

  function setOverride(index: number, next: { device_id: number; params: Record<string, unknown> }) {
    const key = actionIdentity(actions[index], index);
    setOverrides((current) => ({ ...current, [key]: next }));
    invalidatePreview();
  }

  async function preparePreview() {
    if (effectiveActions.length === 0) return;
    const generation = ++requestGeneration.current;
    setBusy(true);
    setPreview(null);
    setBundleId(null);
    setBundle(null);
    try {
      const result = await api.manualMitigations.preview({
        preset_id: selectedPreset?.id,
        preset_revision: selectedPreset?.revision,
        actions: effectiveActions.map(actionDraftPayload),
        reason: reason.trim() || undefined,
      });
      if (isCurrentPreview(generation, requestGeneration.current)) setPreview(result);
    } catch (error) {
      if (isCurrentPreview(generation, requestGeneration.current))
        toast.error(error instanceof ApiError ? error.message : "Preview failed");
    } finally {
      setBusy(false);
    }
  }

  async function applyPreview() {
    if (!preview?.plan_id || !preview.preview_token) return;
    setBusy(true);
    try {
      const accepted = await api.manualMitigations.apply({
        plan_id: preview.plan_id,
        preview_token: preview.preview_token,
      });
      setPreview(null);
      setBundleId(accepted.bundle_id);
      setSearchParams({ bundle: String(accepted.bundle_id) }, { replace: true });
      setBundle(null);
      setPollError(null);
    } catch (error) {
      setPreview(null);
      toast.error(`${error instanceof ApiError ? error.message : "Execution failed"}. Prepare a fresh preview before retrying.`);
    } finally { setBusy(false); }
  }

  const displayActions: OrderedActionItem[] = (runMode ? effectiveActions : actions).map((action, index) => ({
    ...action,
    client_key: actionIdentity(action, index),
    overridden: Boolean(overrides[actionIdentity(action, index)]),
    warning: action.auto_target === "flow_dst_host" && runMode
      ? "Flow auto-target has no standalone rule context. Replace it with a concrete prefix override before preview."
      : null,
  }));
  const selectedRunAction = selectedAction === null ? null : effectiveActions[selectedAction];
  const selectedBaseAction = selectedAction === null ? null : actions[selectedAction];
  const selectedRunTemplate = selectedRunAction
    ? templates.find((template) => template.id === selectedRunAction.reroute_template_id) ?? null
    : null;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Manual mitigations</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
            Save named, ordered action sets. Every run receives a fresh server preview; temporary router and parameter overrides never change the saved mitigation.
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => void load()} disabled={busy}><RefreshCw className="size-4" /> Refresh</Button>
          {canRun && <Button variant="outline" size="sm" onClick={startAdHoc}><Play className="size-4" /> Run once</Button>}
          {canEdit && <Button size="sm" onClick={startNew}><Plus className="size-4" /> New mitigation</Button>}
        </div>
      </div>

      {loadError && <div className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">
        {loadError}. <button className="font-medium underline underline-offset-4" onClick={() => void load()}>Try again</button>
      </div>}

      <div className="grid gap-6 lg:grid-cols-[18rem_minmax(0,1fr)]">
        <Card className="h-fit">
          <CardHeader><CardTitle className="text-base">Saved mitigations</CardTitle><CardDescription>Select one to edit or run once.</CardDescription></CardHeader>
          <CardContent>
            {presets.length === 0 ? <p className="text-sm text-muted-foreground">No saved mitigations yet.</p> : <div className="space-y-1" role="list">
              {presets.map((preset) => <button key={preset.id} type="button" onClick={() => void openPreset(preset.id)} disabled={busy}
                className={`w-full rounded-md px-3 py-2 text-left outline-none focus-visible:ring-2 focus-visible:ring-ring ${selectedId === preset.id ? "bg-accent text-accent-foreground" : "hover:bg-muted"}`}>
                <span className="block truncate text-sm font-medium">{preset.name}</span>
                <span className="block text-xs text-muted-foreground">{preset.actions.length} action{preset.actions.length === 1 ? "" : "s"} · revision {preset.revision}</span>
                {preset.validation_status === "invalid" && <span className="mt-1 block text-xs font-medium text-destructive">Needs attention before preview</span>}
              </button>)}
            </div>}
          </CardContent>
        </Card>

        <div className="min-w-0 space-y-5">
          {!selectedPreset && !canEdit && <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">Select a saved mitigation to inspect it.</CardContent></Card>}
          {(selectedPreset || canEdit || canRun) && <Card>
            <CardHeader><div className="flex flex-wrap items-start justify-between gap-3"><div>
              <CardTitle>{bundleId !== null ? bundle?.source?.preset_name ?? bundle?.source?.name ?? `Mitigation bundle #${bundleId}` : selectedPreset ? selectedPreset.name : runMode ? "Run once" : "New manual mitigation"}</CardTitle>
              <CardDescription>{runMode ? "Run a temporary copy. Saved targets and parameters remain unchanged." : "Actions execute from top to bottom as one mitigation bundle."}</CardDescription>
            </div>{selectedPreset && <div className="flex flex-wrap gap-2">
              <Badge variant="outline" className="tabular-nums">revision {selectedPreset.revision}</Badge>
              {presetInvalid && <Badge variant="destructive">invalid</Badge>}
              {!presetInvalid && presetNeedsPreview && <Badge variant="outline">validation on preview</Badge>}
            </div>}</div></CardHeader>
            <CardContent className="space-y-5">
              {presetInvalid && <div className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">
                <p className="font-medium">This saved mitigation cannot run yet.</p>
                <p className="mt-1 break-words">{selectedPreset?.validation_error ?? "One or more actions failed validation. Edit the set and save before previewing."}</p>
              </div>}
              {!runMode && canEdit && <div className="grid gap-3 sm:grid-cols-2">
                <label className="space-y-1 text-sm font-medium">Name<Input value={name} maxLength={191} onChange={(event) => setName(event.target.value)} /></label>
                <label className="space-y-1 text-sm font-medium sm:col-span-2">Description <span className="font-normal text-muted-foreground">(optional)</span>
                  <textarea className={`${inputClass} min-h-20 resize-y`} maxLength={4000} value={description} onChange={(event) => setDescription(event.target.value)} />
                </label>
              </div>}

              {bundleId === null && <OrderedActionSetEditor actions={displayActions} templates={templates} devices={devices} busy={busy}
                readOnly={runMode || !canEdit} selectedIndex={selectedAction} onSelect={setSelectedAction}
                onMove={!runMode && canEdit ? moveAction : undefined}
                onRemove={!runMode && canEdit ? (index) => { setActions((current) => current.filter((_, i) => i !== index)); setSelectedAction(null); invalidatePreview(); } : undefined}
                onReset={runMode ? (index) => { const key = actionIdentity(actions[index], index); setOverrides(({ [key]: _removed, ...current }) => current); invalidatePreview(); } : undefined} />}

              {!runMode && selectedPreset?.recent_runs && selectedPreset.recent_runs.length > 0 && <div className="space-y-2">
                <h3 className="text-sm font-medium">Recent runs</h3>
                <ul className="divide-y divide-border rounded-md border border-border text-sm">
                  {selectedPreset.recent_runs.slice(0, 5).map((run) => <li key={run.bundle_id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                    <Link className="font-medium text-primary underline-offset-4 hover:underline" to={`/manual-mitigations?bundle=${run.bundle_id}`}>Bundle #{run.bundle_id}</Link>
                    <span className="text-muted-foreground">{run.state} · {new Date(run.created_at).toLocaleString()}</span>
                  </li>)}
                </ul>
              </div>}

              {bundleId === null && ((!runMode && canEdit) || (runMode && !selectedPreset && canRun)) && <div className="space-y-3 rounded-md border border-dashed border-border p-3">
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1 text-sm font-medium">Action template<select className={inputClass} value={templateId} onChange={(event) => { setTemplateId(event.target.value); setNewValuesByDevice({}); setBulkPrefixes(""); setIncludeMss(false); }}>
                    <option value="">Select template…</option>{templates.map((template) => <option key={template.id} value={template.id}>{templateLabel(template)}</option>)}
                  </select></label>
                  <fieldset className="space-y-1 text-sm font-medium"><legend>Target routers</legend><div className="max-h-36 space-y-1 overflow-y-auto rounded-md border border-input p-2">
                    {devices.map((device) => <label key={device.id} className="flex items-center gap-2 font-normal"><input type="checkbox" checked={deviceIds.includes(device.id)} onChange={() => setDeviceIds((current) => current.includes(device.id) ? current.filter((id) => id !== device.id) : [...current, device.id])} />{device.name}</label>)}
                  </div></fieldset>
                </div>
                {selectedTemplate && prefixParam && <label className="block space-y-1 text-sm font-medium">Prefixes <span className="font-normal text-muted-foreground">(comma or line separated)</span><textarea className={`${inputClass} min-h-16`} value={bulkPrefixes} onChange={(event) => setBulkPrefixes(event.target.value)} /></label>}
                {selectedTemplate && deviceIds.map((target) => <div key={target} className="space-y-2 rounded-md border border-border p-3"><div className="text-sm font-medium">{devices.find((device) => device.id === target)?.name}</div><ActionParamsForm schema={selectedTemplate.parameter_schema} deviceId={target} values={newValuesByDevice[target] ?? {}} onChange={(values) => setNewValuesByDevice((current) => ({ ...current, [target]: values }))} omitParams={prefixParam ? new Set([prefixParam]) : undefined} />
                  {includeMss && <label className="block space-y-1 text-sm font-medium">MSS interface<Input value={mssInterfaceByDevice[target] ?? ""} onChange={(event) => setMssInterfaceByDevice((current) => ({ ...current, [target]: event.target.value }))} /></label>}</div>)}
                {selectedTemplate && ["bgp_advertise_add", "bgp_advertise_remove"].includes(selectedTemplate.name) && <div className="flex flex-wrap items-center gap-3 rounded-md border border-border p-3"><label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={includeMss} onChange={(event) => setIncludeMss(event.target.checked)} />Also {selectedTemplate.name === "bgp_advertise_add" ? "add" : "remove"} MSS clamp per router</label>{includeMss && selectedTemplate.name === "bgp_advertise_add" && <Input className="max-w-32" value={mssValue} onChange={(event) => setMssValue(event.target.value)} aria-label="MSS value" />}</div>}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs tabular-nums text-muted-foreground">{actions.length}/256 actions</span>
                  <Button type="button" size="sm" variant="outline" onClick={addAction} disabled={!selectedTemplate || deviceIds.length === 0 || actions.length >= 256}><CopyPlus className="size-4" /> Add to ordered set</Button>
                </div>
              </div>}

              {!runMode && canEdit && selectedBaseAction && selectedRunTemplate && <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3">
                <div><h3 className="text-sm font-medium">Edit action {selectedAction! + 1}</h3>
                  <p className="text-xs text-muted-foreground">Changes remain local until you save the complete ordered set.</p></div>
                <label className="block space-y-1 text-sm font-medium">Target router<select className={inputClass} value={selectedBaseAction.device_id}
                  onChange={(event) => { const next = [...actions]; next[selectedAction!] = { ...selectedBaseAction, device_id: Number(event.target.value), params: {} }; setActions(next); invalidatePreview(); }}>
                  {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
                </select></label>
                <ActionParamsForm schema={selectedRunTemplate.parameter_schema} deviceId={selectedBaseAction.device_id}
                  values={stringValues(selectedBaseAction.params)} onChange={(values) => {
                    const next = [...actions]; next[selectedAction!] = { ...selectedBaseAction, params: cleanValues(values) }; setActions(next); invalidatePreview();
                  }} />
              </div>}

              {runMode && bundleId === null && selectedRunAction && selectedBaseAction && selectedRunTemplate && <div className="space-y-3 rounded-md border border-border bg-muted/30 p-3">
                <div><h3 className="text-sm font-medium">Temporary override for action {selectedAction! + 1}</h3>
                  <p className="text-xs text-muted-foreground">Only the target router and parameters can change. Template, order, and enabled state stay fixed.</p></div>
                <label className="block space-y-1 text-sm font-medium">Target router<select className={inputClass} value={selectedRunAction.device_id}
                  onChange={(event) => setOverride(selectedAction!, { device_id: Number(event.target.value), params: {} })}>
                  {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
                </select></label>
                <ActionParamsForm schema={selectedRunTemplate.parameter_schema} deviceId={selectedRunAction.device_id}
                  values={stringValues(selectedRunAction.params)}
                  onChange={(values) => setOverride(selectedAction!, { device_id: selectedRunAction.device_id, params: cleanValues(values) })} />
              </div>}

              {!runMode ? <div className="flex flex-wrap justify-between gap-2 border-t border-border pt-4"><div>
                {selectedPreset && canEdit && <Button variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setDeleteOpen(true)} disabled={busy}><Archive className="size-4" /> Archive</Button>}
              </div><div className="flex flex-wrap gap-2">
                {selectedPreset && canRun && <Button variant="outline" onClick={() => { setRunMode(true); setSelectedAction(actions.length ? 0 : null); invalidatePreview(); }} disabled={actions.length === 0 || dirty || presetInvalid} title={presetInvalid ? "Fix invalid actions before running" : dirty ? "Save or discard edits before running this saved revision" : "Run this saved mitigation once"}><Play className="size-4" /> {dirty ? "Save before running" : "Run once"}</Button>}
                {canEdit && <Button onClick={() => void save()} disabled={busy || actions.length === 0 || !name.trim()}><Save className="size-4" /> {busy ? "Saving…" : "Save complete set"}</Button>}
              </div></div> : <div className="space-y-4 border-t border-border pt-4">
                {bundleId === null && <label className="block space-y-1 text-sm font-medium">Run reason <span className="font-normal text-muted-foreground">(recorded in audit history)</span>
                  <Input value={reason} maxLength={500} onChange={(event) => { setReason(event.target.value); invalidatePreview(); }} placeholder="Why is this mitigation being run?" />
                </label>}
                {preview && <div className="space-y-3" aria-live="polite"><div className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4" /> Exact server preview</div>
                  {preview.results.map((result, index) => <ApplyResultRow key={index} r={result} />)}
                  {preview.expires_at && <p className="text-xs text-muted-foreground">Preview expires {new Date(preview.expires_at).toLocaleString()}.</p>}
                  {preview.operating_mode === "observe" && <p className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">Observe mode: this is the complete would-run plan. Nothing executed and no execution approval was issued.</p>}
                </div>}
                {bundleId !== null && <BundleProgressView bundle={bundle} bundleId={bundleId} totalHint={effectiveActions.length} pollError={pollError} />}
                <div className="flex flex-wrap justify-end gap-2">
                  <Button variant="outline" disabled={busy} onClick={() => { leaveBundleView(); setRunMode(false); setOverrides({}); setSelectedAction(null); invalidatePreview(); }}>Back to saved mitigation</Button>
                  {!preview && bundleId === null && <Button onClick={() => void preparePreview()} disabled={busy || effectiveActions.length === 0}>{busy ? "Preparing…" : "Preview exact plan"}</Button>}
                  {preview?.operating_mode === "enforce" && <Button variant="destructive" onClick={() => void applyPreview()} disabled={busy || !preview.plan_id || !preview.preview_token}>{busy ? "Starting…" : "Execute reviewed plan"}</Button>}
                </div>
              </div>}
            </CardContent>
          </Card>}
        </div>
      </div>

      {selectedPreset && <ConfirmDialog open={deleteOpen} onOpenChange={setDeleteOpen} title={`Archive “${selectedPreset.name}”?`}
        description="The saved mitigation will no longer be available for new runs. Existing execution history and rule copies remain unchanged."
        confirmLabel="Archive mitigation" destructive onConfirm={async () => {
          try {
            await api.mitigationPresets.remove(selectedPreset.id, selectedPreset.revision);
            setPresets((current) => current.filter((preset) => preset.id !== selectedPreset.id));
            setDeleteOpen(false);
            startNew();
          } catch (error) {
            toast.error(error instanceof ApiError ? error.message : "Archive failed");
          }
        }} />}
    </div>
  );
}
