import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useBlocker, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { Archive, CopyPlus, Eye, Pencil, Play, Plus, RefreshCw, RotateCcw, Save, ShieldAlert, ShieldCheck, Trash2 } from "lucide-react";
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
  type VerificationMode,
  type ManualMitigationCapabilities,
} from "@/lib/api";
import { useAuth } from "@/lib/auth";
import {
  actionDraftPayload,
  actionIdentity,
  applyActionOverrides,
  isCurrentPreview,
  moveOrderedAction,
  expandBulkActions,
  configurationOnlyEligible as isConfigurationOnlyEligible,
  previewMatchesVerificationMode,
} from "@/lib/action-sets";
import { orderTemplatesForChoice, templateGuidance, templateLabel } from "@/lib/labels";
import { ActionParamsForm } from "@/components/action-params-form";
import { ApplyResultRow, BundleProgressView } from "@/components/apply-mitigation-dialog";
import { OrderedActionSetEditor, type OrderedActionItem } from "@/components/ordered-action-set-editor";
import { ActionsAndRevert } from "@/components/actions-and-revert";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { RowActionButton } from "@/components/row-action-button";
import { AsyncRetryButton } from "@/components/async-retry-button";
import { ToneBadge } from "@/components/status-badge";
import { presentMitigationRun, recentRunAsBundle } from "@/lib/mitigation-run-state";

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
  const { id: routeIdRaw } = useParams();
  const routeId = Number(routeIdRaw) || null;
  const location = useLocation();
  const navigate = useNavigate();
  const listMode = location.pathname === "/manual-mitigations" && !new URLSearchParams(location.search).has("bundle");
  const editorMode = location.pathname.endsWith("/edit") || location.pathname.endsWith("/new");
  const routeRunMode = location.pathname.endsWith("/run");
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
  const [refreshing, setRefreshing] = useState(false);
  const [retryingCapabilities, setRetryingCapabilities] = useState(false);
  const [deletingPresetId, setDeletingPresetId] = useState<number | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [runMode, setRunMode] = useState(initialBundleId !== null);
  const [overrides, setOverrides] = useState<Record<string, { device_id: number; params: Record<string, unknown> }>>({});
  const [reason, setReason] = useState("");
  const [revertAfter, setRevertAfter] = useState("");
  const [preview, setPreview] = useState<ManualMitigationPreview | null>(null);
  const [verificationMode, setVerificationMode] = useState<VerificationMode>("routing");
  const [capabilities, setCapabilities] = useState<ManualMitigationCapabilities>({ configuration_test_device_ids: [], configuration_test_templates: [] });
  const [capabilitiesState, setCapabilitiesState] = useState<"loading" | "ready" | "error">("loading");
  const [bundleId, setBundleId] = useState<number | null>(initialBundleId);
  const [bundle, setBundle] = useState<RerouteBundle | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [activeByPreset, setActiveByPreset] = useState<Record<number, number>>({});
  const requestGeneration = useRef(0);
  const loadGeneration = useRef(0);
  const allowNavigation = useRef(false);

  const selectedPreset = presets.find((preset) => preset.id === selectedId) ?? null;
  const activePresetRuns = selectedPreset?.active_runs ?? selectedPreset?.recent_runs?.filter((run) => run.active || (run.lifecycle_state && run.lifecycle_state !== "inactive") || (run.remaining_changes ?? run.remaining_mutations ?? 0) > 0 || (run.unknown_effects ?? 0) > 0) ?? [];
  const presetInvalid = Boolean(selectedPreset && (selectedPreset.definition_status ?? selectedPreset.validation_status) !== "ready" && selectedPreset.validation_status !== "valid");
  const presetNeedsPreview = selectedPreset?.validation_status === "needs_preview";
  const selectedTemplate = templates.find((template) => String(template.id) === templateId) ?? null;
  const prefixParam = selectedTemplate
    ? Object.entries(selectedTemplate.parameter_schema).find(([, spec]) => spec.source === "announced_prefix")?.[0] ?? null
    : null;
  const effectiveActions = useMemo(
    () => applyActionOverrides(actions, overrides),
    [actions, overrides],
  );
  const configurationOnlyEligible = useMemo(() => isConfigurationOnlyEligible(effectiveActions, templates, capabilities), [effectiveActions, capabilities, templates]);
  const configurationTestDeviceName = useMemo(() => {
    const deviceId = effectiveActions.find((action) => action.enabled !== false)?.device_id;
    return devices.find((device) => device.id === deviceId)?.name ?? (deviceId ? `device #${deviceId}` : "the eligible lab device");
  }, [effectiveActions, devices]);
  const dirty = selectedPreset
    ? name !== selectedPreset.name ||
      description !== (selectedPreset.description ?? "") ||
      JSON.stringify(actions.map(actionDraftPayload)) !==
        JSON.stringify(selectedPreset.actions.map(actionDraftPayload))
    : name.length > 0 || description.length > 0 || actions.length > 0;
  const blocker = useBlocker(() => editorMode && dirty && !allowNavigation.current);

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

  async function load() {
    const generation = ++loadGeneration.current;
    setLoadError(null);
    try {
      const [saved, actionTemplates, routers] = await Promise.all([
        api.mitigationPresets.list(), api.templates.list(), api.devices.list(),
      ]);
      if (generation !== loadGeneration.current) return;
      const available = saved.filter((preset) => !preset.archived_at);
      setPresets(available);
      // Keep disabled/legacy templates visible so an existing needs-setup action
      // can still be inspected and repaired. New actions only offer enabled ones.
      setTemplates(actionTemplates.filter((template) => template.provider_type === "device_cli"));
      setDevices(routers);
      void loadCapabilities(generation);
      const initialId = bundleId !== null ? undefined : routeId ?? undefined;
      if (initialId) {
        const current = await api.mitigationPresets.get(initialId);
        if (generation !== loadGeneration.current) return;
        setPresets(available.map((item) => item.id === current.id ? current : item));
        selectPreset(current);
        setRunMode(routeRunMode);
      }
    } catch (error) {
      setLoadError(error instanceof ApiError ? error.message : "Could not load manual mitigations");
    }
  }

  async function refreshPage() { setRefreshing(true); try { await load(); } finally { setRefreshing(false); } }
  async function archivePreset(preset: MitigationPreset) { if (deletingPresetId !== null || !window.confirm(`Archive “${preset.name}”? Active runs and history will remain unchanged.`)) return; setDeletingPresetId(preset.id); try { await api.mitigationPresets.remove(preset.id, preset.revision); setPresets((current) => current.filter((item) => item.id !== preset.id)); } catch (cause) { toast.error(cause instanceof Error ? cause.message : "Archive failed"); } finally { setDeletingPresetId(null); } }

  useEffect(() => { void load(); return () => { loadGeneration.current += 1; }; }, [routeId, location.pathname]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { allowNavigation.current = false; }, [location.pathname]);

  async function loadCapabilities(generation = loadGeneration.current) {
    setCapabilitiesState("loading");
    try {
      const value = await api.manualMitigations.capabilities();
      if (generation === loadGeneration.current) { setCapabilities(value); setCapabilitiesState("ready"); }
    } catch {
      if (generation === loadGeneration.current) setCapabilitiesState("error");
    }
  }
  async function retryCapabilities() { const generation = loadGeneration.current; setRetryingCapabilities(true); try { const value = await api.manualMitigations.capabilities(); if (generation === loadGeneration.current) { setCapabilities(value); setCapabilitiesState("ready"); } } catch { if (generation === loadGeneration.current) setCapabilitiesState("error"); } finally { setRetryingCapabilities(false); } }

  useEffect(() => {
    if (!listMode) return;
    let cancelled = false;
    void (async () => {
      const counts: Record<number, number> = {}; let page = 1;
      while (true) {
        const response = await api.bundles.list({ lifecycle: "active", page, per_page: 200 });
        const items = Array.isArray(response) ? response : response.items;
        for (const run of items) { const presetId = run.source?.preset_id; if (presetId) counts[presetId] = (counts[presetId] ?? 0) + 1; }
        if (Array.isArray(response) || page * response.per_page >= response.total) break;
        page += 1;
      }
      if (!cancelled) setActiveByPreset(counts);
    })().catch(() => { if (!cancelled) setActiveByPreset({}); });
    return () => { cancelled = true; };
  }, [listMode]);

  useEffect(() => {
    if (location.pathname.endsWith("/new")) startNew();
    if (routeRunMode || searchParams.get("run") === "once") setRunMode(true);
  }, [location.pathname, location.search]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!dirty || !editorMode) return;
    const beforeUnload = (event: BeforeUnloadEvent) => { event.preventDefault(); event.returnValue = ""; };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty, editorMode]);

  useEffect(() => { if (blocker.state === "blocked") { if (window.confirm("Discard unsaved changes?")) blocker.proceed(); else blocker.reset(); } }, [blocker]);

  useEffect(() => {
    if (capabilitiesState === "ready" && verificationMode === "configuration_only" && !configurationOnlyEligible) {
      setVerificationMode("routing");
      setRevertAfter("");
      invalidatePreview();
      toast.error("Configuration-only test was cleared because the effective actions are no longer eligible for the EMA3 lab target.");
    }
  }, [configurationOnlyEligible, verificationMode, capabilitiesState]); // eslint-disable-line react-hooks/exhaustive-deps

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
      allowNavigation.current = true;
      navigate(`/manual-mitigations/${saved.id}`);
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
    if (selectedPreset && presetInvalid) return toast.error("Every step must be ready before the complete mitigation can run.");
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
        revert_after_seconds: verificationMode === "routing" && revertAfter ? Number(revertAfter) : undefined,
        verification_mode: verificationMode,
      });
      if (isCurrentPreview(generation, requestGeneration.current)) {
        if (!previewMatchesVerificationMode(result, verificationMode)) {
          toast.error("The preview returned a different verification scope. Prepare a new preview before running.");
          setPreview(null);
        } else setPreview(result);
      }
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
  function renderActionEditor(index: number) {
    const baseAction = actions[index];
    if (!baseAction) return null;
    const effectiveAction = effectiveActions[index] ?? baseAction;
    const action = runMode ? effectiveAction : baseAction;
    const template = templates.find((item) => item.id === action.reroute_template_id) ?? null;

    if (runMode) {
      if (!template) return <p className="mt-3 border-t border-border pt-3 text-sm text-destructive">This action template is unavailable, so its temporary values cannot be changed.</p>;
      return <div className="mt-3 space-y-3 border-t border-border pt-3">
        <div><h3 className="text-sm font-semibold">Temporary override for action {index + 1}</h3>
          <p className="text-xs text-muted-foreground">Only this run uses these values. The saved action stays unchanged.</p></div>
        <label className="block space-y-1 text-sm font-medium">Target router<select className={inputClass} value={action.device_id}
          onChange={(event) => setOverride(index, { device_id: Number(event.target.value), params: {} })}>
          {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
        </select></label>
        <ActionParamsForm schema={template.parameter_schema} deviceId={action.device_id}
          values={stringValues(action.params)} onChange={(values) => setOverride(index, { device_id: action.device_id, params: cleanValues(values) })} />
      </div>;
    }

    return <div className="mt-3 space-y-3 border-t border-border pt-3">
      <div><h3 className="text-sm font-semibold">Edit action {index + 1}</h3>
        <p className="text-xs text-muted-foreground">Changes remain in this draft until you save the mitigation.</p></div>
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block space-y-1 text-sm font-medium">Action template<select className={inputClass} value={baseAction.reroute_template_id}
          onChange={(event) => { const next = [...actions]; next[index] = { ...baseAction, reroute_template_id: Number(event.target.value), params: {} }; setActions(next); invalidatePreview(); }}>
          {orderTemplatesForChoice(templates).map((item) => <option key={item.id} value={item.id}>{templateLabel(item)}{item.enabled ? "" : " (unavailable for new actions)"}</option>)}
        </select></label>
        <label className="block space-y-1 text-sm font-medium">Target router<select className={inputClass} value={baseAction.device_id}
          onChange={(event) => { const next = [...actions]; next[index] = { ...baseAction, device_id: Number(event.target.value), params: {} }; setActions(next); invalidatePreview(); }}>
          {devices.map((device) => <option key={device.id} value={device.id}>{device.name}</option>)}
        </select></label>
      </div>
      <label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={baseAction.enabled ?? true}
        onChange={(event) => { const next = [...actions]; next[index] = { ...baseAction, enabled: event.target.checked }; setActions(next); invalidatePreview(); }} />Enabled</label>
      {template
        ? <ActionParamsForm schema={template.parameter_schema} deviceId={baseAction.device_id}
            values={stringValues(baseAction.params)} onChange={(values) => { const next = [...actions]; next[index] = { ...baseAction, params: cleanValues(values) }; setActions(next); invalidatePreview(); }} />
        : <p className="text-sm text-destructive">The saved template is unavailable. Choose another template to repair this action.</p>}
    </div>;
  }
  const readiness = (preset: MitigationPreset) => preset.definition_status ?? (preset.actions.length === 0 ? "draft" : preset.validation_status === "valid" ? "ready" : "needs_setup");
  const shownPresets = presets.filter((preset) => `${preset.name} ${preset.description ?? ""}`.toLowerCase().includes(search.trim().toLowerCase()));

  if (listMode) return <div className="space-y-6">
    <div className="flex flex-wrap items-start justify-between gap-3"><div><h1 className="text-2xl font-bold tracking-tight">Manual mitigations</h1><p className="mt-1 text-sm text-muted-foreground">Saved ordered action sets. Archiving a definition never reverts an active run.</p></div><div className="flex gap-2">{canRun && <Button variant="outline" asChild><Link to="/manual-mitigations/new?run=once"><Play className="size-4" /> Run once</Link></Button>}{canEdit && <Button asChild><Link to="/manual-mitigations/new"><Plus className="size-4" /> Add</Link></Button>}</div></div>
    <Input aria-label="Search manual mitigations" placeholder="Search by name or description…" value={search} onChange={(event) => setSearch(event.target.value)} />
    {loadError && <div role="alert" className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">{loadError} <AsyncRetryButton onRetry={load} /></div>}
    <div className="overflow-x-auto rounded-md border"><table className="w-full text-sm"><thead className="bg-muted/50 text-left"><tr><th className="px-3 py-2">Name</th><th className="px-3 py-2">Readiness</th><th className="px-3 py-2">Routers</th><th className="px-3 py-2">Steps</th><th className="px-3 py-2">Active runs</th><th className="px-3 py-2">Last result</th><th className="px-3 py-2 text-right">Actions</th></tr></thead><tbody>{shownPresets.map((preset) => <tr key={preset.id} className="border-t"><td className="px-3 py-3"><Link className="font-medium hover:underline" to={`/manual-mitigations/${preset.id}`}>{preset.name}</Link><p className="max-w-xl truncate text-xs text-muted-foreground">{preset.description || "No description"}</p></td><td className="px-3 py-3"><Badge variant={readiness(preset) === "ready" ? "outline" : readiness(preset) === "needs_setup" ? "destructive" : "secondary"}>{readiness(preset).replace("_", " ")}</Badge></td><td className="px-3 py-3">{new Set(preset.actions.map((action) => action.device_id)).size}</td><td className="px-3 py-3 tabular-nums">{preset.actions.length}</td><td className="px-3 py-3 tabular-nums">{activeByPreset[preset.id] ?? 0}</td><td className="px-3 py-3">{preset.recent_runs?.[0]?.state ?? "Never run"}</td><td className="px-3 py-3"><div className="flex justify-end gap-1">
      {canRun && readiness(preset) === "ready" ? <RowActionButton label={`Run ${preset.name}`} asChild><Link to={`/manual-mitigations/${preset.id}/run`}><Play className="size-4" /></Link></RowActionButton> : canRun ? <RowActionButton label={`Review setup for ${preset.name}`} asChild><Link to={`/manual-mitigations/${preset.id}`}><ShieldAlert className="size-4" /></Link></RowActionButton> : null}
      {canRun && (activeByPreset[preset.id] ?? 0) > 0 && <RowActionButton label={`Revert active runs for ${preset.name}`} asChild><Link to={`/mitigations?tab=active&preset_id=${preset.id}`}><RotateCcw className="size-4" /></Link></RowActionButton>}
      {canEdit && <RowActionButton label={`Edit ${preset.name}`} asChild><Link to={`/manual-mitigations/${preset.id}/edit`}><Pencil className="size-4" /></Link></RowActionButton>}
      {canEdit && <RowActionButton label={deletingPresetId === preset.id ? `Archiving ${preset.name}…` : `Delete ${preset.name}`} tone="destructive" disabled={deletingPresetId !== null} loading={deletingPresetId === preset.id} loadingLabel={`Archiving ${preset.name}…`} onClick={() => void archivePreset(preset)}><Trash2 className="size-4" /></RowActionButton>}
      <RowActionButton label="Details" asChild><Link to={`/manual-mitigations/${preset.id}`}><Eye className="size-4" /></Link></RowActionButton>
    </div></td></tr>)}</tbody></table>{!loadError && shownPresets.length === 0 && <p className="p-8 text-center text-sm text-muted-foreground">{presets.length ? "No mitigations match this search." : "No saved manual mitigations yet."}</p>}</div>
  </div>;

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
          <Button variant="outline" size="sm" onClick={() => { if (!dirty || window.confirm("Discard unsaved changes and reload?")) void refreshPage(); }} disabled={busy} loading={refreshing} loadingLabel="Refreshing…"><RefreshCw className="size-4" /> Refresh</Button>
          {canRun && <Button variant="outline" size="sm" asChild><Link to="/manual-mitigations/new?run=once"><Play className="size-4" /> Run once</Link></Button>}
          {canEdit && <Button size="sm" asChild><Link to="/manual-mitigations/new"><Plus className="size-4" /> New mitigation</Link></Button>}
        </div>
      </div>

      {loadError && <div className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">
        {loadError}. <AsyncRetryButton onRetry={load} />
      </div>}

      <div>
        <div className="min-w-0 space-y-5">
          {!selectedPreset && !canEdit && <Card><CardContent className="py-8 text-center text-sm text-muted-foreground">Select a saved mitigation to inspect it.</CardContent></Card>}
          {(selectedPreset || canEdit || canRun) && <Card>
            <CardHeader><div className="flex flex-wrap items-start justify-between gap-3"><div>
              <CardTitle>{bundleId !== null ? bundle?.source?.preset_name ?? bundle?.source?.name ?? `Mitigation run #${bundleId}` : selectedPreset ? selectedPreset.name : runMode ? "Run once" : "New manual mitigation"}</CardTitle>
              <CardDescription>{runMode ? "Run a temporary copy. Saved targets and parameters remain unchanged." : "Actions execute from top to bottom as one run."}</CardDescription>
            </div>{selectedPreset && <div className="flex flex-wrap items-center gap-2">
              <Badge variant="outline" className="tabular-nums">revision {selectedPreset.revision}</Badge>
              {presetInvalid && <Badge variant="destructive">invalid</Badge>}
              {!presetInvalid && presetNeedsPreview && <Badge variant="outline">validation on preview</Badge>}
              {!runMode && !editorMode && canEdit && <Button size="sm" asChild><Link to={`/manual-mitigations/${selectedPreset.id}/edit`}>Edit mitigation</Link></Button>}
            </div>}</div></CardHeader>
            <CardContent className="space-y-5">
              {presetInvalid && <div className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive" role="alert">
                <p className="font-medium">{selectedPreset?.definition_status === "draft" ? "Draft — add and configure every step before running." : "Needs setup — the complete action set is blocked."}</p>
                <p className="mt-1 break-words">{selectedPreset?.validation_error ?? "One or more steps are incomplete. All saved steps remain visible; none will be silently omitted."}</p>
              </div>}
              {!runMode && editorMode && canEdit && <div className="grid gap-3 sm:grid-cols-2">
                <label className="space-y-1 text-sm font-medium">Name<Input value={name} maxLength={191} onChange={(event) => setName(event.target.value)} /></label>
                <label className="space-y-1 text-sm font-medium sm:col-span-2">Description <span className="font-normal text-muted-foreground">(optional)</span>
                  <textarea className={`${inputClass} min-h-20 resize-y`} maxLength={4000} value={description} onChange={(event) => setDescription(event.target.value)} />
                </label>
              </div>}

              {!runMode && activePresetRuns.length > 0 && <div className="space-y-2 rounded-md border p-4">
                <h3 className="text-sm font-semibold">Current state</h3>
                {activePresetRuns.map((run) => { const bundleRun = recentRunAsBundle(run); const state = presentMitigationRun(bundleRun); const devices = run.affected_devices?.map((device) => device.name ?? device.device_name ?? `Device ${device.id ?? device.device_id}`).join(", "); return <div key={run.bundle_id} className="space-y-1 rounded-md bg-muted/40 p-3 text-sm"><div className="flex flex-wrap items-center gap-2"><ToneBadge tone={state.tone}>{state.label}</ToneBadge><span>Run #{run.bundle_id}</span><Button asChild className="ml-auto" size="sm" variant="outline"><Link to={`/mitigations?tab=active&run=${run.bundle_id}`}>{run.revert?.available ? "Review & revert" : "Review run"}</Link></Button></div><p className="text-xs text-muted-foreground">{state.known} known changes · {state.unknown} unknown effects{devices ? ` · ${devices}` : ""}</p><p className="text-xs text-muted-foreground">{run.triggered_by ?? "system"} · {run.started_at ? new Date(run.started_at).toLocaleString() : "not started"} · {run.recovery_deadline ? `Revert scheduled for ${new Date(run.recovery_deadline).toLocaleString()} · pending until automatic recovery is allowed` : "Until manually reverted"}</p>{bundleRun.verification_mode === "configuration_only" && <p className="text-xs text-muted-foreground">BGP advertisements were not verified.</p>}{run.source_preset_revision && run.source_preset_revision !== selectedPreset!.revision && <p className="text-xs text-amber-700 dark:text-amber-300">This run used revision {run.source_preset_revision}; the saved mitigation is now revision {selectedPreset!.revision}.</p>}</div>; })}
              </div>}

              {bundleId === null && <OrderedActionSetEditor actions={displayActions} templates={templates} devices={devices} busy={busy}
                readOnly={runMode || !editorMode || !canEdit} selectedIndex={selectedAction}
                onSelect={(runMode && canRun) || (!runMode && editorMode && canEdit) ? setSelectedAction : undefined}
                editLabel={runMode ? "Override" : "Edit"} renderEditor={renderActionEditor}
                onMove={!runMode && editorMode && canEdit ? moveAction : undefined}
                onRemove={!runMode && editorMode && canEdit ? (index) => { setActions((current) => current.filter((_, i) => i !== index)); setSelectedAction(null); invalidatePreview(); } : undefined}
                onReset={runMode ? (index) => { const key = actionIdentity(actions[index], index); setOverrides(({ [key]: _removed, ...current }) => current); invalidatePreview(); } : undefined} />}

              {!runMode && selectedPreset?.recent_runs && selectedPreset.recent_runs.length > 0 && <div className="space-y-2">
                <h3 className="text-sm font-medium">Recent runs</h3>
                <ul className="divide-y divide-border rounded-md border border-border text-sm">
                  {selectedPreset.recent_runs.slice(0, 5).map((run) => { const bundleRun = recentRunAsBundle(run); const state = presentMitigationRun(bundleRun); const active = run.active ?? state.remaining > 0; return <li key={run.bundle_id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                    <div className="flex flex-wrap items-center gap-2"><strong>Run #{run.bundle_id}</strong><ToneBadge tone={state.tone}>{state.label}</ToneBadge><span className="text-muted-foreground">{new Date(run.created_at).toLocaleString()}</span>{active && <span className="block text-xs text-muted-foreground">{state.known} known changes · {state.unknown} unknown effects</span>}</div>
                    <Button asChild size="sm" variant="outline"><Link to={`/mitigations?tab=active&run=${run.bundle_id}`}>{active ? "Review & revert" : "Review run"}</Link></Button>
                  </li>; })}
                </ul>
              </div>}

              {bundleId === null && ((!runMode && editorMode && canEdit) || (runMode && !selectedPreset && canRun)) && <div className="space-y-3 rounded-md border border-dashed border-border p-3">
                <div><h3 className="text-sm font-semibold">Add actions</h3><p className="text-xs text-muted-foreground">Choose a template and one or more routers to append new steps.</p></div>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1 text-sm font-medium">Action template<select className={inputClass} value={templateId} onChange={(event) => { setTemplateId(event.target.value); setNewValuesByDevice({}); setBulkPrefixes(""); setIncludeMss(false); }}>
                    <option value="">Select template…</option>{orderTemplatesForChoice(templates.filter((template) => template.enabled)).map((template) => <option key={template.id} value={template.id}>{templateLabel(template)}</option>)}
                  </select></label>
                  <fieldset className="space-y-1 text-sm font-medium"><legend>Target routers</legend><div className="max-h-36 space-y-1 overflow-y-auto rounded-md border border-input p-2">
                    {devices.map((device) => <label key={device.id} className="flex items-center gap-2 font-normal"><input type="checkbox" checked={deviceIds.includes(device.id)} onChange={() => setDeviceIds((current) => current.includes(device.id) ? current.filter((id) => id !== device.id) : [...current, device.id])} />{device.name}</label>)}
                  </div></fieldset>
                </div>
                {selectedTemplate && templateGuidance(selectedTemplate.name) && <p className="text-xs text-muted-foreground">{templateGuidance(selectedTemplate.name)}</p>}
                {selectedTemplate && prefixParam && <label className="block space-y-1 text-sm font-medium">Prefixes <span className="font-normal text-muted-foreground">(comma or line separated)</span><textarea className={`${inputClass} min-h-16`} value={bulkPrefixes} onChange={(event) => setBulkPrefixes(event.target.value)} /></label>}
                {selectedTemplate && deviceIds.map((target) => <div key={target} className="space-y-2 rounded-md border border-border p-3"><div className="text-sm font-medium">{devices.find((device) => device.id === target)?.name}</div><ActionParamsForm schema={selectedTemplate.parameter_schema} deviceId={target} values={newValuesByDevice[target] ?? {}} onChange={(values) => setNewValuesByDevice((current) => ({ ...current, [target]: values }))} omitParams={prefixParam ? new Set([prefixParam]) : undefined} />
                  {includeMss && <label className="block space-y-1 text-sm font-medium">MSS interface<Input value={mssInterfaceByDevice[target] ?? ""} onChange={(event) => setMssInterfaceByDevice((current) => ({ ...current, [target]: event.target.value }))} /></label>}</div>)}
                {selectedTemplate && ["bgp_advertise_add", "bgp_advertise_remove"].includes(selectedTemplate.name) && <div className="flex flex-wrap items-center gap-3 rounded-md border border-border p-3"><label className="flex items-center gap-2 text-sm font-medium"><input type="checkbox" checked={includeMss} onChange={(event) => setIncludeMss(event.target.checked)} />Also {selectedTemplate.name === "bgp_advertise_add" ? "add" : "remove"} MSS clamp per router</label>{includeMss && selectedTemplate.name === "bgp_advertise_add" && <Input className="max-w-32" value={mssValue} onChange={(event) => setMssValue(event.target.value)} aria-label="MSS value" />}</div>}
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs tabular-nums text-muted-foreground">{actions.length}/256 actions</span>
                  <Button type="button" size="sm" variant="outline" onClick={addAction} disabled={!selectedTemplate || deviceIds.length === 0 || actions.length >= 256}><CopyPlus className="size-4" /> Add to ordered set</Button>
                </div>
              </div>}

              {bundleId === null && <ActionsAndRevert actions={runMode ? effectiveActions : actions} deviceNames={Object.fromEntries(devices.map((device) => [device.id, device.name]))} />}
              {!runMode ? <div className="flex flex-wrap justify-between gap-2 border-t border-border pt-4"><div>
                {selectedPreset && editorMode && canEdit && <Button variant="ghost" className="text-destructive hover:text-destructive" onClick={() => setDeleteOpen(true)} disabled={busy}><Archive className="size-4" /> Archive</Button>}
              </div><div className="flex flex-wrap gap-2">
                {selectedPreset && canRun && <Button variant="outline" asChild><Link to={`/manual-mitigations/${selectedPreset.id}/run`}><Play className="size-4" /> Run</Link></Button>}
                {selectedPreset && !editorMode && canEdit && <Button asChild><Link to={`/manual-mitigations/${selectedPreset.id}/edit`}>Edit</Link></Button>}
                {editorMode && <Button variant="outline" onClick={() => navigate(selectedPreset ? `/manual-mitigations/${selectedPreset.id}` : "/manual-mitigations")}>Cancel</Button>}
                {editorMode && canEdit && <Button onClick={() => void save()} disabled={!name.trim()} loading={busy} loadingLabel="Saving…"><Save className="size-4" /> Save</Button>}
              </div></div> : <div className="space-y-4 border-t border-border pt-4">
                {bundleId === null && <fieldset className="space-y-2"><legend className="text-sm font-medium">Verification scope</legend>
                  <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="radio" name="verification-mode" checked={verificationMode === "routing"} onChange={() => { setVerificationMode("routing"); invalidatePreview(); }} /><span><strong>Normal routing verification</strong><span className="block text-xs text-muted-foreground">Apply the reviewed plan and verify its routing outcome.</span></span></label>
                  <label className="flex items-start gap-2 text-sm"><input className="mt-1" type="radio" name="verification-mode" checked={verificationMode === "configuration_only"} disabled={capabilitiesState !== "ready" || !configurationOnlyEligible} onChange={() => { setVerificationMode("configuration_only"); setRevertAfter(""); invalidatePreview(); }} /><span><strong>Configuration-only lab test — {configurationTestDeviceName}</strong><span className="block text-xs text-muted-foreground">Available only when every enabled action targets this eligible lab device and uses an approved template.</span></span></label>
                  {capabilitiesState === "loading" && <p role="status" className="text-xs text-muted-foreground">Checking configuration-only lab eligibility…</p>}
                  {(capabilitiesState === "error" || retryingCapabilities) && <div className="flex flex-wrap items-center gap-2 text-xs text-amber-800 dark:text-amber-300" role="alert"><span>{retryingCapabilities ? "Checking lab eligibility…" : "Lab eligibility is unavailable. Normal routing runs remain available; a selected lab scope is retained but cannot be previewed or confirmed."}</span><Button type="button" size="sm" variant="outline" onClick={() => void retryCapabilities()} loading={retryingCapabilities} loadingLabel="Checking lab eligibility…">Retry lab eligibility</Button></div>}
                  {verificationMode === "configuration_only" && <p role="alert" className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">Configuration-only test — router configuration will change; BGP advertisement is not verified.</p>}
                </fieldset>}
                {bundleId === null && <label className="block space-y-1 text-sm font-medium">Run reason <span className="font-normal text-muted-foreground">(recorded in audit history)</span>
                  <Input value={reason} maxLength={500} disabled={busy} onChange={(event) => { setReason(event.target.value); invalidatePreview(); }} placeholder="Why is this mitigation being run?" />
                </label>}
                {bundleId === null && <label className="block max-w-sm space-y-1 text-sm font-medium">Revert schedule<select className={inputClass} value={revertAfter} disabled={verificationMode === "configuration_only"} onChange={(event) => { setRevertAfter(event.target.value); invalidatePreview(); }}><option value="">Until manually reverted</option><option value="900">After 15 minutes</option><option value="3600">After 1 hour</option><option value="14400">After 4 hours</option><option value="86400">After 24 hours</option></select><span className="block text-xs font-normal text-muted-foreground">{verificationMode === "configuration_only" ? "Configuration-only tests have no automatic recovery. Revert the reviewed run manually." : "Timed recovery is paused unless Enforce mode and the automatic master switch are both enabled. Manual revert remains available."}</span></label>}
                {preview && <div className="space-y-3" aria-live="polite"><div className="flex items-center gap-2 text-sm font-medium"><ShieldCheck className="size-4" /> Exact server preview</div>
                  {(preview.verification_mode ?? "routing") === "configuration_only" && <p className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">Configuration-only test — router configuration will change; BGP advertisement is not verified.</p>}
                  {preview.results.map((result, index) => <ApplyResultRow key={index} r={result} />)}
                  {preview.expires_at && <p className="text-xs text-muted-foreground">Preview expires {new Date(preview.expires_at).toLocaleString()}.</p>}
                  {preview.operating_mode === "observe" && <p className="rounded-md border border-amber-400 bg-amber-50 p-3 text-sm font-medium text-amber-900 dark:border-amber-700 dark:bg-amber-950/30 dark:text-amber-200">Observe mode disables automatic response. This one-use preview can authorize this explicit manual run after confirmation.</p>}
                </div>}
                {bundleId !== null && <BundleProgressView bundle={bundle} bundleId={bundleId} totalHint={effectiveActions.length} pollError={pollError} />}
                <div className="flex flex-wrap justify-end gap-2">
                  <Button variant="outline" disabled={busy} onClick={() => { const presetId = selectedPreset?.id ?? bundle?.source?.preset_id; setBundleId(null); setBundle(null); setPollError(null); setRunMode(false); if (presetId) navigate(`/manual-mitigations/${presetId}`); else navigate("/manual-mitigations"); }}>{(selectedPreset?.id ?? bundle?.source?.preset_id) ? "Return to mitigation details" : "Return to manual mitigations"}</Button>
                  {!preview && bundleId === null && <div className="space-y-1"><p className="text-xs text-muted-foreground">Step 1 · Preview changes — reads current router configuration; no configuration changes are made. Preview time depends on router response times and the number of actions.</p><Button onClick={() => void preparePreview()} disabled={effectiveActions.length === 0 || presetInvalid || (verificationMode === "configuration_only" && capabilitiesState !== "ready")} loading={busy} loadingLabel="Preparing exact preview…">Preview changes</Button></div>}
                  {preview && <div className="space-y-1"><p className="text-xs text-muted-foreground">Step 2 · Review and explicitly confirm the exact changes.</p><Button variant="destructive" onClick={() => void applyPreview()} disabled={!preview.plan_id || !preview.preview_token || (verificationMode === "configuration_only" && capabilitiesState !== "ready")} loading={busy} loadingLabel="Starting mitigation…">Apply reviewed changes</Button></div>}
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
