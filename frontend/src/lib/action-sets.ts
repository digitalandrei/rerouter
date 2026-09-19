import type { ActionDraft, ManualMitigationCapabilities, ManualMitigationPreview, Template, VerificationMode } from "@/lib/api";

export function configurationOnlyEligible(actions: ActionDraft[], templates: Template[], capabilities: ManualMitigationCapabilities): boolean {
  const enabled = actions.filter((action) => action.enabled !== false);
  return enabled.length > 0
    && new Set(enabled.map((action) => action.device_id)).size === 1
    && capabilities.configuration_test_device_ids.includes(enabled[0].device_id)
    && enabled.every((action) => capabilities.configuration_test_templates.includes(templates.find((template) => template.id === action.reroute_template_id)?.name ?? ""));
}

export function previewMatchesVerificationMode(preview: ManualMitigationPreview, requested: VerificationMode): boolean {
  const returned = preview.verification_mode ?? "routing";
  return returned === requested && (returned !== "configuration_only" || preview.routing_verified === false);
}

export type ActionOverride = {
  device_id: number;
  params: Record<string, unknown>;
};

export function actionIdentity(action: ActionDraft, index: number): string {
  return String(action.id ?? `draft-${index}`);
}

/** Strict request shape: hydrated labels/status/position never cross the API. */
export function actionDraftPayload(action: ActionDraft): ActionDraft {
  return {
    ...(action.id === undefined ? {} : { id: action.id }),
    reroute_template_id: action.reroute_template_id,
    device_id: action.device_id,
    params: { ...(action.params ?? {}) },
    enabled: action.enabled ?? true,
    auto_target: action.auto_target ?? null,
  };
}

export function moveOrderedAction(
  actions: ActionDraft[],
  index: number,
  delta: -1 | 1,
): ActionDraft[] {
  const target = index + delta;
  if (target < 0 || target >= actions.length) return actions;
  const next = [...actions];
  const [moved] = next.splice(index, 1);
  next.splice(target, 0, moved);
  return next;
}

/** Preset import is a value copy: preset row IDs are deliberately discarded. */
export function importActionCopies(
  existing: ActionDraft[],
  preset: ActionDraft[],
  mode: "append" | "replace",
): ActionDraft[] {
  const copies = preset.map((action) => {
    const copy = actionDraftPayload(action);
    delete copy.id;
    return copy;
  });
  return mode === "replace"
    ? copies
    : [...existing.map(actionDraftPayload), ...copies];
}

/** Apply run-once values to a fresh action object without mutating saved state. */
export function applyActionOverrides(
  actions: ActionDraft[],
  overrides: Record<string, ActionOverride>,
): ActionDraft[] {
  return actions.map((action, index) => {
    const override = overrides[actionIdentity(action, index)];
    return override
      ? { ...actionDraftPayload(action), device_id: override.device_id, params: { ...override.params } }
      : actionDraftPayload(action);
  });
}

export function isCurrentPreview(requestGeneration: number, currentGeneration: number): boolean {
  return requestGeneration === currentGeneration;
}

export function expandBulkActions(input: {
  templateId: number;
  deviceIds: number[];
  paramsByDevice: Record<number, Record<string, unknown>>;
  prefixParam?: string | null;
  prefixes?: string[];
  autoTarget?: string | null;
  mss?: {
    templateId: number;
    paramsByDevice: Record<number, Record<string, unknown>>;
    placement: "before" | "after";
  } | null;
}): ActionDraft[] {
  const primary: ActionDraft[] = [];
  const companions: ActionDraft[] = [];
  const prefixes = input.prefixParam ? input.prefixes ?? [] : [null];
  for (const deviceId of input.deviceIds) {
    for (const prefix of prefixes) {
      const params = { ...(input.paramsByDevice[deviceId] ?? {}) };
      if (input.prefixParam && prefix) params[input.prefixParam] = prefix;
      primary.push({ reroute_template_id: input.templateId, device_id: deviceId, params, enabled: true, auto_target: input.autoTarget ?? null });
    }
    if (input.mss) companions.push({ reroute_template_id: input.mss.templateId, device_id: deviceId, params: { ...(input.mss.paramsByDevice[deviceId] ?? {}) }, enabled: true, auto_target: null });
  }
  return input.mss?.placement === "before"
    ? [...companions, ...primary]
    : [...primary, ...companions];
}
