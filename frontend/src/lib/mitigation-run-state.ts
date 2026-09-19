import type { PresetRunSummary, RerouteBundle } from "@/lib/api";
import { bundleVerificationMode } from "@/lib/api";
import type { Tone } from "@/components/status-badge";

export type RunPresentation = {
  label: string;
  detail: string;
  tone: Tone;
  remaining: number;
  known: number;
  unknown: number;
};

export function presentMitigationRun(run: RerouteBundle): RunPresentation {
  const remaining = run.remaining_changes ?? run.remaining_mutations ?? run.still_applied_reroute_ids?.length ?? 0;
  const unknown = run.unknown_effects ?? 0;
  const lifecycle = run.lifecycle_state ?? (remaining > 0 ? "active" : "inactive");
  const execution = run.execution_state ?? run.state;
  const reverting = ["recovery_claimed", "recovery_running"].includes(lifecycle) || execution === "compensating";
  let label = "Status unavailable";
  let detail = "Refresh this run before making a decision.";
  let tone: RunPresentation["tone"] = "neutral";
  if (["planned", "running"].includes(execution)) { label = "Applying"; detail = `${run.completed_actions}/${run.total_actions} steps completed.`; }
  else if (reverting) { label = "Reverting"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "warn"; }
  else if (execution === "compensation_blocked" || lifecycle === "recovery_blocked" || unknown > 0) { label = "Needs attention"; detail = unknown > 0 ? `${remaining} known change${remaining === 1 ? " remains" : "s remain"}; ${unknown} outcome${unknown === 1 ? " is" : "s are"} unknown.` : `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "bad"; }
  else if (execution === "compensated") { label = "Failed—changes reverted"; detail = "The attempted changes were restored."; tone = "warn"; }
  else if (execution === "succeeded" && remaining > 0) { label = run.trigger_type === "automatic" ? "Applied automatically" : "Applied manually"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "good"; }
  else if (execution === "succeeded" && remaining === 0 && run.recovery_bundle_id) { label = "Reverted"; detail = "No owned router changes remain."; tone = "good"; }
  else if (execution === "succeeded" && remaining === 0) { label = run.parent_bundle_id ? "Revert completed" : "No changes needed"; detail = run.parent_bundle_id ? "The original router changes were restored." : "The router already matched the requested state."; tone = "good"; }
  else if (["failed", "aborted"].includes(execution) && remaining === 0) { label = "Failed—no changes applied"; detail = "No router changes remain from this run."; tone = "warn"; }
  else if (["failed", "aborted"].includes(execution)) { label = "Partially applied"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "bad"; }
  if (bundleVerificationMode(run) === "configuration_only") detail += " BGP advertisements were not verified.";
  return { label, detail, tone, remaining, known: Math.max(0, remaining), unknown };
}

export function recentRunAsBundle(run: PresetRunSummary): RerouteBundle {
  return { ...run, id: run.id ?? run.bundle_id, rule_id: run.rule_id ?? null, trigger_type: run.trigger_type ?? "manual", state: run.state as RerouteBundle["state"], failure_policy: run.failure_policy ?? "abort_and_compensate", total_actions: run.total_actions ?? 0, completed_actions: run.completed_actions ?? 0, failure_reason: run.failure_reason ?? null, started_at: run.started_at ?? null, finished_at: run.finished_at ?? null, actions: run.actions ?? [], still_applied_reroute_ids: run.still_applied_reroute_ids ?? [] };
}

export function runSourceName(run: RerouteBundle): string {
  return run.source_preset_name ?? run.source?.preset_name ?? run.source?.name ?? `Run #${run.id}`;
}
