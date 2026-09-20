import type { PresetRunSummary, RunSummary, RerouteBundle } from "@/lib/api";
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

export function presentMitigationRun(run: RunSummary): RunPresentation {
  const remaining = run.remaining_changes ?? run.remaining_mutations ?? 0;
  const unknown = run.unknown_effects ?? 0;
  const lifecycle = run.lifecycle_state ?? (remaining > 0 ? "active" : "inactive");
  const execution = run.execution_state ?? run.state;
  const reverting = ["recovery_claimed", "recovery_running"].includes(lifecycle) || execution === "compensating";
  let label = "Status unavailable";
  let detail = "Refresh this run before making a decision.";
  let tone: RunPresentation["tone"] = "neutral";
  if (run.parent_bundle_id && ["planned", "pending", "running", "verifying", "compensating"].includes(execution)) { label = "Reverting"; detail = `${run.completed_actions}/${run.total_actions} restore steps completed.`; tone = "warn"; }
  else if (run.parent_bundle_id && ["failed", "aborted", "compensation_blocked"].includes(execution)) { label = "Revert failed"; detail = "Inspect the source mitigation for remaining changes and unknown outcomes."; tone = "bad"; }
  else if (run.parent_bundle_id && execution === "compensated") { label = "Revert failed—restoration undone"; detail = "Inspect the source mitigation for remaining changes and unknown outcomes."; tone = "bad"; }
  else if (["planned", "running"].includes(execution)) { label = "Applying"; detail = `${run.completed_actions}/${run.total_actions} steps completed.`; }
  else if (reverting) { label = "Reverting"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "warn"; }
  else if (execution === "compensation_blocked" || lifecycle === "recovery_blocked" || unknown > 0) { label = "Needs attention"; detail = unknown > 0 ? `${remaining} known change${remaining === 1 ? " remains" : "s remain"}; ${unknown} outcome${unknown === 1 ? " is" : "s are"} unknown.` : `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "bad"; }
  else if (execution === "compensated") { label = "Failed—changes reverted"; detail = "The attempted changes were restored."; tone = "warn"; }
  else if (execution === "succeeded" && remaining > 0) { label = run.trigger_type === "automatic" ? "Applied automatically" : "Applied manually"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "good"; }
  else if (execution === "succeeded" && remaining === 0 && unknown === 0 && run.latest_recovery?.state === "succeeded") { label = "Reverted"; detail = "No owned router changes remain."; tone = "good"; }
  else if (execution === "succeeded" && remaining === 0) { label = run.parent_bundle_id ? "Revert completed" : "No changes needed"; detail = run.parent_bundle_id ? "The original router changes were restored." : "The router already matched the requested state."; tone = "good"; }
  else if (["failed", "aborted"].includes(execution) && remaining === 0) { label = "Failed—no changes applied"; detail = "No router changes remain from this run."; tone = "warn"; }
  else if (["failed", "aborted"].includes(execution)) { label = "Partially applied"; detail = `${remaining} router change${remaining === 1 ? "" : "s"} remain.`; tone = "bad"; }
  if (bundleVerificationMode(run) === "configuration_only") detail += " BGP advertisements were not verified.";
  return { label, detail, tone, remaining, known: Math.max(0, remaining), unknown };
}

export function recentRunAsBundle(run: PresetRunSummary): RunSummary {
  return { ...run, id: run.id ?? run.bundle_id, rule_id: run.rule_id ?? null, trigger_type: run.trigger_type ?? "manual", state: run.state as RunSummary["state"], failure_policy: run.failure_policy ?? "abort_and_compensate", total_actions: run.total_actions ?? 0, completed_actions: run.completed_actions ?? 0, failure_reason: run.failure_reason ?? null, started_at: run.started_at ?? null, finished_at: run.finished_at ?? null };
}

export function runSourceName(run: RunSummary): string {
  return run.source_preset_name ?? run.source?.preset_name ?? run.source?.name ?? `Run #${run.id}`;
}

export function chooseRecoveryChildId(acceptedId: number | null, parentId: number | null): number | null {
  if (acceptedId !== null && (parentId === null || acceptedId > parentId)) return acceptedId;
  return parentId ?? acceptedId;
}

export function recoveryProgressHeading(state?: string | null): "Needs attention" | "Revert completed" | "Reverting" {
  if (["failed", "aborted", "compensated", "compensation_blocked"].includes(state ?? "")) return "Needs attention";
  return state === "succeeded" ? "Revert completed" : "Reverting";
}

export function recoveryFieldLabel(source: RerouteBundle, child?: RerouteBundle | null, targetId?: number | null): string {
  const id = targetId ?? child?.id ?? source.recovery_bundle_id ?? source.latest_recovery_bundle_id;
  const matchingChild = child?.id === id ? child : null;
  const matchingSummary = source.latest_recovery?.id === id ? source.latest_recovery : null;
  let state: string | undefined;
  if (matchingChild) state = matchingChild.state;
  else if (matchingSummary) state = matchingSummary.state;
  if (id && state === "succeeded") { const finished = matchingChild?.finished_at ?? matchingSummary?.finished_at; return `Completed${finished ? ` ${new Date(finished).toLocaleString()}` : ""} · recovery #${id}`; }
  if (id && ["failed", "aborted", "compensated", "compensation_blocked"].includes(state ?? "")) return `Needs attention · recovery #${id}`;
  if (id && ["planned", "pending", "running", "verifying", "compensating"].includes(state ?? "")) return `Revert in progress · recovery #${id}`;
  if (id) return `Revert accepted · recovery #${id}`;
  if (source.recovery_deadline) return `Revert scheduled for ${new Date(source.recovery_deadline).toLocaleString()} · pending until automatic recovery is allowed`;
  if (source.take_control?.available) return "Rule-driven automatic recovery eligible";
  return source.automatic_recovery_cancelled_at ? "Automatic recovery cancelled · manual revert only" : "Until manually reverted";
}
