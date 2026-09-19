import { describe, expect, it } from "vitest";
import type { RerouteBundle } from "@/lib/api";
import { chooseRecoveryChildId, presentMitigationRun, recoveryFieldLabel, recoveryProgressHeading } from "@/lib/mitigation-run-state";

const liveFixture = {
  id: 1,
  rule_id: null,
  trigger_type: "manual",
  state: "succeeded",
  execution_state: "succeeded",
  lifecycle_state: "active",
  failure_policy: "abort_and_compensate",
  total_actions: 8,
  completed_actions: 8,
  remaining_mutations: 8,
  failure_reason: null,
  started_at: "2026-09-19T08:00:00Z",
  finished_at: "2026-09-19T08:01:00Z",
  created_at: "2026-09-19T08:00:00Z",
  actions: [],
  still_applied_reroute_ids: [],
  verification_mode: "configuration_only",
} as RerouteBundle;

describe("presentMitigationRun", () => {
  it("keeps a newly accepted recovery child over stale parent linkage", () => {
    expect(chooseRecoveryChildId(99, 98)).toBe(99);
    expect(chooseRecoveryChildId(99, 100)).toBe(100);
  });

  it("labels failed and compensated recovery summaries as needing attention", () => {
    expect(recoveryProgressHeading("failed")).toBe("Needs attention");
    expect(recoveryProgressHeading("compensated")).toBe("Needs attention");
    expect(recoveryProgressHeading("running")).toBe("Reverting");
  });

  it("describes active, failed, completed, and absent recovery children truthfully", () => {
    expect(recoveryFieldLabel(liveFixture, { ...liveFixture, id: 2, parent_bundle_id: 1, state: "running" })).toBe("Revert in progress · recovery #2");
    expect(recoveryFieldLabel(liveFixture, { ...liveFixture, id: 2, parent_bundle_id: 1, state: "failed" })).toBe("Needs attention · recovery #2");
    expect(recoveryFieldLabel(liveFixture, { ...liveFixture, id: 2, parent_bundle_id: 1, state: "succeeded", finished_at: null })).toBe("Completed · recovery #2");
    expect(recoveryFieldLabel({ ...liveFixture, latest_recovery_bundle_id: null, latest_recovery: null })).toBe("Until manually reverted");
    const stale: RerouteBundle = { ...liveFixture, latest_recovery_bundle_id: 98, latest_recovery: { id: 98, parent_bundle_id: 1, state: "succeeded", total_actions: 8, completed_actions: 8, started_at: null, finished_at: null, failure_reason: null } };
    expect(recoveryFieldLabel(stale, null, 99)).toBe("Revert accepted · recovery #99");
    const current: RerouteBundle = { ...liveFixture, latest_recovery_bundle_id: 99, latest_recovery: { id: 99, parent_bundle_id: 1, state: "succeeded", total_actions: 8, completed_actions: 8, started_at: null, finished_at: "2026-09-19T11:00:00Z", failure_reason: null } };
    const staleChild: RerouteBundle = { ...liveFixture, id: 98, parent_bundle_id: 1, state: "succeeded", finished_at: "2026-09-18T09:00:00Z" };
    const label = recoveryFieldLabel(current, staleChild, 99);
    expect(label).toContain(new Date("2026-09-19T11:00:00Z").toLocaleString());
    expect(label).not.toContain(new Date("2026-09-18T09:00:00Z").toLocaleString());
  });
  it("describes the live eight-step manual LAB run without claiming routing verification", () => {
    const state = presentMitigationRun(liveFixture);
    expect(state.label).toBe("Applied manually");
    expect(state.remaining).toBe(8);
    expect(state.detail).toContain("8 router changes remain");
    expect(state.detail).toContain("BGP advertisements were not verified");
  });

  it("keeps unknown effects separate from known remaining changes", () => {
    const state = presentMitigationRun({ ...liveFixture, remaining_changes: 1, remaining_mutations: 2, unknown_effects: 1, lifecycle_state: "recovery_blocked" });
    expect(state.label).toBe("Needs attention");
    expect(state.known).toBe(1);
    expect(state.unknown).toBe(1);
    expect(state.detail).toContain("1 known change remains; 1 outcome is unknown");
  });

  it("keeps scheduled recovery in the applied state until recovery actually starts", () => {
    expect(presentMitigationRun({ ...liveFixture, lifecycle_state: "recovery_scheduled" }).label).toBe("Applied manually");
  });

  it("labels a running recovery child as reverting", () => {
    const state = presentMitigationRun({ ...liveFixture, id: 2, parent_bundle_id: 1, state: "running", execution_state: "running", completed_actions: 3 });
    expect(state.label).toBe("Reverting");
    expect(state.detail).toContain("3/8 restore steps completed");
  });

  it("never infers source ownership from a failed recovery child", () => {
    const failed = presentMitigationRun({ ...liveFixture, id: 2, parent_bundle_id: 1, state: "failed", execution_state: "failed", remaining_changes: 0, remaining_mutations: 0 });
    expect(failed.label).toBe("Revert failed"); expect(failed.tone).toBe("bad"); expect(failed.detail).toContain("Inspect the source mitigation");
    const compensated = presentMitigationRun({ ...liveFixture, id: 2, parent_bundle_id: 1, state: "compensated", execution_state: "compensated", remaining_changes: 0, remaining_mutations: 0 });
    expect(compensated.label).toBe("Revert failed—restoration undone"); expect(compensated.tone).toBe("bad");
  });
});
