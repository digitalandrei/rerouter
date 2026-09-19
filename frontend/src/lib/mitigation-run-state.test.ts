import { describe, expect, it } from "vitest";
import type { RerouteBundle } from "@/lib/api";
import { presentMitigationRun } from "@/lib/mitigation-run-state";

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
  it("describes the live eight-step manual LAB run without claiming routing verification", () => {
    const state = presentMitigationRun(liveFixture);
    expect(state.label).toBe("Applied manually");
    expect(state.remaining).toBe(8);
    expect(state.detail).toContain("8 router changes remain");
    expect(state.detail).toContain("BGP advertisements were not verified");
  });

  it("keeps unknown effects separate from known remaining changes", () => {
    const state = presentMitigationRun({ ...liveFixture, remaining_mutations: 3, unknown_effects: 2, lifecycle_state: "recovery_blocked" });
    expect(state.label).toBe("Needs attention");
    expect(state.remaining).toBe(3);
    expect(state.unknown).toBe(2);
    expect(state.detail).toContain("2 effects are unknown");
  });
});
