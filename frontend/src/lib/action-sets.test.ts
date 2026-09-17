import { describe, expect, it } from "vitest";
import type { ActionDraft } from "@/lib/api";
import {
  actionIdentity,
  applyActionOverrides,
  importActionCopies,
  isCurrentPreview,
  moveOrderedAction,
  expandBulkActions,
} from "@/lib/action-sets";

const actions: ActionDraft[] = [
  { id: 11, reroute_template_id: 1, device_id: 10, params: { prefix: "192.0.2.0/24" }, enabled: true },
  { id: 12, reroute_template_id: 2, device_id: 20, params: { neighbor: "198.51.100.1" }, enabled: true },
];

describe("ordered action sets", () => {
  it("reorders without mutating the saved array", () => {
    const moved = moveOrderedAction(actions, 1, -1);
    expect(moved.map((action) => action.id)).toEqual([12, 11]);
    expect(actions.map((action) => action.id)).toEqual([11, 12]);
  });

  it("imports independent copies and discards preset row ownership", () => {
    const imported = importActionCopies([], actions, "append");
    expect(imported.map((action) => action.id)).toEqual([undefined, undefined]);
    imported[0].params.prefix = "203.0.113.0/24";
    expect(actions[0].params.prefix).toBe("192.0.2.0/24");
  });

  it("applies run-once overrides without changing saved targets or params", () => {
    const key = actionIdentity(actions[0], 0);
    const effective = applyActionOverrides(actions, {
      [key]: { device_id: 99, params: { prefix: "203.0.113.0/24" } },
    });
    expect(effective[0].device_id).toBe(99);
    expect(effective[0].params.prefix).toBe("203.0.113.0/24");
    expect(actions[0].device_id).toBe(10);
    expect(actions[0].params.prefix).toBe("192.0.2.0/24");
  });

  it("rejects a response from a superseded preview generation", () => {
    expect(isCurrentPreview(4, 5)).toBe(false);
    expect(isCurrentPreview(5, 5)).toBe(true);
  });

  it("expands routers × prefixes and appends one MSS helper per router", () => {
    const expanded = expandBulkActions({
      templateId: 3,
      deviceIds: [10, 20],
      paramsByDevice: { 10: { neighbor: "a" }, 20: { neighbor: "b" } },
      prefixParam: "prefix",
      prefixes: ["192.0.2.0/24", "198.51.100.0/24"],
      mss: { templateId: 4, paramsByDevice: { 10: { interface: "Gi0/0" }, 20: { interface: "Gi0/1" } }, placement: "before" },
    });
    expect(expanded).toHaveLength(6);
    expect(expanded.map((action) => action.reroute_template_id)).toEqual([4, 4, 3, 3, 3, 3]);
    expect(expanded.filter((action) => action.reroute_template_id === 4)).toHaveLength(2);
  });

  it("places every MSS removal after every BGP withdrawal across routers", () => {
    const expanded = expandBulkActions({
      templateId: 30,
      deviceIds: [10, 20],
      paramsByDevice: { 10: {}, 20: {} },
      mss: { templateId: 40, paramsByDevice: { 10: {}, 20: {} }, placement: "after" },
    });
    expect(expanded.map((action) => action.reroute_template_id)).toEqual([30, 30, 40, 40]);
  });
});
