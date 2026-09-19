// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import type { RoutingPolicyInventory } from "@/lib/api";
import { classifyCachedRouteMap, RoutingPolicyInventoryView } from "@/components/routing-policy-inventory";

afterEach(cleanup);

const inventory: RoutingPolicyInventory = {
  device_id: 3, read_at: "2026-09-19T08:00:00Z", completeness: "complete", blockers: [],
  prefix_lists: [{ name: "PL-NEW", entries: [{ sequence: 10, action: "permit", prefix: "203.0.113.0/24", ge: 25, le: 28 }], referenced_by: [] }],
  route_maps: [{ name: "RM-OUT", clauses: [{ sequence: 10, action: "permit", matches: [{ kind: "ip_address_prefix-list", value: "ip address prefix-list LIMITED" }], sets: [] }], references: [] }],
  peer_bindings: [
    { neighbor_ip: "192.0.2.1", local_asn: 64500, address_family: "ipv4", direction: "out", policy_kind: "prefix_list", policy_name: "PL-OLD", scope: "direct" },
    { neighbor_ip: "192.0.2.1", local_asn: 64500, address_family: "ipv4", direction: "out", policy_kind: "route_map", policy_name: "RM-OUT", scope: "direct" },
  ],
};

describe("routing policy preflight", () => {
  it("shows a prefix-list replacement while preserving the complementary route map", () => {
    render(<RoutingPolicyInventoryView inventory={inventory} selectedPeer="192.0.2.1" selectedKind="prefix_list" selectedName="PL-NEW" />);
    expect(screen.getByText(/outbound route map is preserved/i)).toBeTruthy();
    expect(screen.getAllByText(/may filter routes/i)).toHaveLength(2);
    expect(screen.getByText("203.0.113.0/24")).toBeTruthy();
    expect(screen.getAllByText("RM-OUT")).toHaveLength(3);
  });

  it("only calls no-match permit maps with bounded attribute sets straightforward", () => {
    expect(classifyCachedRouteMap({ name: "safe", references: [], clauses: [{ sequence: 10, action: "permit", matches: [], sets: [{ kind: "as-path_prepend", value: "as-path prepend 64500" }, { kind: "metric_80", value: "metric 80" }, { kind: "local-preference_150", value: "local-preference 150" }] }] })).toBe("straightforward");
    expect(classifyCachedRouteMap(inventory.route_maps[0])).toBe("may_filter");
    expect(classifyCachedRouteMap({ name: "community", references: [], clauses: [{ sequence: 10, action: "permit", matches: [], sets: [{ kind: "community", value: "community 64500:1" }] }] })).toBe("may_filter");
  });
});
