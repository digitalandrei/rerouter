import { describe, expect, it } from "vitest";
import { orderTemplatesForChoice, templateGuidance, templateLabel, templateLabelFrom } from "@/lib/labels";

describe("BGP action template presentation", () => {
  it("clearly labels legacy entry editing regardless of stored display name", () => {
    expect(templateLabel({ name: "bgp_advertise_add", display_name: "BGP Advertise to Upstream" })).toBe("Add prefix-list entry (legacy)");
    expect(templateLabelFrom("BGP Advertise Withdraw", "bgp_advertise_remove")).toBe("Remove prefix-list entry (legacy)");
    expect(templateGuidance("bgp_advertise_add")).toMatch(/edits entries/i);
    expect(templateGuidance("bgp_export_policy_set")).toMatch(/attached outbound/i);
  });
  it("places the unified attachment action before legacy entry editors", () => {
    expect(orderTemplatesForChoice([{ name: "bgp_advertise_add" }, { name: "other" }, { name: "bgp_export_policy_set" }]).map((item) => item.name)).toEqual(["bgp_export_policy_set", "other", "bgp_advertise_add"]);
  });
});
