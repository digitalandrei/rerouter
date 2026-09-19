// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BrowserRouter } from "react-router-dom";
import { api, type Rule, type RerouteBundle } from "@/lib/api";
import { ActionsAndRevert } from "@/components/actions-and-revert";
import { ApplyMitigationDialog, BundleProgressView } from "@/components/apply-mitigation-dialog";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("manual mitigation workflow", () => {
  it("labels compensated and blocked configuration-only outcomes without claiming routing verification", () => {
    const base: Omit<RerouteBundle, "state"> = { id: 9, rule_id: null, trigger_type: "manual", failure_policy: "abort_and_compensate", total_actions: 1, completed_actions: 1, failure_reason: null, started_at: null, finished_at: null, actions: [], still_applied_reroute_ids: [], source: { kind: "manual", verification_mode: "configuration_only" } };
    const view = render(<BundleProgressView bundle={{ ...base, state: "compensated" }} bundleId={9} totalHint={1} pollError={null} />);
    expect(screen.getByText(/changes were reverted; routing not verified/i)).toBeTruthy();
    view.rerender(<BundleProgressView bundle={{ ...base, state: "compensation_blocked" }} bundleId={9} totalHint={1} pollError={null} />);
    expect(screen.getByText(/recovery is blocked and needs review; routing not verified/i)).toBeTruthy();
  });
  it("shows the applied-changes alarm only for unhealthy partial outcomes", () => {
    const healthy = { id: 1, rule_id: null, trigger_type: "manual", state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", failure_policy: "abort_and_compensate", total_actions: 8, completed_actions: 8, remaining_mutations: 8, failure_reason: null, started_at: null, finished_at: null, actions: [], still_applied_reroute_ids: [1,2,3,4,5,6,7,8] } as RerouteBundle;
    const view = render(<BrowserRouter><BundleProgressView bundle={healthy} bundleId={1} totalHint={8} pollError={null} /></BrowserRouter>);
    expect(screen.queryByText(/changes? (?:is|are) still applied/i)).toBeNull();
    view.rerender(<BrowserRouter><BundleProgressView bundle={{ ...healthy, state: "compensation_blocked", execution_state: "compensation_blocked", lifecycle_state: "recovery_blocked" }} bundleId={1} totalHint={8} pollError={null} /></BrowserRouter>);
    expect(screen.getByText(/known changes remain/i)).toBeTruthy();
  });
  it("only inspects after an explicit click and invalidates evidence after edits", async () => {
    const user = userEvent.setup();
    const inspect = vi.spyOn(api.actionSets, "inspect").mockResolvedValue({
      blockers: [], prepared_actions: [], devices: [{ device_id: 1, before_config: {}, after_config: { changed: true }, revert_config: {}, changes: [{ action_index: 0, template_name: "test", effect: "change" }], completeness: "complete", blockers: [], read_at: "2026-09-19T08:00:00Z" }],
    });
    const first = [{ reroute_template_id: 1, device_id: 1, params: {}, enabled: true }];
    const view = render(<ActionsAndRevert actions={first} />);
    expect(inspect).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Inspect" }));
    expect(await screen.findByText("After all actions")).toBeTruthy();
    view.rerender(<ActionsAndRevert actions={[{ ...first[0], params: { prefix: "192.0.2.0/24" } }]} />);
    await waitFor(() => expect(screen.queryByText("After all actions")).toBeNull());
    expect(inspect).toHaveBeenCalledTimes(1);
  });

  it("renders multiline configuration and ignores a late inspection for an edited set", async () => {
    const user = userEvent.setup();
    let resolveOld!: (value: Awaited<ReturnType<typeof api.actionSets.inspect>>) => void;
    vi.spyOn(api.actionSets, "inspect").mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve; }));
    const first = [{ reroute_template_id: 1, device_id: 1, params: {}, enabled: true }];
    const view = render(<ActionsAndRevert actions={first} />);
    await user.click(screen.getByRole("button", { name: "Inspect" }));
    view.rerender(<ActionsAndRevert actions={[{ ...first[0], params: { changed: true } }]} />);
    resolveOld({ blockers: [], prepared_actions: [], devices: [{ device_id: 1, before_config: "line one\nline two", after_config: "line one\nline three", revert_config: "line one\nline two", changes: [{ action_index: 0, template_name: "bgp_export_policy_set", effect: "change" }], completeness: "complete", blockers: [], read_at: "2026-09-19T08:00:00Z" }] });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(screen.queryByText(/line one\nline two/)).toBeNull();

    vi.spyOn(api.actionSets, "inspect").mockResolvedValueOnce({ blockers: [], prepared_actions: [], devices: [{ device_id: 1, before_config: "line one\nline two", after_config: "line one\nline three", revert_config: "line one\nline two", changes: [{ action_index: 0, template_name: "bgp_export_policy_set", effect: "change" }], completeness: "complete", blockers: [], read_at: "2026-09-19T08:00:00Z" }] });
    await user.click(screen.getByRole("button", { name: "Inspect" }));
    await waitFor(() => expect(Array.from(document.querySelectorAll("pre")).some((node) => node.textContent?.includes("line one\nline two"))).toBe(true));
    expect(Array.from(document.querySelectorAll("pre")).some((node) => node.textContent?.includes("- line two"))).toBe(true);
    expect(Array.from(document.querySelectorAll("pre")).some((node) => node.textContent?.includes("+ line three"))).toBe(true);
    expect(screen.getByText(/Bgp Export Policy Set/)).toBeTruthy();
  });

  it("allows an explicit token-bound confirmation in Observe", async () => {
    const user = userEvent.setup();
    const apply = vi.spyOn(api.rules, "apply")
      .mockResolvedValueOnce({ results: [{ executed: false, message: "prepared", device_id: 1, would_run: { template_id: 1, template_name: "test", config_mode: true, commands: ["router bgp 64500"], verify: null } }], preview_token: "one-use" })
      .mockResolvedValueOnce({ bundle_id: 42, async: true, state: "planned", total_actions: 1, failure_policy: "abort_and_compensate", results: [] });
    const rule = { id: 7, name: "Flood response" } as Rule;
    render(<BrowserRouter><ApplyMitigationDialog rule={rule} operatingMode="observe" onClose={() => undefined} /></BrowserRouter>);
    expect(screen.getByText(/automatic response is disabled/i)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Preview exact commands" }));
    await user.click(await screen.findByRole("button", { name: "Execute reviewed actions" }));
    expect(apply).toHaveBeenNthCalledWith(2, 7, expect.objectContaining({ dry_run: false, preview_token: "one-use" }));
  });

  it("reports reordered configuration values as changes", async () => {
    const user = userEvent.setup();
    vi.spyOn(api.actionSets, "inspect").mockResolvedValue({ blockers: [], prepared_actions: [], devices: [{ device_id: 1, before_config: "interface A\n ip tcp adjust-mss 1400\ninterface B\n ip tcp adjust-mss 1436", after_config: "interface A\n ip tcp adjust-mss 1436\ninterface B\n ip tcp adjust-mss 1400", revert_config: "interface A\n ip tcp adjust-mss 1400\ninterface B\n ip tcp adjust-mss 1436", changes: [{ action_index: 0, template_name: "iface_tcp_adjust_mss", effect: "change" }], completeness: "complete", blockers: [], read_at: "2026-09-19T08:00:00Z" }] });
    render(<ActionsAndRevert actions={[{ reroute_template_id: 1, device_id: 1, params: {} }]} />);
    await user.click(screen.getByRole("button", { name: "Inspect" }));
    await screen.findByText("Before → after all actions");
    const diffs = Array.from(document.querySelectorAll("pre")).map((node) => node.textContent ?? "");
    expect(diffs.some((value) => value.split("\n").some((line) => line.startsWith("- ")) && value.split("\n").some((line) => line.startsWith("+ ")) && value.includes("1400") && value.includes("1436"))).toBe(true);
    expect(diffs).not.toContain("  No configuration difference");
  });
});
