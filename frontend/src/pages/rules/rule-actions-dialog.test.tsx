// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, type Rule } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import Rules, { RuleActionsDialog } from "@/pages/Rules";
import { createMemoryRouter, MemoryRouter, RouterProvider } from "react-router-dom";

const rule = { id: 9, name: "Edge flood", target_kind: "interface", interface_id: 3, device_id: 2, metric: "rx_bps", operator: ">", threshold_value: 1_000_000, duration_seconds: 0, consecutive_samples: 3, severity: "warning", enabled: true, actions_revision: 3, automatic_reroute_enabled: false, automatic_revert_enabled: false, manual_apply_enabled: true, actions: [{ id: 41, reroute_template_id: 5, template_name: "null_route_prefix", template_display_name: "Null route", device_id: 2, device_name: "edge-2", params: { prefix: "192.0.2.1/32" }, enabled: true, position: 0 }], action_count: 1 } as unknown as Rule;

function mocks(permissions: string[]) {
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "viewer@example.test", name: "Viewer", roles: ["viewer"], permissions });
  vi.spyOn(api.templates, "list").mockResolvedValue([{ id: 5, name: "null_route_prefix", display_name: "Null route", description: null, provider_type: "device_cli", mode: "config", automatic_allowed: false, parameter_schema: { prefix: { type: "cidr", label: "Prefix" } }, plan: null, verification: null, rollback_template_id: null, enabled: true }]);
  vi.spyOn(api.devices, "list").mockResolvedValue([{ id: 2, name: "edge-2" } as never]);
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([]);
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

describe("RuleActionsDialog", () => {
  it("lets a read-only viewer inspect actions without editing controls", async () => {
    mocks(["view_asset"]);
    render(<AuthProvider><RuleActionsDialog rule={rule} onClose={() => undefined} onChanged={() => undefined} /></AuthProvider>);
    expect(await screen.findByRole("button", { name: "Inspect" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Save complete set" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit action 1" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove action 1" })).toBeNull();
  });

  it("keeps removals local until one atomic complete-set save", async () => {
    mocks(["view_asset", "edit_rules"]);
    const save = vi.spyOn(api.rules, "saveActions").mockResolvedValue({ ...rule, actions: [], action_count: 0, actions_revision: 4 });
    const user = userEvent.setup();
    render(<AuthProvider><RuleActionsDialog rule={rule} onClose={() => undefined} onChanged={() => undefined} /></AuthProvider>);
    await user.click(await screen.findByRole("button", { name: "Remove action 1" }));
    expect(save).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Save complete set" }));
    await waitFor(() => expect(save).toHaveBeenCalledWith(9, { revision: 3, actions: [] }));
  });

  it("labels only the complete-set save as pending and prevents a duplicate save", async () => {
    mocks(["view_asset", "edit_rules"]);
    let finish!: (value: Rule) => void;
    const save = vi.spyOn(api.rules, "saveActions").mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
    const user = userEvent.setup();
    render(<AuthProvider><RuleActionsDialog rule={rule} onClose={() => undefined} onChanged={() => undefined} /></AuthProvider>);
    await user.click(await screen.findByRole("button", { name: "Remove action 1" }));
    await user.click(screen.getByRole("button", { name: "Save complete set" }));
    const pending = await screen.findByRole("button", { name: "Saving…" });
    expect(pending.getAttribute("aria-busy")).toBe("true");
    expect(screen.getByRole("button", { name: "Add action" }).getAttribute("aria-busy")).toBeNull();
    await user.click(pending);
    expect(save).toHaveBeenCalledTimes(1);
    finish({ ...rule, actions: [], action_count: 0, actions_revision: 4 });
    await waitFor(() => expect(screen.getByRole("button", { name: "Save complete set" })).toBeTruthy());
  });

  it("shows recovered ownership and offers the original active run instead of another run", async () => {
    mocks(["view_asset", "trigger_manual_reroute"]);
    vi.spyOn(api.rules, "list").mockResolvedValue([{ ...rule, current_state: "recovered_awaiting_revert" }]);
    vi.spyOn(api.settings, "get").mockResolvedValue({ operating_mode: "observe", automatic_actions_enabled: false, global_lock: false });
    render(<AuthProvider><MemoryRouter initialEntries={["/rules"]}><Rules /></MemoryRouter></AuthProvider>);
    expect(await screen.findByText("recovered · awaiting revert")).toBeTruthy();
    expect(screen.getByRole("link", { name: "View Edge flood" }).getAttribute("href")).toBe("/rules/9#overview");
    expect(screen.queryByRole("button", { name: "Run manually" })).toBeNull();
  });

  it("opens a URL-owned rule overview, allows a defined manual run, and stores tab selection in the hash", async () => {
    mocks(["view_asset", "trigger_manual_reroute"]);
    vi.spyOn(api.rules, "list").mockResolvedValue([{ ...rule, current_state: "recovered_awaiting_revert" }]);
    vi.spyOn(api.settings, "get").mockResolvedValue({ operating_mode: "observe", automatic_actions_enabled: false, global_lock: false });
    const router = createMemoryRouter([
      { path: "/rules", element: <Rules /> },
      { path: "/rules/:id", element: <Rules /> },
      { path: "/rules/:id/edit", element: <Rules /> },
    ], { initialEntries: ["/rules/9"] });
    const user = userEvent.setup();
    render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
    expect(await screen.findByRole("heading", { name: "Edge flood" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Run manually" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Manage mitigation actions" })).toBeNull();
    expect(screen.getByRole("link", { name: "View active run / revert" }).getAttribute("href")).toBe("/mitigations?tab=active&rule_id=9");
    await user.click(screen.getByRole("tab", { name: "Configuration" }));
    expect(router.state.location.pathname).toBe("/rules/9");
    expect(router.state.location.hash).toBe("#configuration");
    expect(screen.getByText("Detection configuration")).toBeTruthy();
    expect(screen.getByText("Null route")).toBeTruthy();
    await user.click(screen.getByRole("tab", { name: "Overview & run" }));
    expect(router.state.location.hash).toBe("#overview");
  });

  it("reconstructs a rule's active run and blocks another manual start", async () => {
    mocks(["view_asset", "trigger_manual_reroute"]);
    vi.spyOn(api.rules, "list").mockResolvedValue([{ ...rule, current_state: "clear", active_run_id: 77, active_run_count: 1 }]);
    vi.spyOn(api.settings, "get").mockResolvedValue({ operating_mode: "observe", automatic_actions_enabled: false, global_lock: false });
    const router = createMemoryRouter([
      { path: "/rules", element: <Rules /> },
      { path: "/rules/:id", element: <Rules /> },
    ], { initialEntries: ["/rules/9"] });
    render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);

    const runButton = await screen.findByRole("button", { name: "Run manually" }) as HTMLButtonElement;
    expect(runButton.disabled).toBe(true);
    expect(screen.getByRole("link", { name: "View active run / revert" }).getAttribute("href")).toBe("/mitigations?tab=active&rule_id=9&run=77");
  });
});
