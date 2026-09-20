// @vitest-environment jsdom
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { api, type MitigationPreset, type Template } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import ManualReroute from "@/pages/ManualReroute";

const saved: MitigationPreset = { id: 4, name: "Edge diversion", description: "Reviewed set", revision: 2, archived_at: null, actions: [], definition_status: "draft", validation_error: null, created_at: "2026-09-19T08:00:00Z", updated_at: "2026-09-19T08:00:00Z", recent_runs: [] };
const editableTemplate: Template = { id: 5, name: "null_route_prefix", display_name: "Null route", description: null, provider_type: "device_cli", mode: "config", automatic_allowed: false, parameter_schema: { prefix: { type: "cidr", label: "Prefix" } }, plan: null, verification: null, rollback_template_id: null, enabled: true };
const alternateTemplate: Template = { ...editableTemplate, id: 6, name: "alternate_route", display_name: "Alternate route" };
const legacyPeerTemplate: Template = { ...editableTemplate, id: 7, name: "legacy_peer", display_name: "Legacy peer", parameter_schema: { neighbor: { type: "ip", source: "bgp_peer" }, prefix_list: { type: "string", source: "peer_out_prefix_list" } } };
const longSaved: MitigationPreset = {
  ...saved,
  definition_status: "needs_setup",
  validation_error: "Action 16 needs setup",
  actions: Array.from({ length: 16 }, (_, index) => ({ id: 100 + index, reroute_template_id: 5, template_name: editableTemplate.name, device_id: 10, device_name: "Router A", params: { prefix: `192.0.2.${index}/32` }, enabled: true, auto_target: null, validation_status: index === 15 ? "invalid" : "valid" })),
};

function mockEditorDependencies(preset: MitigationPreset) {
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "edit_rules", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([preset]);
  vi.spyOn(api.templates, "list").mockResolvedValue([editableTemplate, alternateTemplate]);
  vi.spyOn(api.devices, "list").mockResolvedValue([
    { id: 10, name: "Router A" }, { id: 11, name: "Router B" },
  ] as never);
  vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [], page: 1, per_page: 200, total: 0 });
  vi.spyOn(api.rtbh, "list").mockResolvedValue([]);
  vi.spyOn(api.devices, "bgpPeers").mockResolvedValue([]);
  vi.spyOn(api.devices, "bgpNetworks").mockResolvedValue([]);
  vi.spyOn(api.devices, "interfaces").mockResolvedValue([]);
  vi.spyOn(api.devices, "routeMaps").mockResolvedValue([]);
}

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("renders every active run for a saved mitigation with an exact selection link", async () => {
  const activePreset: MitigationPreset = { ...saved, definition_status: "ready", active_runs: [1, 2].map((id) => ({ bundle_id: id, id, state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", active: true, created_at: `2026-09-19T08:0${id}:00Z`, remaining_changes: id, unknown_effects: 0, trigger_type: "manual", total_actions: 8, completed_actions: 8, revert: { available: true, block_reasons: [] } })) };
  mockEditorDependencies(activePreset);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(activePreset);
  const router = createMemoryRouter([{ path: "/manual-mitigations/:id", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4"] });
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  expect(await screen.findByRole("heading", { name: "Current state" })).toBeTruthy();
  const links = await screen.findAllByRole("link", { name: "Review & revert" });
  expect(links.map((link) => link.getAttribute("href"))).toEqual(["/mitigations?tab=active&run=1", "/mitigations?tab=active&run=2"]);
  expect((screen.getByRole("button", { name: "Edit mitigation" }) as HTMLButtonElement).disabled).toBe(true);
  expect(screen.queryByRole("link", { name: "Run mitigation" })).toBeNull();
});

it("locks a saved mitigation after navigation while its run remains active", async () => {
  const labTemplate = { ...editableTemplate, id: 20, name: "iface_tcp_adjust_mss", display_name: "Set MSS", parameter_schema: { interface: { type: "string", label: "Interface" }, mss: { type: "integer", label: "MSS" } } };
  const activeRun = { bundle_id: 33, id: 33, state: "running", execution_state: "running", lifecycle_state: "active", active: true, created_at: "2026-09-20T08:00:00Z", remaining_changes: 0, unknown_effects: 0, trigger_type: "manual", total_actions: 1, completed_actions: 0, revert: { available: false, block_reasons: ["run is still applying"] } };
  const preset: MitigationPreset = { ...saved, definition_status: "ready", validation_status: "valid", actions: [{ reroute_template_id: 20, template_name: labTemplate.name, device_id: 3, device_name: "Router A", params: { interface: "Po1", mss: "1436" }, enabled: true }], active_runs: [activeRun as never] };
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "edit_rules", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([preset]);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(preset);
  vi.spyOn(api.templates, "list").mockResolvedValue([labTemplate]);
  vi.spyOn(api.devices, "list").mockResolvedValue([{ id: 3, name: "Router A" }] as never);
  vi.spyOn(api.manualMitigations, "capabilities").mockResolvedValue({ configuration_test_device_ids: [3], configuration_test_templates: [labTemplate.name] });
  const preview = vi.spyOn(api.manualMitigations, "preview");
  const router = createMemoryRouter([{ path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4/run"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  expect(await screen.findByText(/already has an active run/i)).toBeTruthy();
  expect(screen.getByRole("link", { name: "Review run #33" }).getAttribute("href")).toBe("/mitigations?tab=active&run=33");
  expect((screen.getByRole("button", { name: "Preview changes" }) as HTMLButtonElement).disabled).toBe(true);
  await user.click(screen.getByRole("tab", { name: "Configuration" }));
  expect((screen.getByRole("button", { name: "Override action 1" }) as HTMLButtonElement).disabled).toBe(true);
  expect(preview).not.toHaveBeenCalled();
});

it("returns from a direct run link to its saved mitigation details", async () => {
  const preset = { ...saved, definition_status: "ready", active_runs: [{ bundle_id: 1, id: 1, state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", active: true, created_at: "2026-09-19T08:01:00Z", remaining_changes: 1, trigger_type: "manual", total_actions: 1, completed_actions: 1 }] } as MitigationPreset;
  mockEditorDependencies(preset);
  const getPreset = vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(preset);
  vi.spyOn(api.bundles, "get").mockResolvedValue({ id: 1, rule_id: null, trigger_type: "manual", state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", active: true, remaining_changes: 1, failure_policy: "abort_and_compensate", total_actions: 1, completed_actions: 1, failure_reason: null, started_at: null, finished_at: null, actions: [], still_applied_reroute_ids: [], source: { kind: "preset", preset_id: 4, preset_name: "Edge diversion" } } as never);
  const router = createMemoryRouter([{ path: "/manual-mitigations", element: <ManualReroute /> }, { path: "/manual-mitigations/:id", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations?bundle=1"] });
  const user = userEvent.setup(); render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Return to mitigation details" }));
  await waitFor(() => expect(router.state.location.pathname).toBe("/manual-mitigations/4"));
  expect(getPreset).toHaveBeenCalledWith(4);
  expect(await screen.findByRole("heading", { name: "Current state" })).toBeTruthy();
  expect((await screen.findAllByText("Edge diversion")).length).toBeGreaterThan(0);
});

it("defaults a run to Overview and preserves path and query while tabs update the hash", async () => {
  const preset: MitigationPreset = { ...saved, definition_status: "ready", validation_status: "valid", actions: [{ reroute_template_id: 5, template_name: editableTemplate.name, device_id: 10, device_name: "Router A", params: { prefix: "192.0.2.1/32" }, enabled: true }] };
  mockEditorDependencies(preset);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(preset);
  const router = createMemoryRouter([{ path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4/run?keep=1"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  const overview = await screen.findByRole("tab", { name: "Overview & run" });
  expect(overview.getAttribute("aria-selected")).toBe("true");
  expect(router.state.location.hash).toBe("");
  await user.click(screen.getByRole("tab", { name: "Configuration" }));
  expect(router.state.location.pathname).toBe("/manual-mitigations/4/run");
  expect(router.state.location.search).toBe("?keep=1");
  expect(router.state.location.hash).toBe("#configuration");
  expect(await screen.findByRole("button", { name: "Override action 1" })).toBeTruthy();
  await user.click(screen.getByRole("tab", { name: "Overview & run" }));
  expect(router.state.location.hash).toBe("#overview");
});

it("navigates list to URL-owned detail/edit and saves one deliberate draft", async () => {
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "edit_rules", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([saved]);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(saved);
  const update = vi.spyOn(api.mitigationPresets, "update").mockImplementation(async (_id, body) => ({ ...saved, ...body, revision: 3 }));
  vi.spyOn(api.templates, "list").mockResolvedValue([]); vi.spyOn(api.devices, "list").mockResolvedValue([]);
  vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [], page: 1, per_page: 200, total: 0 });
  vi.spyOn(window, "confirm").mockReturnValue(true);
  const router = createMemoryRouter([{ path: "/manual-mitigations", element: <ManualReroute /> }, { path: "/manual-mitigations/:id", element: <ManualReroute /> }, { path: "/manual-mitigations/:id/edit", element: <ManualReroute /> }, { path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  await user.click(await screen.findByRole("link", { name: "Details" }));
  await waitFor(() => expect(router.state.location.pathname).toBe("/manual-mitigations/4"));
  expect((await screen.findAllByText("Edge diversion")).length).toBeGreaterThan(0);
  await user.click(screen.getByRole("link", { name: "Edit mitigation" }));
  const name = await screen.findByLabelText("Name");
  await user.clear(name); await user.type(name, "Edge diversion revised");
  await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(update).toHaveBeenCalledWith(4, expect.objectContaining({ name: "Edge diversion revised", actions: [], revision: 2 })));
  await waitFor(() => expect(router.state.location.pathname).toBe("/manual-mitigations/4"));
});

it("never lets a late detail response overwrite new or run-once routes", async () => {
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "edit_rules", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([saved]);
  let resolveOld!: (value: MitigationPreset) => void;
  vi.spyOn(api.mitigationPresets, "get").mockImplementation(() => new Promise((resolve) => { resolveOld = resolve; }));
  const create = vi.spyOn(api.mitigationPresets, "create").mockImplementation(async (body) => ({ ...saved, ...body, id: 8, revision: 1 }));
  const update = vi.spyOn(api.mitigationPresets, "update");
  vi.spyOn(api.templates, "list").mockResolvedValue([]); vi.spyOn(api.devices, "list").mockResolvedValue([]); vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [], page: 1, per_page: 200, total: 0 });
  const router = createMemoryRouter([{ path: "/manual-mitigations", element: <ManualReroute /> }, { path: "/manual-mitigations/new", element: <ManualReroute /> }, { path: "/manual-mitigations/:id", element: <ManualReroute /> }, { path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4"] });
  const user = userEvent.setup(); render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  await waitFor(() => expect(resolveOld).toBeTypeOf("function"));
  await router.navigate("/manual-mitigations/new");
  resolveOld(saved); await new Promise((resolve) => setTimeout(resolve, 0));
  const name = await screen.findByLabelText("Name"); expect((name as HTMLInputElement).value).toBe("");
  await user.type(name, "Fresh draft"); await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(create).toHaveBeenCalled()); expect(update).not.toHaveBeenCalled();
  await router.navigate("/manual-mitigations/new?run=once");
  expect(await screen.findByText("Run once")).toBeTruthy();
  expect(screen.queryByDisplayValue("Edge diversion")).toBeNull();
});

it("edits the last action of a saved needs-setup set inline and persists the same preset", async () => {
  mockEditorDependencies(longSaved);
  let persisted = longSaved;
  vi.spyOn(api.mitigationPresets, "get").mockImplementation(async () => persisted);
  const update = vi.spyOn(api.mitigationPresets, "update").mockImplementation(async (id, body) => {
    persisted = { ...longSaved, ...body, id, revision: 3 };
    return persisted;
  });
  const preview = vi.spyOn(api.manualMitigations, "preview");
  const apply = vi.spyOn(api.manualMitigations, "apply");
  const remove = vi.spyOn(api.mitigationPresets, "remove");
  const confirm = vi.spyOn(window, "confirm");
  const router = createMemoryRouter([
    { path: "/manual-mitigations/:id", element: <ManualReroute /> },
    { path: "/manual-mitigations/:id/edit", element: <ManualReroute /> },
  ], { initialEntries: ["/manual-mitigations/4"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);

  await user.click(await screen.findByRole("link", { name: "Edit mitigation" }));
  const editLast = await screen.findByRole("button", { name: "Edit action 16" });
  await user.click(editLast);
  const editorHeading = screen.getByRole("heading", { name: "Edit action 16" });
  const row = editorHeading.closest("li");
  expect(row).not.toBeNull();
  expect(within(row!).getByText("Changes remain in this draft until you save the mitigation.")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Add actions" }).compareDocumentPosition(editorHeading) & Node.DOCUMENT_POSITION_PRECEDING).toBeTruthy();

  const editor = within(row!);
  await user.selectOptions(editor.getByLabelText("Action template"), "6");
  await user.selectOptions(editor.getByLabelText("Target router"), "11");
  await user.type(editor.getByLabelText("Prefix (cidr)"), "203.0.113.16/32");
  await user.click(editor.getByLabelText("Enabled"));
  await user.click(screen.getByRole("button", { name: "Save" }));

  await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
  const [id, body] = update.mock.calls[0];
  expect(id).toBe(4);
  expect(body.revision).toBe(2);
  expect(body.actions).toHaveLength(16);
  expect(body.actions[15]).toMatchObject({ id: 115, reroute_template_id: 6, device_id: 11, params: { prefix: "203.0.113.16/32" }, enabled: false });
  expect(preview).not.toHaveBeenCalled();
  expect(apply).not.toHaveBeenCalled();
  expect(remove).not.toHaveBeenCalled();
  expect(confirm).not.toHaveBeenCalled();
  await waitFor(() => expect(router.state.location.pathname).toBe("/manual-mitigations/4"));

  await router.navigate("/manual-mitigations/4/edit");
  await user.click(await screen.findByRole("button", { name: "Edit action 16" }));
  expect((within(screen.getByRole("heading", { name: "Edit action 16" }).closest("li")!).getByLabelText("Target router") as HTMLSelectElement).value).toBe("11");
});

it("keeps a dirty action draft when cancel navigation is declined", async () => {
  mockEditorDependencies(longSaved);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(longSaved);
  const confirm = vi.spyOn(window, "confirm").mockReturnValue(false);
  const router = createMemoryRouter([
    { path: "/manual-mitigations/:id", element: <ManualReroute /> },
    { path: "/manual-mitigations/:id/edit", element: <ManualReroute /> },
  ], { initialEntries: ["/manual-mitigations/4/edit"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Edit action 1" }));
  await user.click(within(screen.getByRole("heading", { name: "Edit action 1" }).closest("li")!).getByLabelText("Enabled"));
  await user.click(screen.getByRole("tab", { name: "Overview & run" }));
  expect(confirm).not.toHaveBeenCalled();
  await user.click(screen.getByRole("tab", { name: "Configuration" }));
  expect((within(screen.getByRole("heading", { name: "Edit action 1" }).closest("li")!).getByLabelText("Enabled") as HTMLInputElement).checked).toBe(false);
  await user.click(screen.getByRole("button", { name: "Cancel" }));
  await waitFor(() => expect(confirm).toHaveBeenCalledTimes(1));
  expect(router.state.location.pathname).toBe("/manual-mitigations/4/edit");
  expect((within(screen.getByRole("heading", { name: "Edit action 1" }).closest("li")!).getByLabelText("Enabled") as HTMLInputElement).checked).toBe(false);
});

it("does not clear a saved derived peer value when inventory loading fails", async () => {
  const preset = { ...longSaved, actions: [{ ...longSaved.actions[0], reroute_template_id: 7, params: { neighbor: "198.51.100.1", prefix_list: "PL-LEGACY" } }] };
  mockEditorDependencies(preset);
  vi.mocked(api.templates.list).mockResolvedValue([legacyPeerTemplate]);
  vi.mocked(api.devices.bgpPeers).mockRejectedValue(new Error("inventory unavailable"));
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(preset);
  const update = vi.spyOn(api.mitigationPresets, "update").mockImplementation(async (_id, body) => ({ ...preset, ...body, revision: 3 }));
  const router = createMemoryRouter([
    { path: "/manual-mitigations/:id", element: <ManualReroute /> },
    { path: "/manual-mitigations/:id/edit", element: <ManualReroute /> },
  ], { initialEntries: ["/manual-mitigations/4/edit"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Edit action 1" }));
  await waitFor(() => expect(api.devices.bgpPeers).toHaveBeenCalledWith(10));
  await user.click(screen.getByRole("button", { name: "Save" }));
  await waitFor(() => expect(update).toHaveBeenCalled());
  expect(update.mock.calls[0][1].actions[0].params).toEqual({ neighbor: "198.51.100.1", prefix_list: "PL-LEGACY" });
});

it("sends an explicit configuration-only scope without a deadline and rejects a mismatched preview", async () => {
  const labTemplate = { ...editableTemplate, id: 20, name: "iface_tcp_adjust_mss", display_name: "Set MSS", parameter_schema: { interface: { type: "string", label: "Interface" }, mss: { type: "integer", label: "MSS" } } };
  const labPreset: MitigationPreset = { ...saved, definition_status: "ready", validation_status: "valid", actions: [{ reroute_template_id: 20, template_name: labTemplate.name, device_id: 3, device_name: "eMA3 lab", params: { interface: "Bundle-Ether3", mss: "1436" }, enabled: true }] };
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([labPreset]);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(labPreset);
  vi.spyOn(api.templates, "list").mockResolvedValue([labTemplate]);
  vi.spyOn(api.devices, "list").mockResolvedValue([{ id: 3, name: "eMA3 lab" }, { id: 4, name: "Production edge" }] as never);
  vi.spyOn(api.manualMitigations, "capabilities")
    .mockResolvedValueOnce({ configuration_test_device_ids: [3], configuration_test_templates: [labTemplate.name] })
    .mockRejectedValueOnce(new Error("identity inventory unavailable"))
    .mockResolvedValue({ configuration_test_device_ids: [3], configuration_test_templates: [labTemplate.name] });
  const preview = vi.spyOn(api.manualMitigations, "preview").mockResolvedValue({ plan_id: 8, preview_token: "token", results: [], operating_mode: "observe", verification_mode: "routing", routing_verified: false });
  const router = createMemoryRouter([{ path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4/run"] });
  const user = userEvent.setup(); render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  const configurationOnly = await screen.findByRole("radio", { name: /^configuration only/i }) as HTMLInputElement;
  await waitFor(() => expect(configurationOnly.checked).toBe(true));
  expect(screen.getAllByRole("radio")[0]).toBe(configurationOnly);
  expect(screen.getByText("BGP advertisements are not verified.")).toBeTruthy();
  expect((screen.getByRole("radio", { name: /^additional checks/i }) as HTMLInputElement).disabled).toBe(true);
  expect(screen.getByText(/available in a future version/i)).toBeTruthy();
  const schedule = screen.getByRole("combobox", { name: /revert schedule/i }) as HTMLSelectElement;
  expect(schedule.disabled).toBe(true);
  expect(schedule.className).toContain("disabled:bg-muted");
  await user.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByText(/configuration-only eligibility is unavailable/i)).toBeTruthy();
  expect((screen.getByRole("radio", { name: /^configuration only/i }) as HTMLInputElement).checked).toBe(true);
  expect((screen.getByRole("button", { name: "Preview changes" }) as HTMLButtonElement).disabled).toBe(true);
  expect(preview).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: "Retry eligibility" }));
  await waitFor(() => expect(screen.queryByText(/configuration-only eligibility is unavailable/i)).toBeNull());
  await user.click(screen.getByRole("button", { name: "Preview changes" }));
  await waitFor(() => expect(preview).toHaveBeenCalledWith(expect.objectContaining({ verification_mode: "configuration_only", revert_after_seconds: undefined })));
  expect(screen.queryByRole("button", { name: "Apply reviewed changes" })).toBeNull();
  await user.click(screen.getByRole("tab", { name: "Configuration" }));
  await user.click(screen.getByRole("button", { name: "Override action 1" }));
  await user.selectOptions(screen.getByLabelText("Target router"), "4");
  await user.click(screen.getByRole("tab", { name: "Overview & run" }));
  expect((screen.getByRole("radio", { name: /^configuration only/i }) as HTMLInputElement).checked).toBe(true);
  expect(await screen.findByText(/supported actions on one enabled router/i)).toBeTruthy();
  expect((screen.getByRole("button", { name: "Preview changes" }) as HTMLButtonElement).disabled).toBe(true);
});

it("locks every run control while an exact preview is pending and keeps the action in one layout slot", async () => {
  const labTemplate = { ...editableTemplate, id: 20, name: "iface_tcp_adjust_mss", display_name: "Set MSS", parameter_schema: { interface: { type: "string", label: "Interface" }, mss: { type: "integer", label: "MSS" } } };
  const labPreset: MitigationPreset = { ...saved, definition_status: "ready", validation_status: "valid", actions: [{ reroute_template_id: 20, template_name: labTemplate.name, device_id: 3, device_name: "Lab router", params: { interface: "Bundle-Ether3", mss: "1436" }, enabled: true }] };
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "trigger_manual_reroute"] });
  vi.spyOn(api.mitigationPresets, "list").mockResolvedValue([labPreset]);
  vi.spyOn(api.mitigationPresets, "get").mockResolvedValue(labPreset);
  vi.spyOn(api.templates, "list").mockResolvedValue([labTemplate]);
  vi.spyOn(api.devices, "list").mockResolvedValue([{ id: 3, name: "Lab router" }] as never);
  vi.spyOn(api.manualMitigations, "capabilities").mockResolvedValue({ configuration_test_device_ids: [3], configuration_test_templates: [labTemplate.name] });
  const inspect = vi.spyOn(api.actionSets, "inspect");
  let resolvePreview!: (value: Awaited<ReturnType<typeof api.manualMitigations.preview>>) => void;
  const preview = vi.spyOn(api.manualMitigations, "preview").mockImplementation(() => new Promise((resolve) => { resolvePreview = resolve; }));
  const router = createMemoryRouter([{ path: "/manual-mitigations/:id/run", element: <ManualReroute /> }], { initialEntries: ["/manual-mitigations/4/run"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);

  const configurationOnly = await screen.findByRole("radio", { name: /^configuration only/i }) as HTMLInputElement;
  await waitFor(() => expect(configurationOnly.checked).toBe(true));
  const additionalChecks = screen.getByRole("radio", { name: /^additional checks/i }) as HTMLInputElement;
  const previewButton = screen.getByRole("button", { name: "Preview changes" }) as HTMLButtonElement;
  expect(previewButton.className).toContain("sm:w-[22rem]");
  await user.click(previewButton);

  const preparing = await screen.findByRole("button", { name: "Preparing exact preview…" }) as HTMLButtonElement;
  expect(preparing).toBe(previewButton);
  expect(preparing.className).toContain("sm:w-[22rem]");
  for (const button of screen.getAllByRole("button")) expect((button as HTMLButtonElement).disabled).toBe(true);
  expect(configurationOnly.matches(":disabled")).toBe(true);
  expect(additionalChecks.matches(":disabled")).toBe(true);
  expect((screen.getByRole("combobox", { name: /revert schedule/i }) as HTMLSelectElement).matches(":disabled")).toBe(true);
  await user.click(additionalChecks);
  await user.click(screen.getByRole("button", { name: "Inspect" }));
  expect(configurationOnly.checked).toBe(true);
  expect(inspect).not.toHaveBeenCalled();
  expect(preview).toHaveBeenCalledTimes(1);

  resolvePreview({ plan_id: 8, preview_token: "token", results: [], operating_mode: "observe", verification_mode: "configuration_only", routing_verified: false });
  expect(await screen.findByRole("button", { name: "Apply reviewed changes" })).toBeTruthy();
});
