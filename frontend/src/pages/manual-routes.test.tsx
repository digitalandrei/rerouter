// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { api, type MitigationPreset } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import ManualReroute from "@/pages/ManualReroute";

const saved: MitigationPreset = { id: 4, name: "Edge diversion", description: "Reviewed set", revision: 2, archived_at: null, actions: [], definition_status: "draft", validation_error: null, created_at: "2026-09-19T08:00:00Z", updated_at: "2026-09-19T08:00:00Z", recent_runs: [] };

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

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
  await user.click(screen.getByRole("link", { name: "Edit" }));
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
