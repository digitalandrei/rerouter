// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { api, type ManualMitigationPreview, type RerouteBundle } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import { ActiveRunsTab, HistoryTab } from "@/pages/Mitigations";

const run = { id: 7, rule_id: null, trigger_type: "manual", state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", active: true, remaining_mutations: 1, failure_policy: "abort_and_compensate", total_actions: 1, completed_actions: 1, failure_reason: null, started_at: "2026-09-19T08:00:00Z", finished_at: "2026-09-19T08:01:00Z", actions: [], still_applied_reroute_ids: [71], revert: { available: true, block_reasons: [] }, source: { kind: "manual", name: "Run once" }, created_at: "2026-09-19T08:00:00Z" } as RerouteBundle;
const preview = { plan_id: 12, preview_token: "token-b", results: [], operating_mode: "observe" } as ManualMitigationPreview;

function auth() { vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "trigger_manual_reroute"] }); }
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

it("shows one honest pending state while preparing and confirming a whole-run revert", async () => {
  auth(); vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [run], page: 1, per_page: 200, total: 1 }); vi.spyOn(api.bundles, "get").mockResolvedValue(run);
  let resolveOld!: (value: ManualMitigationPreview) => void;
  const revert = vi.spyOn(api.bundles, "revert").mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve as (value: ManualMitigationPreview) => void; })).mockResolvedValueOnce({ bundle_id: 99, async: true });
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  const reason = await screen.findByLabelText("Audit reason"); await user.type(reason, "Reason A"); await user.click(screen.getByRole("button", { name: "Preview revert" }));
  const pending = screen.getByRole("button", { name: "Preparing revert preview…" });
  expect(pending.getAttribute("aria-busy")).toBe("true"); expect((pending as HTMLButtonElement).disabled).toBe(true); expect(pending.querySelector("svg.animate-spin")).not.toBeNull();
  await user.click(pending); expect(revert).toHaveBeenCalledTimes(1); expect((reason as HTMLInputElement).disabled).toBe(true);
  resolveOld(preview); await screen.findByRole("button", { name: "Apply reviewed revert" });
  await user.click(screen.getByRole("button", { name: "Apply reviewed revert" }));
  expect(revert).toHaveBeenLastCalledWith(7, { dry_run: false, reason: "Reason A", plan_id: 12, preview_token: "token-b" });
  expect((await screen.findAllByText(/recovery #99/i)).length).toBeGreaterThan(0);
});

it("pages through run history beyond the first fifty records", async () => {
  auth(); vi.spyOn(api.reroutes, "list").mockResolvedValue([]); vi.spyOn(api.locks, "list").mockResolvedValue([]);
  const list = vi.spyOn(api.bundles, "list").mockImplementation(async (options) => ({ items: [{ ...run, id: options?.page === 2 ? 51 : 1 }], page: options?.page ?? 1, per_page: 50, total: 51 }));
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter initialEntries={["/mitigations?tab=history"]}><HistoryTab /></MemoryRouter></AuthProvider>);
  await screen.findByText("#1"); await user.click(screen.getByRole("button", { name: "Next" }));
  expect(await screen.findByText("#51")).toBeTruthy(); expect(list).toHaveBeenCalledWith(expect.objectContaining({ page: 2, per_page: 50 }));
});

it("does not reopen a closed run when a polling response arrives late", async () => {
  auth(); const polls: Array<() => void> = [];
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback) => { polls.push(callback as () => void); return polls.length as unknown as ReturnType<typeof setInterval>; });
  vi.spyOn(globalThis, "clearInterval").mockImplementation(() => undefined);
  vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [run], page: 1, per_page: 200, total: 1 });
  let resolveSelected!: (value: RerouteBundle) => void;
  vi.spyOn(api.bundles, "get").mockResolvedValueOnce(run).mockResolvedValueOnce(run).mockImplementationOnce(() => new Promise((resolve) => { resolveSelected = resolve; })).mockResolvedValue(run);
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  polls.forEach((poll) => poll()); await vi.waitFor(() => expect(resolveSelected).toBeTypeOf("function"));
  const closeButtons = await screen.findAllByRole("button", { name: "Close" }); await user.click(closeButtons.find((button) => button.textContent === "Close")!);
  resolveSelected(run); await new Promise((resolve) => setTimeout(resolve, 0)); polls.forEach((poll) => poll()); await new Promise((resolve) => setTimeout(resolve, 0));
  await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});

it("refreshes an open run after it leaves the active list", async () => {
  auth(); const polls: Array<() => void> = [];
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback) => { polls.push(callback as () => void); return polls.length as unknown as ReturnType<typeof setInterval>; });
  vi.spyOn(globalThis, "clearInterval").mockImplementation(() => undefined);
  vi.spyOn(api.bundles, "list").mockResolvedValueOnce({ items: [run], page: 1, per_page: 200, total: 1 }).mockResolvedValue({ items: [], page: 1, per_page: 200, total: 0 });
  vi.spyOn(api.bundles, "get").mockResolvedValueOnce(run).mockResolvedValueOnce(run).mockResolvedValueOnce({ ...run, state: "succeeded", execution_state: "succeeded", lifecycle_state: "inactive", active: false, remaining_mutations: 0, remaining_changes: 0, latest_recovery_bundle_id: 99, latest_recovery: { id: 99, parent_bundle_id: 7, state: "succeeded", total_actions: 1, completed_actions: 1, started_at: null, finished_at: null, failure_reason: null } }).mockResolvedValue({ ...run, id: 99, parent_bundle_id: 7, state: "succeeded", execution_state: "succeeded", lifecycle_state: "inactive", active: false, remaining_mutations: 0, remaining_changes: 0 });
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  polls.forEach((poll) => poll());
  expect((await screen.findAllByText("Reverted")).length).toBeGreaterThan(0);
});

it("retains selected evidence and warns when its independent refresh fails", async () => {
  auth(); const polls: Array<() => void> = [];
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback) => { polls.push(callback as () => void); return polls.length as unknown as ReturnType<typeof setInterval>; });
  vi.spyOn(globalThis, "clearInterval").mockImplementation(() => undefined);
  vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [run], page: 1, per_page: 200, total: 1 });
  vi.spyOn(api.bundles, "get").mockResolvedValueOnce(run).mockResolvedValueOnce(run).mockRejectedValue(new Error("offline"));
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  polls.forEach((poll) => poll());
  expect(await screen.findByText(/Selected run could not be refreshed/i)).toBeTruthy();
  expect(screen.getByRole("dialog")).toBeTruthy();
});

it("shows recovery child progress instead of original apply progress through completion", async () => {
  auth(); const polls: Array<() => void> = [];
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback) => { polls.push(callback as () => void); return polls.length as unknown as ReturnType<typeof setInterval>; }); vi.spyOn(globalThis, "clearInterval").mockImplementation(() => undefined);
  const source = { ...run, total_actions: 8, completed_actions: 8, lifecycle_state: "recovery_claimed", latest_recovery_bundle_id: 2, actions: [{ reroute_id: 71, position: 0, device_id: 3, device_name: "eMA3", state: "succeeded", failure_reason: null, template_display_name: "Original apply" }] } as RerouteBundle;
  const childRunning = { ...run, id: 2, parent_bundle_id: 7, trigger_type: "rollback", state: "running", execution_state: "running", lifecycle_state: "recovery_running", total_actions: 8, completed_actions: 3, remaining_mutations: 0, actions: [{ reroute_id: 81, position: 0, device_id: 3, device_name: "eMA3", state: "running", failure_reason: null, template_display_name: "Restore policy" }] } as RerouteBundle;
  const sourceDone = { ...source, lifecycle_state: "inactive", active: false, remaining_mutations: 0, remaining_changes: 0, latest_recovery: { id: 2, parent_bundle_id: 7, state: "succeeded", total_actions: 8, completed_actions: 8, started_at: null, finished_at: null, failure_reason: null } } as RerouteBundle;
  const childDone = { ...childRunning, state: "succeeded", execution_state: "succeeded", lifecycle_state: "inactive", completed_actions: 8 } as RerouteBundle;
  vi.spyOn(api.bundles, "list").mockResolvedValueOnce({ items: [source], page: 1, per_page: 200, total: 1 }).mockResolvedValue({ items: [], page: 1, per_page: 200, total: 0 });
  let sourceReads = 0; let childReads = 0;
  vi.spyOn(api.bundles, "get").mockImplementation(async (id) => id === 2 ? (++childReads === 1 ? childRunning : childDone) : (++sourceReads <= 3 ? source : sourceDone));
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  expect(await screen.findByText("Revert progress")).toBeTruthy(); expect(screen.getByText("Restore policy")).toBeTruthy(); expect((await screen.findAllByText("Reverting")).length).toBeGreaterThan(0); const original = screen.getByText("Original apply"); expect(original.closest("details")?.hasAttribute("open")).toBe(false);
  polls.forEach((poll) => poll()); expect(await screen.findByText(/Revert completed · recovery #2/)).toBeTruthy(); expect((await screen.findAllByText(/Reverted|Revert completed/)).length).toBeGreaterThan(0);
});

it("clears old child evidence when the parent switches recovery IDs and the new child is unavailable", async () => {
  auth(); const polls: Array<() => void> = [];
  vi.spyOn(globalThis, "setInterval").mockImplementation((callback) => { polls.push(callback as () => void); return polls.length as unknown as ReturnType<typeof setInterval>; }); vi.spyOn(globalThis, "clearInterval").mockImplementation(() => undefined);
  const source2 = { ...run, latest_recovery_bundle_id: 2, lifecycle_state: "recovery_running" } as RerouteBundle;
  const source3 = { ...source2, latest_recovery_bundle_id: 3 } as RerouteBundle;
  const child2 = { ...run, id: 2, parent_bundle_id: 7, state: "running", execution_state: "running", actions: [{ reroute_id: 82, position: 0, device_id: 3, device_name: "eMA3", state: "running", failure_reason: null, template_display_name: "Old child evidence" }] } as RerouteBundle;
  let sourceReads = 0;
  vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [source2], page: 1, per_page: 200, total: 1 });
  vi.spyOn(api.bundles, "get").mockImplementation(async (id) => { if (id === 2) return child2; if (id === 3) throw new Error("unavailable"); return ++sourceReads <= 2 ? source2 : source3; });
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  polls.forEach((poll) => poll()); expect(await screen.findByText(/unavailable for this recovery run/i)).toBeTruthy(); expect(screen.queryByText("Old child evidence")).toBeNull(); expect((await screen.findAllByText(/recovery #3/i)).length).toBeGreaterThan(0);
});
