// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
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

it("ignores a late revert preview after the audit reason changes and confirms the exact new reason", async () => {
  auth(); vi.spyOn(api.bundles, "list").mockResolvedValue({ items: [run], page: 1, per_page: 200, total: 1 }); vi.spyOn(api.bundles, "get").mockResolvedValue(run);
  let resolveOld!: (value: ManualMitigationPreview) => void;
  const revert = vi.spyOn(api.bundles, "revert").mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve as (value: ManualMitigationPreview) => void; })).mockResolvedValueOnce(preview).mockResolvedValueOnce({ bundle_id: 99, async: true });
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" }));
  const reason = await screen.findByLabelText("Audit reason"); await user.type(reason, "Reason A"); await user.click(screen.getByRole("button", { name: "Preview whole-run revert" }));
  await user.clear(reason); await user.type(reason, "Reason B"); resolveOld({ ...preview, preview_token: "token-a" }); await new Promise((resolve) => setTimeout(resolve, 0));
  expect(screen.queryByRole("button", { name: "Confirm reviewed revert" })).toBeNull();
  await user.click(screen.getByRole("button", { name: "Preview whole-run revert" })); await user.click(await screen.findByRole("button", { name: "Confirm reviewed revert" }));
  expect(revert).toHaveBeenLastCalledWith(7, { dry_run: false, reason: "Reason B", plan_id: 12, preview_token: "token-b" });
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
  let resolvePoll!: (value: { items: RerouteBundle[]; page: number; per_page: number; total: number }) => void;
  vi.spyOn(api.bundles, "list").mockResolvedValueOnce({ items: [run], page: 1, per_page: 200, total: 1 }).mockImplementationOnce(() => new Promise((resolve) => { resolvePoll = resolve; }));
  vi.spyOn(api.bundles, "get").mockResolvedValue(run);
  const user = userEvent.setup(); render(<AuthProvider><MemoryRouter><ActiveRunsTab /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: "Review run 7" })); const closeButtons = await screen.findAllByRole("button", { name: "Close" }); await user.click(closeButtons.find((button) => button.textContent === "Close")!);
  polls.forEach((poll) => poll()); await vi.waitFor(() => expect(resolvePoll).toBeTypeOf("function")); resolvePoll({ items: [run], page: 1, per_page: 200, total: 1 }); await Promise.resolve();
  expect(screen.queryByRole("dialog")).toBeNull();
});
