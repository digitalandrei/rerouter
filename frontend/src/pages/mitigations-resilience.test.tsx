// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { createMemoryRouter, RouterProvider } from "react-router-dom";
import { api } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import Mitigations from "@/pages/Mitigations";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("does not report normal operation when rules fail and keeps tabs URL-owned", async () => {
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "viewer@example.test", name: "Viewer", roles: ["viewer"], permissions: ["view_asset"] });
  vi.spyOn(api.rules, "list").mockRejectedValue(new Error("rules offline"));
  vi.spyOn(api.alerts, "list").mockResolvedValue({ rows: [], total: 0 } as never);
  vi.spyOn(api.settings, "get").mockResolvedValue({ operating_mode: "observe", automatic_actions_enabled: false, global_lock: false });
  const router = createMemoryRouter([{ path: "/mitigations", element: <Mitigations /> }], { initialEntries: ["/mitigations?tab=detections"] });
  const user = userEvent.setup();
  render(<AuthProvider><RouterProvider router={router} /></AuthProvider>);
  expect(await screen.findByText(/Detections are unavailable: rules offline/)).toBeTruthy();
  expect(screen.queryByText(/system is operating normally/i)).toBeNull();
  await user.click(screen.getByRole("tab", { name: "Alerts" }));
  expect(router.state.location.search).toContain("tab=alerts");
  await router.navigate("/mitigations?tab=detections");
  await vi.waitFor(() => expect(screen.getByRole("tab", { name: /Detections/ }).getAttribute("data-state")).toBe("active"));
});
