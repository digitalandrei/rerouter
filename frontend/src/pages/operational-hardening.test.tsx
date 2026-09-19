// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import Flows from "@/pages/Flows";
import { NotificationsCard } from "@/pages/settings/notifications-card";

const mocks = vi.hoisted(() => ({
  devices: vi.fn(), interfaces: vi.fn(), search: vi.fn(), recipients: vi.fn(), webhooks: vi.fn(), eventTypes: vi.fn(),
}));

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ hasPermission: () => false }) }));
vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error { status = 500; },
  api: {
    devices: { list: mocks.devices, interfaces: mocks.interfaces },
    flows: { search: mocks.search, suggest: vi.fn().mockResolvedValue([]), detail: vi.fn() },
    notifications: {
      recipients: mocks.recipients, webhooks: mocks.webhooks, eventTypes: mocks.eventTypes,
      addRecipient: vi.fn(), addWebhook: vi.fn(), removeRecipient: vi.fn(), removeWebhook: vi.fn(), testRecipient: vi.fn(), testWebhook: vi.fn(),
    },
  },
}));

afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mocks.devices.mockResolvedValue([]); mocks.interfaces.mockResolvedValue([]); mocks.search.mockResolvedValue({ minutes: 60, rows: [] }); });

function Location() { return <output aria-label="location">{useLocation().search}</output>; }

describe("operational resource hardening", () => {
  it("surfaces an invalid URL port and does not silently issue an unfiltered flow request", async () => {
    render(<MemoryRouter initialEntries={["/flows?tab=search&port=99999"]}><Flows /><Location /></MemoryRouter>);
    expect(await screen.findByText("Enter a numeric port")).toBeTruthy();
    expect(screen.getByLabelText("location").textContent).toContain("port=99999");
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(mocks.search).not.toHaveBeenCalled();
  });

  it("does not render failed notification loads as confirmed empty or expose mutations without permission", async () => {
    mocks.eventTypes.mockRejectedValue(new Error("offline"));
    mocks.recipients.mockResolvedValue([]); mocks.webhooks.mockResolvedValue([]);
    render(<NotificationsCard />);
    expect(await screen.findByText("Data could not be loaded.")).toBeTruthy();
    expect(screen.queryByText("No recipients yet.")).toBeNull();
    expect(screen.queryByRole("button", { name: "Add recipient" })).toBeNull();
  });

  it("renders confirmed empty notification routes distinctly", async () => {
    mocks.eventTypes.mockResolvedValue([]); mocks.recipients.mockResolvedValue([]); mocks.webhooks.mockResolvedValue([]);
    render(<NotificationsCard />);
    await waitFor(() => expect(screen.getByText("No recipients yet.")).toBeTruthy());
    expect(screen.getByText("No webhooks yet.")).toBeTruthy();
  });
});
