// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError, type Device } from "@/lib/api";
import DeviceDetail from "@/pages/DeviceDetail";

vi.mock("@/lib/auth", () => ({ useAuth: () => ({ hasPermission: () => true }) }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("keeps a failed device reload visible after inventory discovery", async () => {
  const device = {
    id: 3, name: "eMA3", hostname: "192.0.2.3", reachable: true, enabled: true,
    vendor: "Cisco", model: "ASR", os_version: "IOS", sys_name: "eMA3", sys_uptime: null,
    snmp_version: "v2c", snmp_port: 161, poll_interval_seconds: 30, interface_count: 0,
    ssh_port: 22, ssh_username: "rerouter", ssh_auth_method: "key", ssh_configured: true,
    ssh_public_key: null, ssh_status: "reachable", last_ssh_error: null, last_ssh_ok_at: null,
    ssh_reachable_since: null, automation_stable: true, ssh_recent: true, last_error: null,
  } as Device;
  let rejectReload!: (error: unknown) => void;
  vi.spyOn(api.devices, "get")
    .mockResolvedValueOnce(device)
    .mockImplementationOnce(() => new Promise((_, reject) => { rejectReload = reject; }));
  vi.spyOn(api.devices, "interfaces").mockResolvedValue([]);
  vi.spyOn(api.devices, "discover").mockResolvedValue({ ok: true } as never);
  vi.spyOn(api.devices, "discoverBgp").mockResolvedValue({ ok: true } as never);
  vi.spyOn(api.devices, "discoverPrefixes").mockResolvedValue({ ok: true } as never);
  vi.spyOn(api.devices, "bgpPeers").mockResolvedValue([]);
  vi.spyOn(api.devices, "bgpNetworks").mockResolvedValue([]);
  vi.spyOn(api.rules, "list").mockResolvedValue([]);
  vi.spyOn(api.routingPolicies, "get").mockResolvedValue({ device_id: 3, read_at: null, completeness: "complete", blockers: [], prefix_lists: [], route_maps: [], peer_bindings: [] });

  const user = userEvent.setup();
  render(<MemoryRouter initialEntries={["/devices/3"]}><Routes><Route path="/devices/:id" element={<DeviceDetail />} /></Routes></MemoryRouter>);
  await user.click(await screen.findByRole("button", { name: "Refresh" }));
  expect(await screen.findByRole("button", { name: "Refreshing inventory…" })).toBeTruthy();
  rejectReload(new ApiError(503, "device reload failed"));
  await waitFor(() => expect(screen.getByText("device reload failed")).toBeTruthy());
  expect(screen.queryByText("Refreshed device inventory")).toBeNull();
});
