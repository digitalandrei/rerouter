// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, AUTH_RETURN_TO_KEY } from "@/lib/api";
import { AuthProvider, useAuth } from "@/lib/auth";
import Login from "@/pages/Login";

function Probe() { const auth = useAuth(); return <><span>{auth.stage}</span><span>{auth.user?.email ?? "no-user"}</span></>; }
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); window.sessionStorage.clear(); });

describe("AuthProvider session probing", () => {
  it("treats only 401 as anonymous", async () => {
    vi.spyOn(api.auth, "me").mockRejectedValue(new ApiError(401, "unauthorized"));
    render(<AuthProvider><Probe /></AuthProvider>);
    expect(await screen.findByText("anonymous")).toBeTruthy();
  });

  it("uses bounded retries and reports unavailable for network failures", async () => {
    vi.useFakeTimers();
    const me = vi.spyOn(api.auth, "me").mockRejectedValue(new TypeError("offline"));
    render(<AuthProvider><Probe /></AuthProvider>);
    await act(async () => { await vi.advanceTimersByTimeAsync(1600); });
    expect(screen.getByText("unavailable")).toBeTruthy();
    expect(me).toHaveBeenCalledTimes(3);
    expect(screen.queryByText("anonymous")).toBeNull();
  });

  it("returns to a validated internal route after password and TOTP", async () => {
    const user = userEvent.setup();
    vi.spyOn(api.auth, "me").mockRejectedValue(new ApiError(401, "unauthorized"));
    vi.spyOn(api.auth, "login").mockResolvedValue({ totp_required: true });
    vi.spyOn(api.auth, "totp").mockResolvedValue({ user: { id: 1, email: "operator@example.test", name: "Operator", roles: ["operator"], permissions: [] } });
    render(<AuthProvider><MemoryRouter initialEntries={["/login?returnTo=%2Frules%3Fdevice%3D2%23actions"]}><Routes><Route path="/login" element={<Login />} /><Route path="/rules" element={<span>returned to rules</span>} /></Routes></MemoryRouter></AuthProvider>);
    await screen.findByLabelText("Email");
    await user.type(screen.getByLabelText("Email"), "operator@example.test");
    await user.type(screen.getByLabelText("Password"), "password");
    await user.click(screen.getByRole("button", { name: "Continue" }));
    await user.type(await screen.findByLabelText("Code"), "123456");
    await user.click(screen.getByRole("button", { name: "Verify" }));
    expect(await screen.findByText("returned to rules")).toBeTruthy();
  });

  it("stores the filtered deep link before a global 401 redirect", async () => {
    window.history.replaceState({}, "", "/rules?device=2&rule=edge#actions");
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response('{"error":"expired"}', { status: 401, headers: { "content-type": "application/json" } })));
    await expect(api.devices.list()).rejects.toMatchObject({ status: 401 });
    expect(window.sessionStorage.getItem(AUTH_RETURN_TO_KEY)).toBe("/rules?device=2&rule=edge#actions");
    vi.unstubAllGlobals();
  });
});
