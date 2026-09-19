// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, expect, it, vi } from "vitest";
import { api, type User } from "@/lib/api";
import { AuthProvider } from "@/lib/auth";
import Users from "@/pages/Users";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("marks only the selected row operation busy while 2FA reset is pending", async () => {
  const account = { id: 4, email: "operator@example.test", name: "Operator", role: "operator", twofa_enrolled: true, created_at: "2026-09-19T00:00:00Z" } as User;
  vi.spyOn(api.auth, "me").mockResolvedValue({ id: 1, email: "admin@example.test", name: "Admin", roles: ["superadmin"], permissions: ["manage_users"] });
  vi.spyOn(api.users, "list").mockResolvedValue([account]);
  let finish!: (value: { ok: true; enrollment_code: string }) => void;
  const reset = vi.spyOn(api.users, "reset2fa").mockImplementation(() => new Promise((resolve) => { finish = resolve; }));
  const user = userEvent.setup();
  render(<AuthProvider><MemoryRouter><Users /></MemoryRouter></AuthProvider>);
  await user.click(await screen.findByRole("button", { name: `Reset 2FA for ${account.email}` }));
  await user.click(screen.getByRole("button", { name: "Reset 2FA" }));
  let rowPending: HTMLButtonElement | undefined;
  await waitFor(() => {
    rowPending = Array.from(document.querySelectorAll<HTMLButtonElement>('button[aria-busy="true"]'))
      .find((button) => button.getAttribute("aria-label") === `Resetting 2FA for ${account.email}`);
    expect(rowPending).toBeTruthy();
  });
  expect(rowPending!.getAttribute("aria-busy")).toBe("true");
  const confirmPending = screen.getByRole("button", { name: "Reset 2FA…" });
  await user.click(confirmPending);
  expect(reset).toHaveBeenCalledTimes(1);
  finish({ ok: true, enrollment_code: "enroll-once" });
  await waitFor(() => expect(screen.getByText("One-time enrollment code")).toBeTruthy());
});
