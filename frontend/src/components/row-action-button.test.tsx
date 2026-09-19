// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Link, useLocation } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import { Eye } from "lucide-react";

import { RowActionButton } from "@/components/row-action-button";

afterEach(cleanup);

function CurrentPath() {
  return <output aria-label="Current path">{useLocation().pathname}</output>;
}

describe("RowActionButton", () => {
  it("has an accessible name and explains the action on hover and focus", async () => {
    const user = userEvent.setup();
    render(<RowActionButton label="View device"><Eye /></RowActionButton>);

    const button = screen.getByRole("button", { name: "View device" });
    await user.hover(button);
    expect((await screen.findByRole("tooltip")).textContent).toContain("View device");

    await user.unhover(button);
    button.focus();
    expect((await screen.findByRole("tooltip")).textContent).toContain("View device");
  });

  it("keeps a disabled reason keyboard discoverable", async () => {
    const user = userEvent.setup();
    render(
      <RowActionButton label="Delete user" disabled disabledReason="This user owns the active session">
        <Eye />
      </RowActionButton>,
    );

    expect((screen.getByRole("button", { name: "Delete user" }) as HTMLButtonElement).disabled).toBe(true);
    await user.tab();
    expect(document.activeElement).toBe(screen.getByLabelText("Delete user: This user owns the active session"));
    expect((await screen.findByRole("tooltip")).textContent).toContain("Delete user: This user owns the active session");
  });

  it("preserves link semantics", () => {
    render(
      <MemoryRouter>
        <RowActionButton asChild label="View run"><Link to="/runs/7"><Eye /></Link></RowActionButton>
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: "View run" }).getAttribute("href")).toBe("/runs/7");
  });

  it("prevents disabled links from navigating", async () => {
    const user = userEvent.setup();
    render(
      <MemoryRouter>
        <RowActionButton asChild label="View run" disabled disabledReason="Run is unavailable">
          <Link to="/runs/7"><Eye /></Link>
        </RowActionButton>
        <CurrentPath />
      </MemoryRouter>,
    );

    const link = screen.getByRole("link", { name: "View run" });
    expect(link.getAttribute("aria-disabled")).toBe("true");
    await user.click(link);
    expect(screen.getByLabelText("Current path").textContent).toBe("/");

    screen.getByLabelText("View run: Run is unavailable").focus();
    await user.keyboard("{Enter}");
    expect(screen.getByLabelText("Current path").textContent).toBe("/");
  });
});
