// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { PromptDialog } from "@/components/prompt-dialog";

afterEach(cleanup);

it("announces the pending submit and prevents duplicate submission", async () => {
  let finish!: () => void;
  const submit = vi.fn(() => new Promise<void>((resolve) => { finish = resolve; }));
  const user = userEvent.setup();
  render(<PromptDialog open onOpenChange={() => undefined} title="Set label" label="Label" submitLabel="Save label" onSubmit={submit} />);
  await user.type(screen.getByRole("textbox", { name: "Label" }), "Transit A");
  await user.click(screen.getByRole("button", { name: "Save label" }));
  const pending = screen.getByRole("button", { name: "Save label…" });
  expect(pending.getAttribute("aria-busy")).toBe("true");
  expect((pending as HTMLButtonElement).disabled).toBe(true);
  await user.click(pending);
  expect(submit).toHaveBeenCalledTimes(1);
  finish();
  await waitFor(() => expect(screen.getByRole("button", { name: "Save label" })).toBeTruthy());
});
