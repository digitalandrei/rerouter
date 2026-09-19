// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import { Button } from "@/components/ui/button";

it("announces loading, shows a spinner, and blocks repeat clicks", async () => {
  const click = vi.fn();
  const { rerender } = render(<Button onClick={click}>Preview changes</Button>);
  await userEvent.click(screen.getByRole("button", { name: "Preview changes" }));
  expect(click).toHaveBeenCalledTimes(1);
  rerender(<Button onClick={click} loading loadingLabel="Preparing exact preview…">Preview changes</Button>);
  const button = screen.getByRole("button", { name: "Preparing exact preview…" });
  expect(button.getAttribute("aria-busy")).toBe("true");
  expect((button as HTMLButtonElement).disabled).toBe(true);
  expect(button.querySelector("svg.animate-spin")).not.toBeNull();
  await userEvent.click(button);
  expect(click).toHaveBeenCalledTimes(1);
});
