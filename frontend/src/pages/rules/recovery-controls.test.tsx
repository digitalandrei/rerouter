// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it } from "vitest";
import { RuleDialog } from "@/pages/rules/rule-dialog";
import type { Rule } from "@/lib/api";

afterEach(cleanup);
beforeEach(() => { globalThis.ResizeObserver = class { observe() {} unobserve() {} disconnect() {} }; });

it("keeps the clear condition separate and defaults automatic revert off", () => {
  render(<RuleDialog rule={null} devices={[]} onClose={() => undefined} onSaved={() => undefined} />);
  expect(screen.getByRole("combobox", { name: /Recovery/ })).toBeTruthy();
  expect(screen.getByRole("switch", { name: "Automatically revert after recovery" }).getAttribute("data-state")).toBe("unchecked");
});

it("preserves an existing automatic-revert preference", () => {
  const existing = { id: 1, name: "Existing", automatic_revert_enabled: true, recovery_mode: "manual" } as unknown as Rule;
  render(<RuleDialog rule={existing} devices={[]} onClose={() => undefined} onSaved={() => undefined} />);
  expect(screen.getByRole("switch", { name: "Automatically revert after recovery" }).getAttribute("data-state")).toBe("checked");
  expect((screen.getByRole("combobox", { name: /Recovery/ }) as HTMLSelectElement).value).toBe("manual");
});
