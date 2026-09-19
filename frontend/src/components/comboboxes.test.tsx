// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { SearchableSelect } from "@/components/searchable-select";
import { AutocompleteInput } from "@/components/autocomplete-input";

afterEach(cleanup);

describe("accessible comboboxes", () => {
  it("selects a filtered fixed option with the keyboard", async () => {
    const user = userEvent.setup();
    let selected = "";
    render(<SearchableSelect aria-label="Protocol" options={[{ value: "6", label: "TCP" }, { value: "17", label: "UDP" }]} value={selected} onChange={(value) => { selected = value; }} />);
    const input = screen.getByRole("combobox", { name: "Protocol" });
    await user.click(input);
    await user.keyboard("{ArrowDown}{ArrowDown}{Enter}");
    expect(selected).toBe("17");
    expect(input.getAttribute("aria-expanded")).toBe("false");
  });

  it("navigates async suggestions and preserves ordinary Enter submission", async () => {
    const user = userEvent.setup();
    let value = "10";
    let submitted = 0;
    const view = render(<AutocompleteInput aria-label="Source address" value={value} onChange={(next) => { value = next; }} fetchSuggestions={async () => ["10.0.0.1", "10.0.0.2"]} onEnter={() => { submitted += 1; }} />);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const input = screen.getByRole("combobox", { name: "Source address" });
    await user.click(input);
    await user.keyboard("{ArrowDown}{ArrowDown}{Enter}");
    expect(value).toBe("10.0.0.2");
    view.rerender(<AutocompleteInput aria-label="Source address" value={value} onChange={(next) => { value = next; }} fetchSuggestions={async () => []} onEnter={() => { submitted += 1; }} />);
    await user.keyboard("{Escape}{Enter}");
    expect(submitted).toBe(1);
  });
});
