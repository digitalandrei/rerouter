// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActionParamsForm } from "@/components/action-params-form";
import type { TemplateParamSpec } from "@/lib/api";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

const schema = {
  neighbor_ip: { type: "ip", required: true },
  policy_kind: { type: "string", required: true },
  policy_name: { type: "string", required: true },
} as Record<string, TemplateParamSpec>;

describe("export policy action form", () => {
  it("materializes the visible prefix-list default in a new action", async () => {
    const onChange = vi.fn();
    render(<ActionParamsForm schema={schema} deviceId={null} values={{}} onChange={onChange} />);
    await waitFor(() => expect(onChange).toHaveBeenCalledWith({ policy_kind: "prefix_list" }));
    expect((screen.getByRole("option", { name: /outbound prefix list \(recommended\)/i }) as HTMLOptionElement).selected).toBe(true);
  });

  it("keeps a saved route-map draft explicit without converting its type", () => {
    const onChange = vi.fn();
    render(<ActionParamsForm schema={schema} deviceId={null} values={{ policy_kind: "route_map", policy_name: "RM-SAVED" }} onChange={onChange} />);
    expect((screen.getByRole("option", { name: /outbound route map \(advanced\)/i }) as HTMLOptionElement).selected).toBe(true);
    expect(screen.getByText("RM-SAVED (missing)")).toBeTruthy();
    expect(onChange).not.toHaveBeenCalled();
  });
});
