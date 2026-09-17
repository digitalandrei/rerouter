// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { BrowserRouter } from "react-router-dom";
import { ApplyResultRow } from "@/components/apply-mitigation-dialog";

afterEach(cleanup);

describe("ApplyResultRow", () => {
  it("renders an HTTP-200 failed outcome as failed rather than success", () => {
    render(
      <BrowserRouter>
        <ApplyResultRow
          r={{
            executed: true,
            reroute_id: 44,
            state: "failed",
            message: "verification did not confirm the change",
            device_id: 7,
            device_name: "edge-1",
            mutation_effect: "unknown",
          }}
        />
      </BrowserRouter>,
    );
    expect(screen.getByText("failed")).toBeTruthy();
    expect(screen.queryByText("succeeded")).toBeNull();
    expect(screen.getByText("change unknown")).toBeTruthy();
  });

  it("labels a verified no-op without claiming a configuration change", () => {
    render(
      <BrowserRouter>
        <ApplyResultRow
          r={{
            executed: true,
            state: "succeeded",
            message: "router already matched the requested state",
            device_id: 7,
            mutation_effect: "noop",
          }}
        />
      </BrowserRouter>,
    );
    expect(screen.getByText(/already satisfied · no change sent/)).toBeTruthy();
  });
});
