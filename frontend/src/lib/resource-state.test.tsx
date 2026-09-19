// @vitest-environment jsdom
import { renderHook, waitFor } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApiError } from "@/lib/api";
import { useResource } from "@/lib/resource-state";

describe("useResource", () => {
  it("does not retain data across resource identity changes", async () => {
    const { result, rerender } = renderHook(
      ({ id }) => useResource(async () => {
        if (id === "b") throw new Error("offline");
        return `data-${id}`;
      }, [id]),
      { initialProps: { id: "a" } },
    );
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    rerender({ id: "b" });
    await waitFor(() => expect(result.current.state.status).toBe("error"));
    expect(result.current.state.data).toBeUndefined();
    expect(result.current.state.stale).toBe(false);
  });

  it("clears previously visible data when access becomes forbidden", async () => {
    let forbidden = false;
    const { result } = renderHook(() => useResource(async () => {
      if (forbidden) throw new ApiError(403, "forbidden");
      return ["private"];
    }, []));
    await waitFor(() => expect(result.current.state.status).toBe("ready"));
    expect(result.current.state.updatedAt).toBeInstanceOf(Date);
    forbidden = true;
    result.current.retry();
    await waitFor(() => expect(result.current.state.status).toBe("forbidden"));
    expect(result.current.state.data).toBeUndefined();
    expect(result.current.state.updatedAt).toBeNull();
  });
});
