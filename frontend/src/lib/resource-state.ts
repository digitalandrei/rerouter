import { useCallback, useEffect, useRef, useState, type DependencyList } from "react";
import { ApiError } from "@/lib/api";

export type ResourceState<T> =
  | { status: "loading"; data?: undefined; error?: undefined; stale: false; updatedAt: null }
  | { status: "ready"; data: T; error?: undefined; stale: false; updatedAt: Date }
  | { status: "error"; data?: T; error: Error; stale: boolean; updatedAt: Date | null }
  | { status: "forbidden"; data?: undefined; error: Error; stale: false; updatedAt: null };

export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  dependencies: DependencyList,
) {
  const [state, setState] = useState<ResourceState<T>>({ status: "loading", stale: false, updatedAt: null });
  const [revision, setRevision] = useState(0);
  const dataRef = useRef<T | undefined>(undefined);
  const updatedAtRef = useRef<Date | null>(null);
  const identityRef = useRef<DependencyList | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    const sameIdentity = identityRef.current !== null && identityRef.current.length === dependencies.length && identityRef.current.every((value, index) => Object.is(value, dependencies[index]));
    identityRef.current = [...dependencies];
    if (!sameIdentity) {
      dataRef.current = undefined;
      updatedAtRef.current = null;
    }
    if (dataRef.current === undefined) setState({ status: "loading", stale: false, updatedAt: null });

    load(controller.signal).then(
      (data) => {
        if (controller.signal.aborted) return;
        dataRef.current = data;
        const updatedAt = new Date();
        updatedAtRef.current = updatedAt;
        setState({ status: "ready", data, stale: false, updatedAt });
      },
      (cause: unknown) => {
        if (controller.signal.aborted) return;
        const error = cause instanceof Error ? cause : new Error("Request failed");
        if (cause instanceof ApiError && cause.status === 403) {
          dataRef.current = undefined;
          updatedAtRef.current = null;
          setState({ status: "forbidden", error, stale: false, updatedAt: null });
          return;
        }
        setState({ status: "error", data: dataRef.current, error, stale: dataRef.current !== undefined, updatedAt: updatedAtRef.current });
      },
    );

    return () => controller.abort();
    // Callers provide the dependencies that define the GET request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, revision]);

  const retry = useCallback(() => setRevision((value) => value + 1), []);
  return { state, retry };
}
