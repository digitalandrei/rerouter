import type { ReactNode } from "react";
import { AlertTriangle, LoaderCircle, LockKeyhole } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { ResourceState } from "@/lib/resource-state";

interface DataStateProps<T> {
  state: ResourceState<T>;
  retry?: () => void;
  children: (data: T) => ReactNode;
  loadingLabel?: string;
  empty?: (data: T) => boolean;
  emptyContent?: ReactNode;
}

export function DataState<T>({
  state,
  retry,
  children,
  loadingLabel = "Loading data…",
  empty,
  emptyContent = "No data is available yet.",
}: DataStateProps<T>) {
  if (state.status === "loading") {
    return <div role="status" className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><LoaderCircle className="h-4 w-4 animate-spin" />{loadingLabel}</div>;
  }
  if (state.status === "forbidden") {
    return <div role="status" className="flex items-center gap-2 py-6 text-sm text-muted-foreground"><LockKeyhole className="h-4 w-4" />You don’t have permission to view this data.</div>;
  }

  const data = state.data;
  return (
    <>
      {state.status === "error" && (
        <div role="alert" className="mb-4 flex flex-wrap items-center gap-2 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4" />
          <span>{state.stale ? "Showing the last available data. Refresh failed." : "Data could not be loaded."}</span>
          {retry && <Button type="button" size="sm" variant="outline" onClick={retry}>Try again</Button>}
        </div>
      )}
      {data !== undefined && (empty?.(data) ? emptyContent : children(data))}
    </>
  );
}
