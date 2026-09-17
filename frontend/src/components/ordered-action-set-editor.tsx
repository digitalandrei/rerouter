import { ArrowDown, ArrowUp, GripVertical, RotateCcw, Trash2 } from "lucide-react";
import type { ActionDraft, Device, Template } from "@/lib/api";
import { templateLabel } from "@/lib/labels";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

export interface OrderedActionItem extends ActionDraft {
  client_key?: string;
  overridden?: boolean;
  warning?: string | null;
}

export function OrderedActionSetEditor({
  actions,
  templates,
  devices,
  busy = false,
  readOnly = false,
  selectedIndex,
  onSelect,
  onMove,
  onRemove,
  onReset,
  emptyMessage = "No actions yet.",
}: {
  actions: OrderedActionItem[];
  templates: Template[];
  devices: Device[];
  busy?: boolean;
  readOnly?: boolean;
  selectedIndex?: number | null;
  onSelect?: (index: number) => void;
  onMove?: (index: number, delta: -1 | 1) => void;
  onRemove?: (index: number) => void;
  onReset?: (index: number) => void;
  emptyMessage?: string;
}) {
  if (actions.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-border px-4 py-6 text-center text-sm text-muted-foreground">
        {emptyMessage}
      </div>
    );
  }

  return (
    <ol className="space-y-2" aria-label="Ordered mitigation actions">
      {actions.map((action, index) => {
        const template = templates.find((item) => item.id === action.reroute_template_id);
        const device = devices.find((item) => item.id === action.device_id);
        const params = Object.entries(action.params ?? {});
        const selected = selectedIndex === index;
        return (
          <li
            key={action.client_key ?? action.id ?? `${action.reroute_template_id}-${action.device_id}-${index}`}
            className={`rounded-md border p-3 transition-colors ${
              selected ? "border-foreground bg-muted/50" : "border-border bg-background"
            }`}
          >
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <GripVertical className="size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
              <span className="inline-flex size-6 shrink-0 items-center justify-center rounded bg-muted text-xs font-semibold tabular-nums">
                {index + 1}
              </span>
              <button
                type="button"
                className="min-w-0 flex-1 text-left outline-none focus-visible:rounded-sm focus-visible:ring-2 focus-visible:ring-ring"
                onClick={() => onSelect?.(index)}
                disabled={!onSelect}
                aria-pressed={onSelect ? selected : undefined}
              >
                <span className="block truncate text-sm font-medium">
                  {template ? templateLabel(template) : `Action template #${action.reroute_template_id}`}
                </span>
                <span className="block truncate text-xs text-muted-foreground">
                  {device?.name ?? `Router #${action.device_id}`}
                </span>
              </button>
              {action.overridden && (
                <Badge variant="outline" className="border-amber-500 text-amber-800 dark:text-amber-300">
                  temporary override
                </Badge>
              )}
              {!action.enabled && <Badge variant="outline">disabled</Badge>}
              {!readOnly && onMove && (
                <div className="flex items-center" aria-label={`Reorder action ${index + 1}`}>
                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    disabled={busy || index === 0}
                    onClick={() => onMove(index, -1)}
                    title="Run earlier"
                  >
                    <ArrowUp className="size-4" />
                    <span className="sr-only">Move action {index + 1} earlier</span>
                  </Button>
                  <Button
                    type="button"
                    size="icon-sm"
                    variant="ghost"
                    disabled={busy || index === actions.length - 1}
                    onClick={() => onMove(index, 1)}
                    title="Run later"
                  >
                    <ArrowDown className="size-4" />
                    <span className="sr-only">Move action {index + 1} later</span>
                  </Button>
                </div>
              )}
              {onReset && action.overridden && (
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  disabled={busy}
                  onClick={() => onReset(index)}
                  title="Reset temporary override"
                >
                  <RotateCcw className="size-4" />
                  <span className="sr-only">Reset override for action {index + 1}</span>
                </Button>
              )}
              {!readOnly && onRemove && (
                <Button
                  type="button"
                  size="icon-sm"
                  variant="ghost"
                  className="text-destructive hover:text-destructive"
                  disabled={busy}
                  onClick={() => onRemove(index)}
                  title="Remove action"
                >
                  <Trash2 className="size-4" />
                  <span className="sr-only">Remove action {index + 1}</span>
                </Button>
              )}
            </div>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 pl-12 text-xs text-muted-foreground">
              {action.auto_target === "flow_dst_host" && (
                <span className="font-medium text-amber-800 dark:text-amber-300">
                  target resolved from rule flows
                </span>
              )}
              {params.map(([name, value]) => (
                <span key={name} className="break-all">
                  <span className="font-medium text-foreground">{name}</span>={String(value)}
                </span>
              ))}
              {params.length === 0 && !action.auto_target && <span>No parameters saved</span>}
            </div>
            {action.warning && (
              <p className="mt-2 break-words pl-12 text-xs text-amber-800 dark:text-amber-300" role="status">
                {action.warning}
              </p>
            )}
          </li>
        );
      })}
    </ol>
  );
}
