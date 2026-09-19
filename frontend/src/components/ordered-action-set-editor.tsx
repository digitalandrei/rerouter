import type { ReactNode } from "react";
import { ArrowDown, ArrowUp, Pencil, RotateCcw, Trash2, X } from "lucide-react";
import type { ActionDraft, Device, Template } from "@/lib/api";
import { templateLabel } from "@/lib/labels";
import { Badge } from "@/components/ui/badge";
import { RowActionButton } from "@/components/row-action-button";

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
  editLabel = "Edit",
  renderEditor,
  emptyMessage = "No actions yet.",
}: {
  actions: OrderedActionItem[];
  templates: Template[];
  devices: Device[];
  busy?: boolean;
  readOnly?: boolean;
  selectedIndex?: number | null;
  onSelect?: (index: number | null) => void;
  onMove?: (index: number, delta: -1 | 1) => void;
  onRemove?: (index: number) => void;
  onReset?: (index: number) => void;
  editLabel?: "Edit" | "Override";
  renderEditor?: (index: number) => ReactNode;
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
        const isPolicyChange = template?.name === "bgp_export_policy_set";
        const selected = selectedIndex === index;
        return (
          <li
            key={action.client_key ?? action.id ?? `${action.reroute_template_id}-${action.device_id}-${index}`}
            className={`rounded-md border p-3 transition-colors ${
              selected ? "border-foreground bg-muted/50" : "border-border bg-background"
            }`}
          >
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <div className="flex min-w-0 basis-full items-center gap-2 sm:basis-0 sm:flex-1">
                <span className="inline-flex size-6 shrink-0 items-center justify-center rounded bg-muted text-xs font-semibold tabular-nums">
                  {index + 1}
                </span>
                <div className="min-w-0 flex-1 text-left">
                  <span className="block truncate text-sm font-medium">
                    {template ? templateLabel(template) : `Action template #${action.reroute_template_id}`}
                  </span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {device?.name ?? `Router #${action.device_id}`}
                  </span>
                </div>
              </div>
              {action.overridden && (
                <Badge variant="outline" className="border-amber-500 text-amber-800 dark:text-amber-300">
                  temporary override
                </Badge>
              )}
              {!action.enabled && <Badge variant="outline">disabled</Badge>}
              <div className="ml-8 flex flex-wrap items-center gap-1 sm:ml-0">
                {onSelect && (
                  <RowActionButton
                    label={selected ? `Close editor for action ${index + 1}` : `${editLabel} action ${index + 1}`}
                    aria-expanded={selected}
                    disabled={busy}
                    disabledReason="Wait for the current request to finish"
                    onClick={() => onSelect(selected ? null : index)}
                  >
                    {selected ? <X className="size-4" /> : <Pencil className="size-4" />}
                  </RowActionButton>
                )}
                {!readOnly && onMove && (
                  <div className="flex items-center gap-1" aria-label={`Reorder action ${index + 1}`}>
                    <RowActionButton
                      type="button"
                      label={`Move action ${index + 1} earlier`}
                      disabled={busy || index === 0}
                      disabledReason={index === 0 ? "Already the first action" : "Wait for the current request to finish"}
                      onClick={() => onMove(index, -1)}
                    >
                      <ArrowUp className="size-4" />
                    </RowActionButton>
                    <RowActionButton
                      type="button"
                      label={`Move action ${index + 1} later`}
                      disabled={busy || index === actions.length - 1}
                      disabledReason={index === actions.length - 1 ? "Already the last action" : "Wait for the current request to finish"}
                      onClick={() => onMove(index, 1)}
                    >
                      <ArrowDown className="size-4" />
                    </RowActionButton>
                  </div>
                )}
                {onReset && action.overridden && (
                  <RowActionButton
                    type="button"
                    label={`Reset override for action ${index + 1}`}
                    disabled={busy}
                    disabledReason="Wait for the current request to finish"
                    onClick={() => onReset(index)}
                  >
                    <RotateCcw className="size-4" />
                  </RowActionButton>
                )}
                {!readOnly && onRemove && (
                  <RowActionButton
                    type="button"
                    label={`Remove action ${index + 1}`}
                    tone="destructive"
                    disabled={busy}
                    disabledReason="Wait for the current request to finish"
                    onClick={() => onRemove(index)}
                  >
                    <Trash2 className="size-4" />
                  </RowActionButton>
                )}
              </div>
            </div>
            <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 pl-8 text-xs text-muted-foreground">
              {action.auto_target === "flow_dst_host" && (
                <span className="font-medium text-amber-800 dark:text-amber-300">
                  target resolved from rule flows
                </span>
              )}
              {isPolicyChange && <span><span className="font-medium text-foreground">Peer {String(action.params.neighbor_ip ?? "not selected")}</span> · {action.params.policy_kind === "route_map" ? "Outbound route map" : "Outbound prefix list"}: {String(action.params.policy_name ?? "not selected")}{action.params.policy_kind !== "route_map" ? " · route map preserved" : " · prefix list preserved"}</span>}
              {!isPolicyChange && params.map(([name, value]) => (
                <span key={name} className="break-all">
                  <span className="font-medium text-foreground">{template?.parameter_schema[name]?.label ?? name.replaceAll("_", " ")}</span>: {typeof value === "boolean" ? (value ? "Yes" : "No") : String(value)}
                </span>
              ))}
              {params.length === 0 && !action.auto_target && <span>No parameters saved</span>}
            </div>
            {action.warning && (
              <p className="mt-2 break-words pl-8 text-xs text-amber-800 dark:text-amber-300" role="status">
                {action.warning}
              </p>
            )}
            {selected && renderEditor?.(index)}
          </li>
        );
      })}
    </ol>
  );
}
