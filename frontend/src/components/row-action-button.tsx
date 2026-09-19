import * as React from "react";

import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";

type RowActionButtonProps = Omit<React.ComponentProps<typeof Button>, "size" | "variant"> & {
  label: string;
  disabledReason?: string;
  tone?: "default" | "destructive";
};

/**
 * A compact, visible action for dense rows and tables.
 *
 * The control keeps a 40px touch target at every breakpoint and explains
 * itself on hover or keyboard focus. Disabled buttons use a focusable wrapper
 * so the reason remains discoverable instead of disappearing with the action.
 */
export function RowActionButton({
  label,
  disabledReason,
  tone = "default",
  className,
  disabled,
  asChild,
  onClick,
  tabIndex,
  type,
  children,
  ...props
}: RowActionButtonProps) {
  const disabledExplanation = disabledReason ?? "This action is currently unavailable";
  const tooltip = disabled ? `${label}: ${disabledExplanation}` : label;
  const button = (
    <Button
      size="icon"
      variant="outline"
      aria-label={label}
      type={asChild ? undefined : (type ?? "button")}
      aria-disabled={asChild && disabled ? true : undefined}
      disabled={asChild ? undefined : disabled}
      tabIndex={asChild && disabled ? -1 : tabIndex}
      asChild={asChild}
      onClick={(event) => {
        if (disabled) {
          event.preventDefault();
          event.stopPropagation();
          return;
        }
        onClick?.(event);
      }}
      className={cn(
        "size-10 cursor-pointer bg-background shadow-xs hover:border-foreground/25 hover:bg-accent sm:size-10",
        disabled && "cursor-not-allowed",
        tone === "destructive" &&
          "border-destructive/30 text-destructive hover:border-destructive/60 hover:bg-destructive/10 hover:text-destructive",
        className,
      )}
      {...props}
    >
      {children}
    </Button>
  );

  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        {disabled ? (
          <TooltipTrigger asChild>
            <span
              className="inline-flex size-10 rounded-md outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
              tabIndex={0}
              aria-label={tooltip}
            >
              {button}
            </span>
          </TooltipTrigger>
        ) : (
          <TooltipTrigger asChild>{button}</TooltipTrigger>
        )}
        <TooltipContent className="max-w-72 whitespace-normal" sideOffset={6}>{tooltip}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

export const ActionIconButton = RowActionButton;
