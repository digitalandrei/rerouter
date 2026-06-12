import { type HTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// Shadcn-style badge stub. Used for state surfacing the doctrine requires to
// be prominent: telemetry freshness (live/cached/degraded/unknown), reroute
// state machine states, and lock indicators (docs/doctrine.md §5.3, §8).
type Variant = "default" | "secondary" | "destructive" | "outline";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  variant?: Variant;
}

const variantClasses: Record<Variant, string> = {
  default: "border-transparent bg-primary text-primary-foreground",
  secondary: "border-transparent bg-secondary text-secondary-foreground",
  destructive: "border-transparent bg-destructive text-destructive-foreground",
  outline: "text-foreground",
};

export function Badge({
  className,
  variant = "default",
  ...props
}: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold",
        variantClasses[variant],
        className,
      )}
      {...props}
    />
  );
}
