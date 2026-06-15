// Copyright (c) 2024-2026 Cloud Craft SRL. All rights reserved.
// Licensed under the Proprietary License. See LICENSE file in the project root.

import * as React from "react";
import { Switch as SwitchPrimitive } from "radix-ui";
import { Check, X } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * On/off switch for operational enable/disable state (e.g. a rule or device).
 * Green track + check when on, red track + cross when off, with a sliding knob
 * — the shared control for every "is this normally-on thing enabled?" toggle.
 *
 * NOTE: green = on is the right signal only when *enabling is the safe/normal*
 * state. Do NOT use this for safety switches where turning the thing ON is the
 * dangerous act (operating mode, the global automatic-reroute enable, the
 * maintenance lock, per-rule auto-reroute) — those keep their deliberate,
 * destructive-styled controls so "on" never looks reassuringly green.
 */
function Switch({
  className,
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root>) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      className={cn(
        "group relative inline-flex h-7 w-[3.25rem] shrink-0 cursor-pointer items-center rounded-full outline-none transition-colors",
        "shadow-sm ring-1 ring-inset ring-black/10 dark:ring-white/15",
        "focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background",
        "disabled:cursor-not-allowed disabled:opacity-50",
        "data-[state=checked]:bg-green-500 data-[state=unchecked]:bg-red-500",
        className,
      )}
      {...props}
    >
      {/* Icon sits on the side the knob is NOT on: check (left) when on, X (right) when off. */}
      <Check
        aria-hidden
        strokeWidth={3}
        className="pointer-events-none absolute left-[7px] top-1/2 size-3.5 -translate-y-1/2 text-white opacity-0 transition-opacity group-data-[state=checked]:opacity-100"
      />
      <X
        aria-hidden
        strokeWidth={3}
        className="pointer-events-none absolute right-[7px] top-1/2 size-3.5 -translate-y-1/2 text-white opacity-0 transition-opacity group-data-[state=unchecked]:opacity-100"
      />
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "pointer-events-none block size-6 rounded-full bg-white shadow-md ring-0 transition-transform",
          "translate-x-0.5 data-[state=checked]:translate-x-[1.625rem]",
        )}
      />
    </SwitchPrimitive.Root>
  );
}

export { Switch };
