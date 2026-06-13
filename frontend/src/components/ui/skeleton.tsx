// Copyright (c) 2024-2026 Cloud Craft SRL. All rights reserved.
// Licensed under the Proprietary License. See LICENSE file in the project root.

import { cn } from "@/lib/utils"

function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      className={cn("animate-pulse rounded-md bg-accent", className)}
      {...props}
    />
  )
}

export { Skeleton }
