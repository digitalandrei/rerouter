/** A tiny (i) icon that reveals an explanatory tooltip on hover/focus. Used for
 *  inline form hints so they don't clutter the layout. Self-contained (carries
 *  its own TooltipProvider) so it works anywhere. */
import { Info } from "lucide-react";
import {
  Tooltip,
  TooltipTrigger,
  TooltipContent,
  TooltipProvider,
} from "@/components/ui/tooltip";

export function InfoHint({ text }: { text: string }) {
  return (
    <TooltipProvider delayDuration={100}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            tabIndex={-1}
            aria-label="More info"
            className="inline-flex align-middle text-muted-foreground hover:text-foreground"
          >
            <Info className="size-3.5" />
          </button>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">{text}</TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
