/**
 * Reusable single-input modal. Replaces every browser prompt() in the app
 * (e.g. setting a BGP-neighbor label, an acknowledgement note). `onSubmit` may
 * be async; the caller closes the dialog (via onOpenChange) on success.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

const textareaClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function PromptDialog({
  open,
  onOpenChange,
  title,
  description,
  label,
  defaultValue = "",
  placeholder,
  multiline = false,
  submitLabel = "Save",
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  description?: ReactNode;
  label?: ReactNode;
  defaultValue?: string;
  placeholder?: string;
  multiline?: boolean;
  submitLabel?: string;
  onSubmit: (value: string) => void | Promise<void>;
}) {
  const [value, setValue] = useState(defaultValue);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setValue(defaultValue);
      setBusy(false);
    }
  }, [open, defaultValue]);

  async function go() {
    setBusy(true);
    try {
      await onSubmit(value);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => !busy && onOpenChange(v)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {description && <DialogDescription>{description}</DialogDescription>}
        </DialogHeader>
        <label className="block space-y-1 text-sm font-medium">
          {label}
          {multiline ? (
            <textarea
              className={textareaClass}
              rows={3}
              value={value}
              placeholder={placeholder}
              autoFocus
              onChange={(e) => setValue(e.target.value)}
            />
          ) : (
            <Input
              value={value}
              placeholder={placeholder}
              autoFocus
              onChange={(e) => setValue(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !busy) void go();
              }}
            />
          )}
        </label>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={busy}>
            Cancel
          </Button>
          <Button onClick={() => void go()} disabled={busy}>
            {busy ? "Working…" : submitLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
