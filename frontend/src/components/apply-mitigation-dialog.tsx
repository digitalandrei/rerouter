/**
 * ApplyMitigationDialog — modal to manually apply a firing rule's configured
 * mitigation actions.
 *
 * Contract (docs/reroute-engine.md, docs/doctrine.md §8):
 * - In observe mode NOTHING executes. Each result carries would_run (the exact
 *   commands) and executed:false. This must look clearly different from real
 *   execution.
 * - In enforce mode the server runs each action through the full safety gate
 *   (locks, cooldowns, etc). A gate block gives executed:false + blocked_reason.
 * - The UI never hides dangerous reroute details: always show the would-run plan.
 * - No typed-confirmation required (see docs/security.md); safety lives in the
 *   observe-by-default + template-only + server-side gating model.
 */
import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, type Rule, type RerouteResult, ApiError } from "@/lib/api";
import { StateBadge } from "@/components/status-badge";
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

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

/** Renders the resolved auto-target info from a RerouteResult (if present). */
function AutoTargetInfo({ result: r }: { result: RerouteResult }) {
  // Set on rule-apply results for a flow auto-target action (the resolved host).
  if (!r.auto_target) return null;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-1 text-xs">
      <span className="text-muted-foreground">Auto-resolved target:</span>
      <span className="rounded bg-amber-100 px-1 font-mono text-amber-800 dark:bg-amber-900/40 dark:text-amber-300">
        {r.auto_target}
      </span>
      {r.auto_target_low_confidence && (
        <span
          className="rounded bg-red-100 px-1 text-red-700 dark:bg-red-900/40 dark:text-red-400"
          title="Low flow-sampling confidence — automatic execution was blocked; manual apply proceeded"
        >
          low sampling confidence
        </span>
      )}
    </div>
  );
}

/** Renders one result from the apply endpoint. */
function ApplyResultRow({ r }: { r: RerouteResult }) {
  const deviceLabel = r.device_name ?? `device ${r.device_id}`;

  if (!r.executed && r.would_run) {
    // observe mode — nothing ran; show the exact would-run plan
    return (
      <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-950/40">
        <div className="flex flex-wrap items-center gap-2 font-medium text-amber-800 dark:text-amber-300">
          <span>Would run (observe mode — nothing executed)</span>
          <span className="font-normal text-muted-foreground">· {deviceLabel}</span>
        </div>
        <AutoTargetInfo result={r} />
        <p className="mt-1 text-xs text-muted-foreground">{r.message}</p>
        <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
          {r.would_run.commands.join("\n")}
        </pre>
        {r.would_run.verify && (
          <div className="mt-1 text-xs text-muted-foreground">
            Verify: <code>{r.would_run.verify.command}</code>
          </div>
        )}
      </div>
    );
  }

  if (!r.executed && r.blocked_reason) {
    return (
      <div className="rounded-md border border-border p-3 text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <span className="font-medium text-amber-700 dark:text-amber-400">Blocked</span>
          <span className="text-muted-foreground">· {deviceLabel}</span>
        </div>
        <AutoTargetInfo result={r} />
        <p className="mt-1 text-xs text-destructive">{r.blocked_reason}</p>
        {r.message !== r.blocked_reason && (
          <p className="mt-0.5 text-xs text-muted-foreground">{r.message}</p>
        )}
      </div>
    );
  }

  // real execution result
  return (
    <div className="rounded-md border border-border p-3 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <StateBadge state={r.state ?? (r.executed ? "succeeded" : "not executed")} />
        <span className="text-muted-foreground">· {deviceLabel}</span>
      </div>
      <AutoTargetInfo result={r} />
      <p className="mt-1 text-xs text-muted-foreground">{r.message}</p>
      {r.reroute_id && (
        <Link
          to="/mitigations"
          className="mt-1 block text-xs text-primary underline-offset-4 hover:underline"
        >
          View in history →
        </Link>
      )}
    </div>
  );
}

interface ApplyMitigationDialogProps {
  rule: Rule;
  /** Pass the current operating mode so the confirmation copy is accurate. */
  operatingMode?: "observe" | "enforce";
  onClose: () => void;
  /** Called after a successful apply so the caller can refresh data. */
  onApplied?: () => void;
}

/**
 * Two-phase dialog:
 *  1. Confirmation + optional reason entry.
 *  2. Results display after the API call.
 */
export function ApplyMitigationDialog({
  rule,
  operatingMode = "observe",
  onClose,
  onApplied,
}: ApplyMitigationDialogProps) {
  const [phase, setPhase] = useState<"confirm" | "results">("confirm");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<RerouteResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const isObserve = operatingMode === "observe";

  async function apply() {
    setBusy(true);
    setError(null);
    try {
      const res = await api.rules.apply(rule.id, {
        reason: reason.trim() || undefined,
      });
      setResults(res.results);
      setPhase("results");
      onApplied?.();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Request failed");
    } finally {
      setBusy(false);
    }
  }

  let body: ReactNode;

  if (phase === "confirm") {
    body = (
      <>
        <DialogHeader>
          <DialogTitle>Apply mitigation — {rule.name}</DialogTitle>
          <DialogDescription asChild>
            <div className="space-y-2 text-sm text-muted-foreground">
              <p>
                This will run all enabled actions configured for this rule as a manual
                reroute, re-checking every safety gate (locks, cooldowns, device state).
              </p>
              {isObserve ? (
                <p className="font-medium text-amber-700 dark:text-amber-400">
                  The controller is in <strong>observe mode</strong>: nothing will
                  execute. You will see the exact commands that would run.
                </p>
              ) : (
                <p className="font-medium text-destructive">
                  The controller is in <strong>enforce mode</strong>: this will push
                  real configuration to the device(s).
                </p>
              )}
            </div>
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-2">
          <label className="block space-y-1 text-sm font-medium">
            Reason{" "}
            <span className="font-normal text-muted-foreground">
              (optional, recorded in the audit log)
            </span>
            <Input
              className={inputClass}
              value={reason}
              placeholder="Why are you applying this mitigation?"
              onChange={(e) => setReason(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !busy) void apply();
              }}
            />
          </label>
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant={isObserve ? "outline" : "destructive"}
            disabled={busy}
            onClick={() => void apply()}
          >
            {busy
              ? "Applying…"
              : isObserve
                ? "Preview plan (observe mode)"
                : "Apply mitigation"}
          </Button>
        </DialogFooter>
      </>
    );
  } else {
    // results phase
    const allObserve = results?.every((r) => !r.executed && r.would_run) ?? false;
    const anyFailed = results?.some(
      (r) => r.executed && (r.state === "failed" || r.state === "uncertain"),
    ) ?? false;
    const anyBlocked = results?.some((r) => !r.executed && r.blocked_reason) ?? false;

    let summaryText: ReactNode;
    if (allObserve) {
      summaryText = (
        <span className="text-amber-700 dark:text-amber-400">
          Observe mode — no commands were sent. Plan shown below.
        </span>
      );
    } else if (anyFailed) {
      summaryText = (
        <span className="text-destructive">
          One or more actions failed or ended in an uncertain state. Check history.
        </span>
      );
    } else if (anyBlocked) {
      summaryText = (
        <span className="text-amber-700 dark:text-amber-400">
          One or more actions were blocked by a safety gate.
        </span>
      );
    } else {
      summaryText = (
        <span className="text-emerald-700 dark:text-emerald-400">Applied successfully.</span>
      );
    }

    body = (
      <>
        <DialogHeader>
          <DialogTitle>Mitigation results — {rule.name}</DialogTitle>
          <DialogDescription asChild>
            <div className="text-sm">{summaryText}</div>
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-3 overflow-y-auto">
          {(results ?? []).map((r, i) => (
            <ApplyResultRow key={i} r={r} />
          ))}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </DialogFooter>
      </>
    );
  }

  return (
    <Dialog open onOpenChange={(v) => !v && !busy && onClose()}>
      <DialogContent className="sm:max-w-lg">
        {body}
      </DialogContent>
    </Dialog>
  );
}
