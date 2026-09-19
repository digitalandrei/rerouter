/**
 * ApplyMitigationDialog — modal to manually apply a firing rule's configured
 * mitigation actions.
 *
 * Contract (docs/reroute-engine.md, docs/doctrine.md §8, plans/015):
 * - Observe disables automatic response. An authorized operator may still
 *   execute this exact manual preview after explicit confirmation.
 * - In enforce mode the server runs each action through the full safety gate
 *   (locks, cooldowns, etc). A gate block gives executed:false + blocked_reason.
 * - The UI never hides dangerous reroute details: always show the would-run plan.
 * - Execution consumes the server-issued one-use token for the exact preview.
 *   The three steps (reason -> exact preview -> execute) are a doctrine gate and
 *   are never collapsed.
 * - A confirmed manual apply answers 202 with a bundle id and runs in the
 *   background (a real mitigation is a dozen-plus SSH sessions). The dialog then
 *   polls GET /api/reroute-bundles/{id} and shows per-action progress until a
 *   terminal state. If the bundle ends with siblings STILL APPLIED, that is
 *   shown as a critical, unmissable block: traffic is still diverted.
 */
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import {
  api,
  asBundleNotAdmitted,
  isBundleAccepted,
  isBundleTerminal,
  type RerouteBundle,
  type Rule,
  type RerouteResult,
  ApiError,
} from "@/lib/api";
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
          title="Low flow-sampling confidence blocks automatic execution"
        >
          low sampling confidence
        </span>
      )}
    </div>
  );
}

/** Renders one result from the apply endpoint. */
export function ApplyResultRow({ r }: { r: RerouteResult }) {
  const deviceLabel = r.device_name ?? `device ${r.device_id}`;

  if (!r.executed && r.would_run) {
    // Preview/observe response — nothing ran; show the exact would-run plan.
    return (
      <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-700 dark:bg-amber-950/40">
        <div className="flex flex-wrap items-center gap-2 font-medium text-amber-800 dark:text-amber-300">
          <span>Would run — preview only, nothing executed</span>
          <span className="font-normal text-muted-foreground">· {deviceLabel}</span>
        </div>
        <AutoTargetInfo result={r} />
        {(r.predicted_noop || r.mutation_effect === "noop") && (
          <p className="mt-1 text-xs font-medium text-emerald-800 dark:text-emerald-300">
            Verified unchanged target — no configuration command is required.
          </p>
        )}
        <p className="mt-1 text-xs text-muted-foreground">{r.message}</p>
        <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
          {r.would_run.commands.join("\n")}
        </pre>
        {r.would_run.verify && (
          <div className="mt-1 text-xs text-muted-foreground">
            Verify: <code>{r.would_run.verify.command}</code>
          </div>
        )}
        {r.verification_states && r.verification_states.length > 0 && (
          <div className="mt-2 space-y-1">
            <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Required read-back state
            </div>
            <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
              {JSON.stringify(r.verification_states, null, 2)}
            </pre>
          </div>
        )}
        {(r.before_state != null || r.after_state != null) && (
          <details className="mt-2 text-xs">
            <summary className="cursor-pointer font-medium text-muted-foreground">Observed and intended state</summary>
            <pre className="mt-1 overflow-x-auto rounded-md border border-border bg-muted/40 p-2">
              {JSON.stringify({ before: r.before_state, after: r.after_state }, null, 2)}
            </pre>
          </details>
        )}
        <div className="mt-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">
          Prepared rollback
        </div>
        {r.would_run_rollback ? (
          <pre className="mt-1 overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
            {r.would_run_rollback.commands.join("\n")}
          </pre>
        ) : (
          <p className="mt-1 text-xs text-muted-foreground">
            {r.predicted_noop || r.mutation_effect === "noop"
              ? "No rollback needed: this action makes no configuration change."
              : "No verified inverse is available for this action."}
          </p>
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
        {r.mutation_effect === "noop" && (
          <span className="text-xs font-medium text-muted-foreground">already satisfied · no change sent</span>
        )}
        {r.mutation_effect === "unknown" && (
          <span className="text-xs font-medium text-amber-800 dark:text-amber-300">change unknown</span>
        )}
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

/** Human label for a bundle state. */
const BUNDLE_STATE_LABEL: Record<string, string> = {
  planned: "Planned",
  running: "Running",
  succeeded: "All actions succeeded",
  aborted: "Aborted — applied siblings left in place",
  compensating: "Rolling back already-applied siblings…",
  compensated: "Aborted and rolled back — nothing left applied",
  compensation_blocked: "Rollback BLOCKED — siblings still applied",
  failed: "Failed",
};

/**
 * Live per-action progress of one ordered mitigation bundle.
 *
 * The critical case is a terminal state with still_applied_reroute_ids: the
 * bundle stopped part-way and could not undo what it had already pushed, so
 * traffic is diverted right now and only a human can put it back. That block is
 * deliberately loud — the difference between an operator who knows and one who
 * does not.
 */
export function BundleProgressView({
  bundle,
  bundleId,
  totalHint,
  pollError,
}: {
  bundle: RerouteBundle | null;
  bundleId: number;
  totalHint: number;
  pollError: string | null;
}) {
  const total = bundle?.total_actions ?? totalHint;
  const done = bundle?.completed_actions ?? 0;
  const pct = total > 0 ? Math.min(100, Math.round((done / total) * 100)) : 0;
  const state = bundle?.state ?? "planned";
  const terminal = isBundleTerminal(state);
  const stillApplied = bundle?.still_applied_reroute_ids ?? [];
  const bad =
    state === "compensation_blocked" || state === "aborted" || state === "failed";

  return (
    <div className="space-y-3">
      <div className="rounded-md border border-border p-3">
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <StateBadge state={state} />
          <span className="font-medium">
            {BUNDLE_STATE_LABEL[state] ?? state}
          </span>
          <span className="flex-1" />
          <span className="text-xs text-muted-foreground">
            bundle #{bundleId} · {done}/{total} action{total === 1 ? "" : "s"}
          </span>
        </div>
        <div
          className="mt-2 h-2 w-full overflow-hidden rounded-full bg-muted"
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={total}
          aria-valuenow={done}
        >
          <div
            className={`h-full transition-all ${bad ? "bg-destructive" : terminal ? "bg-emerald-600" : "bg-primary"}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        {bundle?.failure_reason && (
          <p className="mt-2 text-xs text-destructive">{bundle.failure_reason}</p>
        )}
        {!terminal && (
          <p className="mt-2 text-xs text-muted-foreground">
            Running on the controller — closing this dialog does not stop it.
            Failure policy: <code>{bundle?.failure_policy ?? "abort_and_compensate"}</code>.
          </p>
        )}
      </div>

      {/* CRITICAL: what is still pushed to the routers right now. */}
      {terminal && stillApplied.length > 0 && (
        <div className="rounded-md border-2 border-destructive bg-destructive/10 p-3">
          <div className="text-sm font-semibold text-destructive">
            {stillApplied.length} action{stillApplied.length === 1 ? " is" : "s are"} STILL
            APPLIED on the routers
          </div>
          <p className="mt-1 text-xs text-destructive">
            {state === "compensation_blocked"
              ? "Automatic rollback was blocked (a device is locked pending admin acknowledgement of an uncertain reroute). Doctrine forbids acting through that lock."
              : "This bundle aborted and its failure policy left applied siblings in place."}{" "}
            Traffic is diverted until each of these is rolled back by hand.
          </p>
          <ul className="mt-2 space-y-1">
            {stillApplied.map((rid) => {
              const a = bundle?.actions.find((x) => x.reroute_id === rid);
              return (
                <li key={rid} className="text-xs">
                  <Link
                    to={`/mitigations?tab=history&reroute=${rid}`}
                    className="font-medium text-destructive underline underline-offset-4"
                  >
                    reroute #{rid}
                  </Link>
                  {a && (
                    <span className="text-muted-foreground">
                      {" "}
                      · {a.template_display_name ?? "action"} on{" "}
                      {a.device_name ?? `device ${a.device_id}`}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}

      {/* Per-action detail, in execution order. */}
      <div className="space-y-1.5">
        {(bundle?.actions ?? []).map((a) => (
          <div
            key={`${a.position ?? "queued"}-${a.reroute_id ?? "not-run"}`}
            className="flex flex-wrap items-center gap-2 rounded-md border border-border px-3 py-2 text-sm"
          >
            <span className="w-6 shrink-0 text-xs text-muted-foreground">
              #{(a.position ?? 0) + 1}
            </span>
            <StateBadge state={a.state} />
            <span className="font-medium">{a.template_display_name ?? "action"}</span>
            <span className="text-muted-foreground">on</span>
            <span className="font-medium">{a.device_name ?? `device ${a.device_id}`}</span>
            <span className="flex-1" />
            {a.reroute_id != null ? (
              <Link
                to={`/mitigations?tab=history&reroute=${a.reroute_id}`}
                className="text-xs text-primary underline-offset-4 hover:underline"
              >
                #{a.reroute_id}
              </Link>
            ) : (
              <span className="text-xs text-muted-foreground">not attempted</span>
            )}
            {a.failure_reason && (
              <p className="w-full text-xs text-destructive">{a.failure_reason}</p>
            )}
            {a.params && Object.keys(a.params).length > 0 && (
              <p className="w-full break-all pl-8 text-xs text-muted-foreground">
                {Object.entries(a.params).map(([key, value]) => `${key}=${String(value)}`).join(", ")}
              </p>
            )}
          </div>
        ))}
        {bundle && bundle.actions.length === 0 && (
          <p className="text-sm text-muted-foreground">
            No action has started yet.
          </p>
        )}
        {!bundle && (
          <p className="text-sm text-muted-foreground">Reading bundle progress…</p>
        )}
      </div>

      {pollError && (
        <p className="text-xs text-amber-700 dark:text-amber-400" role="alert">
          Could not read progress ({pollError}) — retrying. The bundle keeps
          running on the controller.
        </p>
      )}
    </div>
  );
}

interface ApplyMitigationDialogProps {
  rule: Rule;
  /** Pass the current operating mode so the confirmation copy is accurate. */
  operatingMode?: "observe" | "enforce" | "unknown";
  onClose: () => void;
  /** Called after a successful apply so the caller can refresh data. */
  onApplied?: () => void;
}

/**
 * Phases: reason -> exact dry-run preview -> execution. The execution phase is
 * either synchronous preview results or live bundle progress after confirmation.
 */
export function ApplyMitigationDialog({
  rule,
  operatingMode = "unknown",
  onClose,
  onApplied,
}: ApplyMitigationDialogProps) {
  const [phase, setPhase] = useState<"confirm" | "preview" | "results" | "progress">(
    "confirm",
  );
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<RerouteResult[] | null>(null);
  const [previewToken, setPreviewToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Async bundle execution (enforce mode): handle + polled progress.
  const [bundleId, setBundleId] = useState<number | null>(null);
  const [bundleTotal, setBundleTotal] = useState(0);
  const [bundle, setBundle] = useState<RerouteBundle | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);

  const isObserve = operatingMode === "observe";
  const isUnknown = operatingMode === "unknown";
  const bundleRunning =
    phase === "progress" && (bundle === null || !isBundleTerminal(bundle.state));

  // Poll the bundle every 2s until it reaches a terminal state. A read failure
  // never ends the poll: the run continues server-side and the operator must be
  // able to see how it ended.
  useEffect(() => {
    if (bundleId === null) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    async function tick() {
      if (cancelled || bundleId === null) return;
      try {
        const b = await api.bundles.get(bundleId);
        if (cancelled) return;
        setBundle(b);
        setPollError(null);
        if (isBundleTerminal(b.state)) return;
      } catch (e) {
        if (cancelled) return;
        setPollError(e instanceof ApiError ? e.message : "read failed");
      }
      timer = setTimeout(() => void tick(), 2000);
    }

    void tick();
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [bundleId]);

  async function apply(dryRun: boolean) {
    setBusy(true);
    setError(null);
    try {
      const res = await api.rules.apply(rule.id, {
        reason: reason.trim() || undefined,
        dry_run: dryRun,
        preview_token: dryRun ? undefined : previewToken ?? undefined,
      });
      // Confirmed manual apply: 202 + bundle handle, work continues
      // server-side. `results` here carries only the actions that could not be
      // resolved to run at all.
      if (isBundleAccepted(res)) {
        setPreviewToken(null);
        setResults(res.results ?? []);
        setBundleTotal(res.total_actions);
        setBundle(null);
        setBundleId(res.bundle_id);
        setPhase("progress");
        return;
      }
      setResults(res.results);
      if (dryRun && res.preview_token) {
        setPreviewToken(res.preview_token);
        setPhase("preview");
      } else {
        setPreviewToken(null);
        setPhase("results");
        if (!dryRun) onApplied?.();
      }
    } catch (e) {
      // All-or-nothing admission: the bundle did not fit the remaining global
      // rate budget, so NOTHING ran. The one-use preview token was already
      // consumed, so the operator has to take a fresh preview.
      const refused = e instanceof ApiError ? asBundleNotAdmitted(e.body) : null;
      if (refused) {
        setPreviewToken(null);
        setResults(null);
        setPhase("confirm");
        setError(
          `Bundle #${refused.bundle_id} was refused as a whole: ${refused.detail} ` +
            `None of its ${refused.total_actions} actions executed — the global ` +
            `action rate budget cannot fit this bundle. Nothing changed on any router. ` +
            `Preview again to retry (the previous one-use preview token is spent).`,
        );
      } else {
        setError(e instanceof ApiError ? e.message : "Request failed");
      }
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
                  The controller is in <strong>observe mode</strong>: automatic response
                  is disabled. This manual run still requires an exact preview and confirmation.
                </p>
              ) : isUnknown ? (
                <p className="font-medium text-amber-800 dark:text-amber-300">
                  The current operating mode could not be confirmed. The server will
                  enforce the preview token and all execution gates.
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
                if (e.key === "Enter" && !busy) void apply(true);
              }}
            />
          </label>
          {error && (
            <div
              className="rounded-md border border-destructive bg-destructive/10 p-3 text-sm text-destructive"
              role="alert"
            >
              {error}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => void apply(true)}
          >
            {busy ? "Preparing…" : "Preview exact commands"}
          </Button>
        </DialogFooter>
      </>
    );
  } else if (phase === "preview") {
    body = (
      <>
        <DialogHeader>
          <DialogTitle>Review commands — {rule.name}</DialogTitle>
          <DialogDescription>
            These are the exact commands and verification reads prepared by the controller.
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-[60vh] space-y-3 overflow-y-auto">
          {(results ?? []).map((r, i) => (
            <ApplyResultRow key={i} r={r} />
          ))}
          {error && (
            <p className="text-sm text-destructive" role="alert">
              {error}
            </p>
          )}
        </div>
        <DialogFooter>
          <Button
            variant="outline"
            disabled={busy}
            onClick={() => {
              setPreviewToken(null);
              setResults(null);
              setPhase("confirm");
            }}
          >
            Back
          </Button>
          <Button variant="destructive" disabled={busy || !previewToken} onClick={() => void apply(false)}>
            {busy ? "Applying…" : "Execute reviewed actions"}
          </Button>
        </DialogFooter>
      </>
    );
  } else if (phase === "progress") {
    const terminal = bundle !== null && isBundleTerminal(bundle.state);
    body = (
      <>
        <DialogHeader>
          <DialogTitle>
            {terminal ? "Mitigation bundle finished" : "Applying mitigation"} — {rule.name}
          </DialogTitle>
          <DialogDescription>
            The reviewed actions run in order on the controller. This view updates
            every 2 seconds from the server, not from this browser's guesswork.
          </DialogDescription>
        </DialogHeader>

        <div className="max-h-[60vh] space-y-3 overflow-y-auto">
          <BundleProgressView
            bundle={bundle}
            bundleId={bundleId ?? 0}
            totalHint={bundleTotal}
            pollError={pollError}
          />
          {/* Actions that never entered the bundle (blocked before admission). */}
          {(results ?? []).length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                Not included in the bundle
              </div>
              {(results ?? []).map((r, i) => (
                <ApplyResultRow key={i} r={r} />
              ))}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              onApplied?.();
              onClose();
            }}
          >
            {terminal ? "Close" : "Leave running in background"}
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
    const anySkipped = results?.some((r) => !r.executed && !r.would_run) ?? false;

    let summaryText: ReactNode;
    if (allObserve) {
      summaryText = (
        <span className="text-amber-700 dark:text-amber-400">
          Preview response — no commands were sent by this request. The plan is shown below.
        </span>
      );
    } else if (anyFailed) {
      summaryText = (
        <span className="text-destructive">
          One or more actions failed or ended in an uncertain state. Check history.
        </span>
      );
    } else if (anyBlocked || anySkipped) {
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
    <Dialog
      open
      // While a bundle is mid-flight an accidental outside-click must not hide
      // the only live view of what is being pushed to the routers. The explicit
      // footer button is always available.
      onOpenChange={(v) => !v && !busy && !bundleRunning && onClose()}
    >
      <DialogContent className={phase === "progress" ? "sm:max-w-2xl" : "sm:max-w-lg"}>
        {body}
      </DialogContent>
    </Dialog>
  );
}
