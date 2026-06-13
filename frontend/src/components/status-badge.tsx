/**
 * Single source of truth for status/severity/state colouring across the app.
 * Everything maps a domain value to a `Tone`, and a Tone to one class string.
 * Use the exported badges (StatusBadge / SeverityBadge / StateBadge / ToneBadge)
 * instead of re-deriving colours anywhere — keep colours unified here.
 */
import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";

export type Tone = "good" | "bad" | "warn" | "info" | "neutral";

const TONE_CLASS: Record<Tone, string> = {
  good: "border-transparent bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300",
  bad: "border-transparent bg-red-100 text-red-700 dark:bg-red-950/60 dark:text-red-300",
  warn: "border-transparent bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300",
  info: "border-transparent bg-sky-100 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300",
  neutral: "",
};

export function toneClass(tone: Tone): string {
  return TONE_CLASS[tone];
}

/** A badge of an explicit tone (e.g. a generic "configured"/"reachable" pill). */
export function ToneBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <Badge variant="outline" className={toneClass(tone)}>
      {children}
    </Badge>
  );
}

// ---- operational status: up / established / reachable vs down / idle / … -------

const STATUS_GOOD = new Set(["established", "up", "reachable", "start", "ok", "configured"]);
const STATUS_BAD = new Set([
  "down",
  "unreachable",
  "idle",
  "active",
  "connect",
  "opensent",
  "openconfirm",
  "stop",
  "shutdown",
  "shut",
  "notconnect",
  "lowerlayerdown",
]);

export function statusTone(value?: string | null): Tone {
  if (!value) return "neutral";
  const s = value.toLowerCase();
  if (STATUS_GOOD.has(s)) return "good";
  if (STATUS_BAD.has(s)) return "bad";
  return "neutral";
}

/** Badge coloured by the semantics of `value`. `label` overrides the shown text
 *  (e.g. admin "stop" -> "shutdown") while colour keys off `value`. */
export function StatusBadge({ value, label }: { value?: string | null; label?: string }) {
  return <ToneBadge tone={statusTone(value)}>{label ?? value ?? "?"}</ToneBadge>;
}

// ---- alert/rule severity ------------------------------------------------------

export function severityTone(severity?: string | null): Tone {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
      return "bad";
    case "warning":
      return "warn";
    case "info":
      return "info";
    default:
      return "neutral";
  }
}

export function SeverityBadge({ severity }: { severity: string }) {
  return <ToneBadge tone={severityTone(severity)}>{severity}</ToneBadge>;
}

// ---- reroute / mitigation state ----------------------------------------------

export function stateTone(state?: string | null): Tone {
  switch ((state ?? "").toLowerCase()) {
    case "succeeded":
      return "good";
    case "failed":
    case "uncertain":
      return "bad";
    case "planned":
    case "pending":
    case "running":
    case "verifying":
      return "info";
    default:
      return "neutral";
  }
}

export function StateBadge({ state }: { state: string }) {
  return <ToneBadge tone={stateTone(state)}>{state}</ToneBadge>;
}
