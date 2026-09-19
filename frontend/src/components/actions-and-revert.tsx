import { useEffect, useRef, useState } from "react";
import { Eye, RefreshCw, TriangleAlert } from "lucide-react";
import { api, ApiError, type ActionDraft, type ActionSetInspection } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export function ActionsAndRevert({ actions, deviceNames = {} }: { actions: ActionDraft[]; deviceNames?: Record<number, string> }) {
  const [inspection, setInspection] = useState<ActionSetInspection | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const generation = useRef(0);
  const fingerprint = JSON.stringify(actions);

  useEffect(() => { generation.current += 1; setInspection(null); setError(null); setBusy(false); }, [fingerprint]);

  async function inspect() {
    const requestGeneration = ++generation.current;
    setBusy(true); setError(null);
    try { const value = await api.actionSets.inspect(actions); if (requestGeneration === generation.current) setInspection(value); }
    catch (cause) { if (requestGeneration === generation.current) { setInspection(null); setError(cause instanceof ApiError ? cause.message : "Inspection is unavailable"); } }
    finally { if (requestGeneration === generation.current) setBusy(false); }
  }

  return <Card>
    <CardHeader className="flex-row items-start justify-between gap-3">
      <div><CardTitle className="text-base">Actions and revert</CardTitle><CardDescription>Inspect current configuration and project the complete ordered set. This read-only inspection never executes or authorizes a change.</CardDescription></div>
      <Button type="button" size="sm" variant="outline" onClick={() => void inspect()} disabled={busy || actions.length === 0}>{busy ? <RefreshCw className="size-4 animate-spin" /> : <Eye className="size-4" />} Inspect</Button>
    </CardHeader>
    <CardContent className="space-y-4">
      {!inspection && !error && <p className="text-sm text-muted-foreground">No inspection runs when this page opens. Select Inspect to read current configuration and prepare a read-only projection.</p>}
      {error && <div role="alert" className="flex items-start gap-2 rounded-md border border-amber-400 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100"><TriangleAlert className="mt-0.5 size-4 shrink-0" /><div><strong>Needs setup or fresh evidence</strong><p className="mt-1 break-words">{error}</p></div></div>}
      {inspection?.devices.map((device) => <section key={device.device_id} className="space-y-3 rounded-md border p-3">
        <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-medium">{deviceNames[device.device_id] ?? `Router ${device.device_id}`}</h3><span className="text-xs text-muted-foreground">Evidence {new Date(device.read_at).toLocaleString()}</span></div>
        {device.blockers.length > 0 && <p className="text-sm text-destructive">{device.blockers.join(" · ")}</p>}
        <div className="grid gap-3 xl:grid-cols-3">
          <Evidence label="Before" value={device.before_config} />
          <Evidence label="After all actions" value={device.after_config} />
          <Evidence label="After revert" value={device.revert_config} />
        </div>
        <div><h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Actions in order</h4><ul className="mt-1 space-y-1 text-sm">{device.changes.map((change) => <li key={`${change.action_index}-${change.template_name}`}>Action {change.action_index + 1}: {humanLabel(change.template_name)} — {change.effect === "already_satisfied" ? "already satisfied; no inverse owned" : "change with prepared inverse"}</li>)}</ul></div>
        <div className="grid gap-3 xl:grid-cols-2"><ConfigDiff label="Before → after all actions" before={device.before_config} after={device.after_config} /><ConfigDiff label="After all actions → after revert" before={device.after_config} after={device.revert_config} /></div>
        <details><summary className="cursor-pointer text-sm font-medium">Exact commands and verification evidence</summary><pre className="mt-2 max-h-96 overflow-auto rounded-md bg-muted p-3 text-xs">{JSON.stringify(inspection.prepared_actions.filter((action) => action.device_id === device.device_id), null, 2)}</pre></details>
      </section>)}
    </CardContent>
  </Card>;
}

function Evidence({ label, value }: { label: string; value: unknown }) {
  return <div className="min-w-0"><h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</h4><pre className="mt-1 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{configText(value)}</pre></div>;
}

function configText(value: unknown): string { return typeof value === "string" ? value : JSON.stringify(value, null, 2); }
function humanLabel(value: string): string { return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase()); }
function diffText(before: unknown, after: unknown): string {
  const left = configText(before).split("\n"); const right = configText(after).split("\n");
  const lengths = Array.from({ length: left.length + 1 }, () => Array<number>(right.length + 1).fill(0));
  for (let i = left.length - 1; i >= 0; i -= 1) for (let j = right.length - 1; j >= 0; j -= 1) lengths[i][j] = left[i] === right[j] ? lengths[i + 1][j + 1] + 1 : Math.max(lengths[i + 1][j], lengths[i][j + 1]);
  const output: string[] = []; let i = 0; let j = 0;
  while (i < left.length || j < right.length) {
    if (i < left.length && j < right.length && left[i] === right[j]) { output.push(`  ${left[i]}`); i += 1; j += 1; }
    else if (j < right.length && (i === left.length || lengths[i][j + 1] >= lengths[i + 1][j])) { output.push(`+ ${right[j]}`); j += 1; }
    else { output.push(`- ${left[i]}`); i += 1; }
  }
  return output.every((line) => line.startsWith("  ")) ? "  No configuration difference" : output.join("\n");
}
function ConfigDiff({ label, before, after }: { label: string; before: unknown; after: unknown }) { return <div><h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{label}</h4><pre className="mt-1 max-h-72 overflow-auto rounded-md bg-muted p-3 text-xs">{diffText(before, after)}</pre></div>; }
