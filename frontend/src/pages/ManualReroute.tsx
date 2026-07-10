/**
 * /mitigations/manual — governed by docs/reroute-engine.md and docs/doctrine.md §8.
 *
 * Enforced server-side and mirrored here:
 *  1. Mitigations only via ALLOWLISTED templates with parameter schemas — no
 *     free-text command box, ever.
 *  2. The EXACT commands are rendered (preview) before submission.
 *  3. In observe mode the controller returns the would-run plan and executes
 *     nothing. "Sent" is never shown as success — the verified state is.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  api,
  type Template,
  type Device,
  type RenderedPlan,
  type RerouteResult,
  ApiError,
} from "@/lib/api";
import { StateBadge, ToneBadge } from "@/components/status-badge";
import { templateLabel, sshStatusBadge } from "@/lib/labels";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { ActionParamsForm } from "@/components/action-params-form";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export default function ManualReroute() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);
  const [templateId, setTemplateId] = useState("");
  const [deviceId, setDeviceId] = useState("");
  const [values, setValues] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<RenderedPlan | null>(null);
  const [previewRollback, setPreviewRollback] = useState<RenderedPlan | null>(null);
  const [previewToken, setPreviewToken] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const [results, setResults] = useState<RerouteResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  // MSS templates are not picked directly from manual reroute — they're only
  // bundled with BGP advertise via the rule action editor.
  const MSS_TEMPLATE_NAMES = ["iface_tcp_adjust_mss", "iface_tcp_adjust_mss_remove"];
  // Host-targeting templates: show helper text about manual prefix bounds.
  const HOST_TARGET_TEMPLATE_NAMES = [
    "null_route_prefix",
    "blackhole_prefix",
    "null_route_prefix_v6",
    "blackhole_prefix_v6",
  ];

  useEffect(() => {
    api.templates
      .list()
      .then((ts) =>
        setTemplates(
          ts.filter(
            (t) =>
              t.provider_type === "device_cli" &&
              t.enabled &&
              !MSS_TEMPLATE_NAMES.includes(t.name),
          ),
        ),
      )
      .catch(() => setTemplates([]));
    api.devices.list().then(setDevices).catch(() => setDevices([]));
  }, []);

  const template = templates.find((t) => String(t.id) === templateId) ?? null;
  const targetDevice = devices.find((d) => String(d.id) === deviceId) ?? null;
  const schema = template?.parameter_schema ?? {};
  const isHostTargetTemplate =
    template !== null && HOST_TARGET_TEMPLATE_NAMES.includes(template.name);

  function reset() {
    setValues({});
    setPreview(null);
    setPreviewRollback(null);
    setPreviewToken(null);
    setResults(null);
    setError(null);
  }

  function buildParams(): Record<string, unknown> {
    const params: Record<string, unknown> = {};
    for (const name of Object.keys(schema)) if (values[name]) params[name] = values[name];
    return params;
  }

  async function doPreview() {
    await submit(true);
  }

  async function submit(dry_run: boolean) {
    if (!template || !deviceId) {
      setError("Pick a template and a router.");
      return;
    }
    setBusy(true);
    setError(null);
    setResults(null);
    try {
      const res = await api.reroutes.manual({
        template_id: template.id,
        targets: [{ device_id: parseInt(deviceId, 10), params: buildParams() }],
        reason: reason.trim() || undefined,
        dry_run,
        preview_token: dry_run ? undefined : previewToken ?? undefined,
      });
      setResults(res.results);
      if (dry_run) {
        const first = res.results[0];
        setPreview(first?.would_run ?? null);
        setPreviewRollback(first?.would_run_rollback ?? null);
        setPreviewToken(res.preview_token ?? null);
        if (!first?.would_run) {
          setError(first?.blocked_reason ?? first?.message ?? "preview failed");
        }
      } else {
        setPreviewToken(null);
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Manual mitigation</h1>
        <Button asChild variant="ghost" size="sm">
          <Link to="/mitigations">Back to history</Link>
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Choose a mitigation</CardTitle>
          <CardDescription>
            Commands come only from validated templates. The exact commands are
            shown before you run anything; in observe mode nothing executes.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2">
            <label className="block space-y-1 text-sm font-medium">
              Template
              <select
                className={inputClass}
                value={templateId}
                onChange={(e) => {
                  setTemplateId(e.target.value);
                  reset();
                }}
              >
                <option value="">Select template…</option>
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>
                    {templateLabel(t)}
                  </option>
                ))}
              </select>
            </label>
            <label className="block space-y-1 text-sm font-medium">
              Router
              <select
                className={inputClass}
                value={deviceId}
                onChange={(e) => {
                  setDeviceId(e.target.value);
                  setValues({});
                  setPreview(null);
                  setPreviewRollback(null);
                  setPreviewToken(null);
                  setResults(null);
                }}
              >
                <option value="">Select router…</option>
                {devices.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.name}
                  </option>
                ))}
              </select>
            </label>
          </div>

          {template && (
            <>
              {template.description && (
                <p className="text-xs text-muted-foreground">{template.description}</p>
              )}

              {isHostTargetTemplate && (
                <p className="text-xs text-muted-foreground">
                  Manual target: a prefix you choose (down to /8 for IPv4, /29 for IPv6).
                  The backend enforces this bound and will reject out-of-range values.
                </p>
              )}

              <ActionParamsForm
                schema={schema}
                deviceId={deviceId ? parseInt(deviceId, 10) : null}
                values={values}
                onChange={(v) => {
                  setValues(v);
                  setPreview(null); // params changed — force a fresh preview before Execute
                  setPreviewRollback(null);
                  setPreviewToken(null);
                  setResults(null);
                }}
              />

              <Button
                size="sm"
                variant="outline"
                disabled={busy || !deviceId}
                onClick={() => void doPreview()}
              >
                {busy ? "Preparing…" : "Preview commands"}
              </Button>

              {preview && (
                <div className="space-y-2">
                  <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Exact commands
                  </div>
                  <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                    {preview.commands.join("\n")}
                  </pre>
                  {preview.verify && (
                    <div className="text-xs text-muted-foreground">
                      Verify: <code>{preview.verify.command}</code>
                    </div>
                  )}
                  <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                    Rollback (to undo by hand)
                  </div>
                  {previewRollback ? (
                    <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                      {previewRollback.commands.join("\n")}
                    </pre>
                  ) : (
                    <p className="text-xs text-muted-foreground">
                      No rollback defined for this template.
                    </p>
                  )}
                </div>
              )}

              <label className="block space-y-1 text-sm font-medium">
                Reason <span className="font-normal text-muted-foreground">(optional, for the audit log)</span>
                <input
                  className={inputClass}
                  value={reason}
                  placeholder="Why is this mitigation being applied?"
                  onChange={(e) => {
                    setReason(e.target.value);
                    setPreview(null);
                    setPreviewRollback(null);
                    setPreviewToken(null);
                    setResults(null);
                  }}
                />
              </label>

              {error && (
                <p className="text-sm text-destructive" role="alert">
                  {error}
                </p>
              )}

              {targetDevice && (
                <div className="space-y-1">
                  <div className="flex flex-wrap items-center gap-2">
                    {(() => {
                      const s = sshStatusBadge(targetDevice.ssh_status);
                      return <ToneBadge tone={s.tone}>SSH: {s.label}</ToneBadge>;
                    })()}
                  </div>
                  {targetDevice.ssh_status === "no_privilege" && (
                    <p className="text-xs text-amber-700 dark:text-amber-400">
                      SSH works but the account can't run every command a reroute needs —
                      either it's not in enable mode (privilege 15), or a parser view denies
                      some. The reroute will be refused. See <em>Command access</em> on the
                      device page for the exact denied commands.
                    </p>
                  )}
                  {targetDevice.ssh_status === "unreachable" && (
                    <p className="text-xs text-amber-700 dark:text-amber-400">
                      Device did not answer SSH at the last probe — the reroute will be
                      refused if SSH does not answer.
                    </p>
                  )}
                  {targetDevice.ssh_status === "reachable" &&
                    !targetDevice.automation_stable && (
                      <p className="text-xs text-amber-700 dark:text-amber-400">
                        Device only recently became reachable — automatic mitigations are
                        held for ~5 min, but you can still proceed with this manual reroute.
                      </p>
                    )}
                </div>
              )}

              <div className="flex gap-2">
                <Button variant="outline" disabled={busy} onClick={() => void submit(true)}>
                  Refresh dry run
                </Button>
                <Button
                  variant="destructive"
                  disabled={busy || !preview}
                  title={!preview ? "Preview the exact commands before executing" : undefined}
                  onClick={() => void submit(false)}
                >
                  Execute
                </Button>
              </div>
              {!preview && (
                <p className="text-xs text-muted-foreground">
                  Preview the commands first — Execute stays disabled until the exact
                  commands are shown.
                </p>
              )}

              {results && (
                <div className="space-y-2">
                  {results.map((r, i) => (
                    <div key={i} className="rounded-md border border-border p-3 text-sm">
                      <div className="flex items-center gap-2">
                        <StateBadge state={r.state ?? (r.executed ? "executed" : "not executed")} />
                        <span className="text-muted-foreground">
                          {r.device_name ?? `device ${r.device_id}`}
                        </span>
                      </div>
                      <p className="mt-1">{r.message}</p>
                      {r.would_run && (
                        <pre className="mt-2 overflow-x-auto rounded-md border border-border bg-muted/40 p-2 text-xs">
                          {r.would_run.commands.join("\n")}
                        </pre>
                      )}
                      {r.reroute_id && (
                        <Link
                          to="/mitigations"
                          className="text-xs text-primary underline-offset-4 hover:underline"
                        >
                          View in history →
                        </Link>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
