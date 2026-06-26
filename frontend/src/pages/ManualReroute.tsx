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
import { StateBadge } from "@/components/status-badge";
import { templateLabel } from "@/lib/labels";
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
  const [reason, setReason] = useState("");
  const [results, setResults] = useState<RerouteResult[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.templates
      .list()
      .then((ts) => setTemplates(ts.filter((t) => t.provider_type === "device_cli" && t.enabled)))
      .catch(() => setTemplates([]));
    api.devices.list().then(setDevices).catch(() => setDevices([]));
  }, []);

  const template = templates.find((t) => String(t.id) === templateId) ?? null;
  const schema = template?.parameter_schema ?? {};

  function reset() {
    setValues({});
    setPreview(null);
    setResults(null);
    setError(null);
  }

  function buildParams(): Record<string, unknown> {
    const params: Record<string, unknown> = {};
    for (const name of Object.keys(schema)) if (values[name]) params[name] = values[name];
    return params;
  }

  async function doPreview() {
    if (!template) return;
    setError(null);
    setPreview(null);
    try {
      const r = await api.templates.render(template.id, buildParams());
      if (r.ok && r.plan) setPreview(r.plan);
      else setError(r.error ?? "render failed");
    } catch {
      setError("render request failed");
    }
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
      });
      setResults(res.results);
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

              <ActionParamsForm
                schema={schema}
                deviceId={deviceId ? parseInt(deviceId, 10) : null}
                values={values}
                onChange={setValues}
              />

              <Button size="sm" variant="outline" onClick={() => void doPreview()}>
                Preview commands
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
                </div>
              )}

              <label className="block space-y-1 text-sm font-medium">
                Reason <span className="font-normal text-muted-foreground">(optional, for the audit log)</span>
                <input
                  className={inputClass}
                  value={reason}
                  placeholder="Why is this mitigation being applied?"
                  onChange={(e) => setReason(e.target.value)}
                />
              </label>

              {error && (
                <p className="text-sm text-destructive" role="alert">
                  {error}
                </p>
              )}

              <div className="flex gap-2">
                <Button variant="outline" disabled={busy} onClick={() => void submit(true)}>
                  Dry run
                </Button>
                <Button variant="destructive" disabled={busy} onClick={() => void submit(false)}>
                  Execute
                </Button>
              </div>

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
