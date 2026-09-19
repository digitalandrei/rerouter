/**
 * /templates — the reroute action-template catalog (docs/reroute-engine.md).
 *
 * Templates are the ONLY way a reroute runs: parameterized, allowlisted
 * mitigations with verification and rollback. This page lists
 * them and — for device_cli (IOS-over-SSH) templates — renders the EXACT
 * commands for a given parameter set via the read-only /render endpoint. No
 * execution happens here; it is a preview sandbox.
 */
import { useEffect, useState } from "react";
import {
  api,
  type Template,
  type RenderedPlan,
  type TemplateParamSpec,
} from "@/lib/api";
import { templateGuidance, templateLabel, providerTypeLabel } from "@/lib/labels";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ApiError } from "@/lib/api";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

function paramPlaceholder(spec: TemplateParamSpec): string {
  switch (spec.type) {
    case "ip":
      return "e.g. 10.0.0.1";
    case "cidr":
      return "e.g. 192.0.2.0/24";
    case "asn":
      return "e.g. 65001";
    default:
      return "";
  }
}

function TemplateCard({ template }: { template: Template }) {
  const isDeviceCli = template.provider_type === "device_cli";
  const params = template.parameter_schema ?? {};
  const paramNames = Object.keys(params);

  const [values, setValues] = useState<Record<string, string>>({});
  const [plan, setPlan] = useState<RenderedPlan | null>(null);
  const [rollbackPlan, setRollbackPlan] = useState<RenderedPlan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function preview() {
    setBusy(true);
    setError(null);
    setPlan(null);
    setRollbackPlan(null);
    try {
      const r = await api.templates.render(template.id, values);
      if (r.ok && r.plan) {
        setPlan(r.plan);
        setRollbackPlan(r.rollback ?? null);
      } else {
        setError(r.error ?? "render failed");
      }
    } catch {
      setError("render request failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle className="text-base">{templateLabel(template)}</CardTitle>
          <code className="text-xs text-muted-foreground">{template.name}</code>
          <Badge variant="outline" className="font-normal text-muted-foreground">
            {providerTypeLabel(template.provider_type)}
          </Badge>
          {!template.enabled && <Badge variant="secondary">disabled</Badge>}
        </div>
        {template.description && (
          <CardDescription>{template.description}</CardDescription>
        )}
        {templateGuidance(template.name) && <CardDescription>{templateGuidance(template.name)}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-3">
        {!isDeviceCli ? (
          <p className="text-xs text-muted-foreground">
            External provider ({providerTypeLabel(template.provider_type)}) — not wired in v1. The
            active mitigation path is the device-CLI templates.
          </p>
        ) : (
          <>
            <div className="grid gap-2 sm:grid-cols-2">
              {paramNames.map((name) => {
                const spec = params[name];
                return (
                  <label key={name} className="block space-y-1 text-xs font-medium">
                    {spec.label ?? name}{" "}
                    <span className="text-muted-foreground">({spec.type})</span>
                    <Input
                      value={values[name] ?? ""}
                      placeholder={paramPlaceholder(spec)}
                      onChange={(e) =>
                        { setValues((v) => ({ ...v, [name]: e.target.value })); setPlan(null); setRollbackPlan(null); }
                      }
                    />
                  </label>
                );
              })}
            </div>
            <Button size="sm" variant="outline" onClick={() => void preview()} disabled={busy}>
              {busy ? "Rendering…" : "Preview commands"}
            </Button>
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            {plan && (
              <div className="space-y-2">
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Would run on the device
                </div>
                <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                  {plan.commands.join("\n")}
                </pre>
                {plan.verify && (
                  <div className="text-xs text-muted-foreground">
                    Verify:{" "}
                    <code>{plan.verify.command}</code>
                    {plan.verify.expect && <> — expect “{plan.verify.expect}”</>}
                    {plan.verify.reject && <> — reject “{plan.verify.reject}”</>}
                  </div>
                )}
                <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  Defined inverse preview
                </div>
                {rollbackPlan ? (
                  <pre className="overflow-x-auto rounded-md border border-border bg-muted/40 p-3 text-xs">
                    {rollbackPlan.commands.join("\n")}
                  </pre>
                ) : (
                  <p className="text-xs text-muted-foreground">
                    No inverse template is defined. This preview does not create an undo operation.
                  </p>
                )}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

export default function Templates() {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);

  useEffect(() => {
    api.templates
      .list()
      .then((items) => { setTemplates(items); setLoadError(null); })
      .catch((e) => setLoadError(e instanceof ApiError ? e.message : "Failed to load templates"))
      .finally(() => setLoading(false));
  }, []);

  // device_cli templates first — they are the active mitigation path.
  const ordered = [...templates].sort((a, b) => {
    if (a.provider_type === b.provider_type) return a.name.localeCompare(b.name);
    return a.provider_type === "device_cli" ? -1 : b.provider_type === "device_cli" ? 1 : 0;
  });
  const filtered = ordered.filter((template) => `${template.name} ${template.display_name ?? ""} ${template.description ?? ""}`.toLowerCase().includes(search.toLowerCase()));
  const selected = templates.find((template) => template.id === selectedId) ?? null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Action templates</h1>
        <p className="text-sm text-muted-foreground">
          Parameterized, allowlisted mitigations — the only way a reroute runs.
          Preview renders exact commands; nothing executes from this page.
        </p>
      </div>
      {loading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : loadError ? (
        <p role="alert" className="text-sm text-destructive">Templates could not be loaded: {loadError}</p>
      ) : ordered.length === 0 ? (
        <p className="text-sm text-muted-foreground">No templates.</p>
      ) : (
        <div className="grid gap-4 lg:grid-cols-[minmax(16rem,22rem)_1fr]">
          <Card><CardHeader><CardTitle className="text-base">Catalog</CardTitle></CardHeader><CardContent className="space-y-3">
            <label className="space-y-1 text-sm font-medium" htmlFor="template-search">Search templates</label><Input id="template-search" value={search} onChange={(event) => setSearch(event.target.value)} />
            <div className="max-h-[32rem] space-y-1 overflow-auto">{filtered.map((template) => <Button key={template.id} type="button" variant={selectedId === template.id ? "secondary" : "ghost"} className="h-auto w-full justify-start whitespace-normal py-2 text-left" onClick={() => setSelectedId(template.id)}>{templateLabel(template)}</Button>)}</div>
            {filtered.length === 0 && <p className="text-sm text-muted-foreground">No templates match this search.</p>}
          </CardContent></Card>
          {selected ? <TemplateCard key={selected.id} template={selected} /> : <div className="rounded-md border border-dashed p-6 text-sm text-muted-foreground">Select a template to inspect its parameters and render a preview.</div>}
        </div>
      )}
    </div>
  );
}
