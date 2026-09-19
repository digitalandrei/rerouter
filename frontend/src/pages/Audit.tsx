import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Eye } from "lucide-react";
import { api } from "@/lib/api";
import { humanizeToken } from "@/lib/labels";
import { useResource } from "@/lib/resource-state";
import { DataState } from "@/components/data-state";
import { Button } from "@/components/ui/button";
import { RowActionButton } from "@/components/row-action-button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";

function positivePage(value: string | null) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : 1;
}

export default function Audit() {
  const [search, setSearch] = useSearchParams();
  const actor = search.get("actor") ?? "";
  const action = search.get("action") ?? "";
  const entity = search.get("entity") ?? "";
  const after = search.get("after") ?? "";
  const before = search.get("before") ?? "";
  const page = positivePage(search.get("page"));
  const load = useCallback((signal: AbortSignal) => api.audit.listPage({ actor, action, entity, after: after || undefined, before: before || undefined, page, limit: 50 }, signal), [actor, action, entity, after, before, page]);
  const resource = useResource(load, [actor, action, entity, after, before, page]);

  function update(key: string, value: string) {
    setSearch((previous) => {
      const next = new URLSearchParams(previous);
      if (value) next.set(key, value); else next.delete(key);
      if (key !== "page") next.delete("page");
      return next;
    }, { replace: true });
  }

  return <div className="space-y-6">
    <h1 className="text-2xl font-bold tracking-tight">Audit log</h1>
    <Card><CardHeader><CardTitle className="text-lg">Filters</CardTitle></CardHeader>
      <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <div className="space-y-1"><Label htmlFor="audit-actor">Actor</Label><Input id="audit-actor" value={actor} onChange={(event) => update("actor", event.target.value)} placeholder="Email or actor type" /></div>
        <div className="space-y-1"><Label htmlFor="audit-action">Action</Label><Input id="audit-action" value={action} onChange={(event) => update("action", event.target.value)} placeholder="Exact event type" /></div>
        <div className="space-y-1"><Label htmlFor="audit-entity">Entity</Label><Input id="audit-entity" value={entity} onChange={(event) => update("entity", event.target.value)} placeholder="Type or ID" /></div>
        <div className="space-y-1"><Label htmlFor="audit-after">From</Label><Input id="audit-after" type="datetime-local" value={after} onChange={(event) => update("after", event.target.value)} /></div>
        <div className="space-y-1"><Label htmlFor="audit-before">Until</Label><Input id="audit-before" type="datetime-local" value={before} onChange={(event) => update("before", event.target.value)} /></div>
        {search.size > 0 && <Button type="button" variant="outline" onClick={() => setSearch({}, { replace: true })}>Reset filters</Button>}
      </CardContent>
    </Card>
    <Card><CardHeader><CardTitle className="text-lg">Entries</CardTitle></CardHeader><CardContent>
      <DataState state={resource.state} retry={resource.retry} loadingLabel="Loading audit entries…" empty={(result) => result.rows.length === 0} emptyContent={<p className="text-sm text-muted-foreground">No audit entries match these filters.</p>}>
        {(result) => <><Table><TableHeader><TableRow><TableHead>When</TableHead><TableHead>Actor</TableHead><TableHead>Action</TableHead><TableHead>Subject</TableHead><TableHead>IP</TableHead><TableHead>Details</TableHead></TableRow></TableHeader>
          <TableBody>{result.rows.map((entry) => <TableRow key={entry.id}><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{new Date(entry.created_at).toLocaleString()}</TableCell><TableCell className="max-w-56 break-words">{entry.actor}</TableCell><TableCell>{humanizeToken(entry.action)}</TableCell><TableCell className="max-w-56 break-words">{entry.subject}</TableCell><TableCell><code className="text-xs">{entry.ip || "—"}</code></TableCell><TableCell><details><RowActionButton asChild label={`View audit details for ${humanizeToken(entry.action)}`}><summary><Eye className="size-4" /></summary></RowActionButton><pre className="mt-2 max-w-md overflow-auto whitespace-pre-wrap break-words rounded bg-muted p-2 text-xs">{JSON.stringify(entry.details, null, 2)}</pre></details></TableCell></TableRow>)}</TableBody></Table>
          <div className="mt-4 flex items-center justify-between"><Button type="button" variant="outline" disabled={result.page <= 1} onClick={() => update("page", String(result.page - 1))}>Previous</Button><span className="text-sm text-muted-foreground">Page {result.page}</span><Button type="button" variant="outline" disabled={!result.has_more} onClick={() => update("page", String(result.page + 1))}>Next</Button></div></>}
      </DataState>
    </CardContent></Card>
  </div>;
}
