import type { RoutingPolicyInventory } from "@/lib/api";

type RouteMap = RoutingPolicyInventory["route_maps"][number];
export type RouteMapPreflight = "none" | "straightforward" | "may_filter";
function isAllowedSet(value: string) {
  return /^(as-path prepend|metric|local-preference)\b/i.test(value.trim());
}

/** A deliberately narrow display hint. The exact device preview remains authoritative. */
export function classifyCachedRouteMap(routeMap: RouteMap | undefined): RouteMapPreflight {
  if (!routeMap) return "none";
  return routeMap.clauses.length > 0 && routeMap.clauses.every((clause) => clause.action === "permit" && clause.matches.length === 0 && clause.sets.every((term) => isAllowedSet(term.value))) ? "straightforward" : "may_filter";
}

function attachmentName(inventory: RoutingPolicyInventory, peer: string | undefined, kind: string) {
  if (!peer) return null;
  return inventory.peer_bindings.find((binding) => binding.neighbor_ip === peer && binding.policy_kind === kind)?.policy_name ?? null;
}
function Attachment({ label, name, complete }: { label: string; name: string | null; complete: boolean }) {
  return <div><dt className="text-xs text-muted-foreground">{label}</dt><dd className="font-medium">{name ?? (complete ? "None attached" : "Unknown from cached inventory")}</dd></div>;
}
function PrefixContents({ policy }: { policy: RoutingPolicyInventory["prefix_lists"][number] }) {
  return <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-muted-foreground"><tr><th className="py-1 pr-3">Seq</th><th className="py-1 pr-3">Action</th><th className="py-1 pr-3">Prefix</th><th className="py-1 pr-3">GE</th><th className="py-1">LE</th></tr></thead><tbody>{policy.entries.map((entry) => <tr key={entry.sequence} className="border-t"><td className="py-1.5 pr-3 tabular-nums">{entry.sequence}</td><td className="py-1.5 pr-3 font-medium">{entry.action}</td><td className="py-1.5 pr-3 font-mono">{entry.prefix}</td><td className="py-1.5 pr-3 tabular-nums">{entry.ge ?? "—"}</td><td className="py-1.5 tabular-nums">{entry.le ?? "—"}</td></tr>)}</tbody></table></div>;
}
function RouteMapContents({ policy }: { policy: RouteMap }) {
  return <ol className="space-y-2">{policy.clauses.map((clause) => <li key={clause.sequence} className="rounded-md bg-background p-2"><div><strong>Sequence {clause.sequence}: {clause.action}</strong></div><div className="mt-1 text-xs"><span className="text-muted-foreground">Matches:</span> {clause.matches.length ? clause.matches.map((term) => term.value).join("; ") : "all routes"}</div><div className="text-xs"><span className="text-muted-foreground">Sets:</span> {clause.sets.length ? clause.sets.map((term) => term.value).join("; ") : "none"}</div><details className="mt-1 text-xs"><summary className="cursor-pointer text-muted-foreground">Technical details</summary><pre className="mt-1 overflow-auto rounded bg-muted p-2">{JSON.stringify(clause, null, 2)}</pre></details></li>)}</ol>;
}

export function RoutingPolicyInventoryView({ inventory, selectedPeer, selectedKind, selectedName }: { inventory: RoutingPolicyInventory; selectedPeer?: string; selectedKind?: string; selectedName?: string }) {
  const currentPrefixList = attachmentName(inventory, selectedPeer, "prefix_list");
  const currentRouteMap = attachmentName(inventory, selectedPeer, "route_map");
  const selectedPrefixList = selectedKind === "prefix_list" ? inventory.prefix_lists.find((item) => item.name === selectedName) : undefined;
  const selectedRouteMap = selectedKind === "route_map" ? inventory.route_maps.find((item) => item.name === selectedName) : undefined;
  const routeMap = inventory.route_maps.find((item) => item.name === (selectedKind === "route_map" ? selectedName : currentRouteMap));
  const routeMapPreflight = classifyCachedRouteMap(routeMap);
  const afterPrefixList = selectedKind === "prefix_list" && selectedName ? selectedName : currentPrefixList;
  const afterRouteMap = selectedKind === "route_map" && selectedName ? selectedName : currentRouteMap;
  const complete = inventory.completeness === "complete" && inventory.blockers.length === 0 && Boolean(inventory.read_at);
  const peerBindings = inventory.peer_bindings.filter((binding) => !selectedPeer || binding.neighbor_ip === selectedPeer);
  if (!selectedPeer) return <div className="space-y-3 rounded-md border bg-muted/20 p-3 text-sm">
    <div className="flex flex-wrap justify-between gap-2"><strong>Cached routing policy inventory</strong><span className="text-xs text-muted-foreground">{inventory.read_at ? `Read ${new Date(inventory.read_at).toLocaleString()}` : "Never read"} · {inventory.completeness}</span></div>
    {inventory.blockers.length > 0 && <p className="text-amber-800 dark:text-amber-300">Cached inventory is incomplete: {inventory.blockers.join(" · ")}</p>}
    <div><h4 className="font-medium">Outbound bindings</h4>{peerBindings.length ? <ul className="mt-1 space-y-1">{peerBindings.map((binding, index) => <li key={`${binding.neighbor_ip}-${binding.policy_kind}-${index}`}><code>{binding.neighbor_ip}</code> · {binding.policy_kind === "route_map" ? "Outbound route map" : "Outbound prefix list"}: <strong>{binding.policy_name}</strong> · {binding.scope}</li>)}</ul> : <p className="text-muted-foreground">{complete ? "No outbound bindings found." : "Outbound bindings are unknown from this cached inventory."}</p>}</div>
    <div className="space-y-2"><h4 className="font-medium">Policy contents</h4>{inventory.prefix_lists.map((policy) => <details key={`prefix-${policy.name}`}><summary className="cursor-pointer">Prefix list <strong>{policy.name}</strong></summary><div className="mt-2"><PrefixContents policy={policy} /></div></details>)}{inventory.route_maps.map((policy) => <details key={`map-${policy.name}`}><summary className="cursor-pointer">Route map <strong>{policy.name}</strong></summary><div className="mt-2"><RouteMapContents policy={policy} /></div></details>)}</div>
  </div>;
  return <div className="space-y-4 rounded-md border bg-muted/20 p-3 text-sm">
    <div className="flex flex-wrap justify-between gap-2"><strong>Cached policy preflight</strong><span className="text-xs text-muted-foreground">{inventory.read_at ? `Read ${new Date(inventory.read_at).toLocaleString()}` : "Never read"} · {inventory.completeness}</span></div>
    {inventory.blockers.length > 0 && <p className="text-amber-800 dark:text-amber-300">Cached inventory is incomplete: {inventory.blockers.join(" · ")}</p>}
    <section aria-label="Outbound attachment change" className="space-y-2">
      <h4 className="font-medium">Outbound attachments for {selectedPeer || "the selected peer"}</h4>
      <div className="grid gap-3 sm:grid-cols-3">
        <div><div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">Before</div><dl className="space-y-2"><Attachment label="Outbound prefix list" name={currentPrefixList} complete={complete} /><Attachment label="Outbound route map" name={currentRouteMap} complete={complete} /></dl></div>
        <div><div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">After this action</div><dl className="space-y-2"><Attachment label="Outbound prefix list" name={afterPrefixList} complete={complete} /><Attachment label="Outbound route map" name={afterRouteMap} complete={complete} /></dl></div>
        <div><div className="mb-1 text-xs font-medium uppercase tracking-wide text-muted-foreground">After revert</div><dl className="space-y-2"><Attachment label="Outbound prefix list" name={currentPrefixList} complete={complete} /><Attachment label="Outbound route map" name={currentRouteMap} complete={complete} /></dl></div>
      </div>
      {selectedKind === "prefix_list" && <p className="text-xs text-muted-foreground">The outbound route map is preserved. Replacing the attachment does not edit the shared prefix list or its entries.</p>}
      {selectedKind === "route_map" && <p className="text-xs text-muted-foreground">The outbound prefix list is preserved. Replacing the attachment does not edit the shared route map or its clauses.</p>}
    </section>
    {(currentRouteMap || selectedKind === "route_map") && routeMapPreflight === "straightforward" && <p><strong>Cached preflight for {selectedKind === "route_map" ? "the selected" : "the attached"} route map:</strong> permit clauses have no matches and use only recognized attribute changes. This is an effect assessment, not routing verification; the exact preview decides the combined result.</p>}
    {(currentRouteMap || selectedKind === "route_map") && routeMapPreflight !== "straightforward" && <p role="status" className="text-amber-800 dark:text-amber-300"><strong>{selectedKind === "route_map" ? "The selected route map" : "The attached route map"} may filter routes.</strong> A prefix list and route map both apply when both are attached. Matches, deny clauses, communities, or policy forms outside this bounded cached check require the exact preview to decide the result.</p>}
    {!currentRouteMap && selectedKind !== "route_map" && selectedPeer && <p className="text-muted-foreground">{complete ? "No outbound route map is attached to this peer in the cached inventory." : "The outbound route-map attachment is unknown from this cached inventory."}</p>}
    {peerBindings.some((binding) => binding.scope !== "direct") && <p className="text-amber-800 dark:text-amber-300">This cached binding is inherited or ambiguous. Attachment changes are blocked until the device context resolves it to a direct binding.</p>}
    {selectedKind === "prefix_list" && routeMap && <details><summary className="cursor-pointer font-medium">Preserved route map {routeMap.name}: {routeMapPreflight === "straightforward" ? "attribute changes only in cached preflight" : "may filter routes"}</summary><div className="mt-2"><RouteMapContents policy={routeMap} /></div></details>}
    {selectedPrefixList && <section className="space-y-2"><h4 className="font-medium">Selected prefix list contents</h4><PrefixContents policy={selectedPrefixList} /><p className="text-xs text-muted-foreground">Shared by: {selectedPrefixList.referenced_by.length ? selectedPrefixList.referenced_by.join(", ") : "no cached references"}</p></section>}
    {selectedRouteMap && <section className="space-y-2"><h4 className="font-medium">Selected route map clauses</h4><RouteMapContents policy={selectedRouteMap} /></section>}
    {selectedName && !selectedPrefixList && !selectedRouteMap && <p className="text-amber-800 dark:text-amber-300">Saved policy “{selectedName}” is missing from the cached inventory. Keep the saved value visible, then complete setup before running this action.</p>}
  </div>;
}
