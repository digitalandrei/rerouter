import type { RoutingPolicyInventory } from "@/lib/api";

export function RoutingPolicyInventoryView({ inventory, selectedPeer, selectedKind, selectedName }: { inventory: RoutingPolicyInventory; selectedPeer?: string; selectedKind?: string; selectedName?: string }) {
  const bindings = inventory.peer_bindings.filter((binding) => !selectedPeer || binding.neighbor_ip === selectedPeer);
  const policy = selectedKind === "prefix_list" ? inventory.prefix_lists.find((item) => item.name === selectedName) : inventory.route_maps.find((item) => item.name === selectedName);
  return <div className="space-y-3 rounded-md border bg-muted/20 p-3 text-sm">
    <div className="flex flex-wrap justify-between gap-2"><strong>Cached routing policy inventory</strong><span className="text-xs text-muted-foreground">{inventory.read_at ? `Read ${new Date(inventory.read_at).toLocaleString()}` : "Never read"} · {inventory.completeness}</span></div>
    {inventory.blockers.length > 0 && <p className="text-amber-800 dark:text-amber-300">{inventory.blockers.join(" · ")}</p>}
    <div><span className="font-medium">Current outbound bindings</span>{bindings.length ? <ul className="mt-1 space-y-1">{bindings.map((binding, index) => <li key={`${binding.neighbor_ip}-${binding.policy_kind}-${index}`}><code>{binding.neighbor_ip}</code> · {binding.policy_kind} <strong>{binding.policy_name}</strong> · {binding.scope}</li>)}</ul> : <p className="mt-1 text-muted-foreground">No direct cached binding matches this peer.</p>}</div>
    {policy && <details open><summary className="cursor-pointer font-medium">Selected policy contents and shared references</summary><pre className="mt-2 max-h-72 overflow-auto rounded-md bg-background p-3 text-xs">{JSON.stringify(policy, null, 2)}</pre></details>}
    {selectedName && !policy && <p className="text-amber-800 dark:text-amber-300">Saved policy “{selectedName}” is missing from current inventory. Keep the value visible, but this action needs setup before it can run.</p>}
  </div>;
}
