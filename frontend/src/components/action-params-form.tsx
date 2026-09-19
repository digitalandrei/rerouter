/**
 * Schema-driven parameter form for a device-CLI action template. Shared by the
 * manual-mitigation wizard and the rule-action editor so both present the same
 * guided pickers instead of free-text:
 *   - source "bgp_local_as"     -> ASN dropdown (discovered local AS)
 *   - source "bgp_peer"         -> neighbor dropdown (filtered by the chosen ASN;
 *                                  auto-fills the local-AS param)
 *   - source "announced_prefix" -> prefix dropdown (SSH-discovered networks)
 *   - source "rtbh_tag"         -> RTBH community dropdown (value = its route tag)
 *   - source "peer_out_prefix_list" -> READ-ONLY display of the prefix-list
 *                                  discovered on the chosen neighbor (never typed)
 *   - deferred: true            -> READ-ONLY note: resolved by the controller at
 *                                  apply time (the prefix-list sequence number is
 *                                  chosen from a read taken in the apply session)
 *   - subprefix_of: "<param>"   -> CIDR textbox scoped to the parent prefix
 *   - otherwise                 -> a plain typed textbox
 * The controlled `values` map is the resolved parameter set the caller submits.
 */
import { useEffect, useId, useState } from "react";
import {
  api,
  type TemplateParamSpec,
  type BgpPeer,
  type BgpNetwork,
  type RtbhCommunity,
  type Interface,
  type RoutingPolicyInventory,
} from "@/lib/api";
import { RoutingPolicyInventoryView } from "@/components/routing-policy-inventory";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

/** Derived (non-editable) value: looks like a field, reads as inventory. */
const derivedClass =
  "w-full rounded-md border border-input bg-muted px-3 py-2 text-sm text-foreground";

/** Same, for the "nothing discovered" state — the action would be refused. */
const derivedWarnClass =
  "w-full rounded-md border border-amber-500 bg-amber-50 px-3 py-2 text-sm " +
  "text-amber-800 dark:border-amber-400 dark:bg-amber-950/40 dark:text-amber-300";

/** Compact "time ago" for SSH-discovered route context (staleness at a glance). */
function discoveredAgo(iso: string | null | undefined): string {
  if (iso === undefined) return ""; // API build without the field: say nothing.
  if (iso === null) return "never discovered";
  const ms = Date.now() - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return "never discovered";
  if (ms < 0) return "discovered just now";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `discovered ${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `discovered ${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `discovered ${h}h ago`;
  return `discovered ${Math.floor(h / 24)}d ago`;
}

export function ActionParamsForm({
  schema,
  deviceId,
  values,
  onChange,
  omitParams,
}: {
  schema: Record<string, TemplateParamSpec>;
  deviceId: number | null;
  values: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
  /** Parameter names to skip rendering (e.g. "prefix" when auto-targeting). */
  omitParams?: Set<string>;
}) {
  const [peers, setPeers] = useState<BgpPeer[]>([]);
  const [peerInventoryState, setPeerInventoryState] = useState<"idle" | "loading" | "ready" | "error">("idle");
  const [networks, setNetworks] = useState<BgpNetwork[]>([]);
  const [rtbh, setRtbh] = useState<RtbhCommunity[]>([]);
  const [interfaces, setInterfaces] = useState<Interface[]>([]);
  const [routeMaps, setRouteMaps] = useState<string[]>([]);
  const [policyInventory, setPolicyInventory] = useState<RoutingPolicyInventory | null>(null);
  const [policyError, setPolicyError] = useState<string | null>(null);
  const policyKindHelpId = useId();
  const isExportPolicy = "neighbor_ip" in schema && "policy_kind" in schema && "policy_name" in schema;

  useEffect(() => {
    if (!isExportPolicy) api.rtbh.list().then(setRtbh).catch(() => setRtbh([]));
  }, [isExportPolicy]);

  useEffect(() => {
    // Clear FIRST: `deviceId` mutates on a mounted form (ManualReroute's router
    // dropdown), so the previous router's peers/prefixes must never stay on
    // screen while the new ones load — that is how a value from device A gets
    // picked for device B. The `cancelled` flag drops late responses from a
    // superseded device for the same reason.
    setPeers([]);
    setPeerInventoryState(deviceId && !isExportPolicy ? "loading" : "idle");
    setNetworks([]);
    setInterfaces([]);
    setRouteMaps([]);
    if (!deviceId || isExportPolicy) return;
    let cancelled = false;
    api.devices
      .bgpPeers(deviceId)
      .then((v) => {
        if (!cancelled) { setPeers(v); setPeerInventoryState("ready"); }
      })
      .catch(() => {
        if (!cancelled) { setPeers([]); setPeerInventoryState("error"); }
      });
    api.devices
      .bgpNetworks(deviceId)
      .then((v) => {
        if (!cancelled) setNetworks(v);
      })
      .catch(() => {
        if (!cancelled) setNetworks([]);
      });
    api.devices
      .interfaces(deviceId)
      .then((v) => {
        if (!cancelled) setInterfaces(v);
      })
      .catch(() => {
        if (!cancelled) setInterfaces([]);
      });
    api.devices
      .routeMaps(deviceId)
      .then((v) => {
        if (!cancelled) setRouteMaps(v);
      })
      .catch(() => {
        if (!cancelled) setRouteMaps([]);
      });
    return () => {
      cancelled = true;
    };
  }, [deviceId, isExportPolicy]);

  useEffect(() => {
    setPolicyInventory(null); setPolicyError(null);
    if (!deviceId || !isExportPolicy) return;
    let cancelled = false;
    api.routingPolicies.get(deviceId).then((value) => { if (!cancelled) setPolicyInventory(value); }).catch((cause: unknown) => { if (!cancelled) setPolicyError(cause instanceof Error ? cause.message : "Policy inventory unavailable"); });
    return () => { cancelled = true; };
  }, [deviceId, isExportPolicy]);

  useEffect(() => {
    if (isExportPolicy && values.policy_kind === undefined) onChange({ ...values, policy_kind: "prefix_list" });
  }, [isExportPolicy, values, onChange]);

  const localAsns = Array.from(
    new Set(peers.map((p) => p.local_as).filter((a): a is number => a != null)),
  );
  const asnParam = Object.entries(schema).find(([, s]) => s.source === "bgp_local_as")?.[0];
  const neighborParam = Object.entries(schema).find(([, s]) => s.source === "bgp_peer")?.[0];
  const pfxListParam = Object.entries(schema).find(
    ([, s]) => s.source === "peer_out_prefix_list",
  )?.[0];

  /** The peer currently chosen in the neighbor dropdown, resolved against the
   *  inventory of the CURRENT device (null while it loads, or after a switch). */
  const selectedPeer =
    (neighborParam && values[neighborParam]
      ? peers.find((p) => p.peer_remote_addr === values[neighborParam])
      : undefined) ?? null;

  /** The outbound prefix-list is derived from that peer — never typed. */
  const derivedPfxList = selectedPeer?.out_prefix_list ?? "";

  // Keep the submitted value equal to what the neighbor actually has. Without
  // this, a value left over from a previously selected peer (or from the
  // previous device) would be submitted and then refused fail-closed by the
  // validator — which is exactly the "pfx-to-viva" the operator saw.
  useEffect(() => {
    if (!pfxListParam || peerInventoryState !== "ready") return;
    if ((values[pfxListParam] ?? "") === derivedPfxList) return;
    onChange({ ...values, [pfxListParam]: derivedPfxList });
  }, [pfxListParam, derivedPfxList, peerInventoryState, values, onChange]);

  function set(name: string, value: string) {
    onChange({ ...values, [name]: value });
  }

  function selectNeighbor(name: string, addr: string) {
    const next = { ...values, [name]: addr };
    const peer = peers.find((p) => p.peer_remote_addr === addr);
    for (const [pname, spec] of Object.entries(schema)) {
      // Auto-fill is TOTAL: every peer-derived param is (re)assigned on every
      // neighbor change, and cleared when the new peer has no value or the
      // neighbor is deselected. A conditional assignment left the previous
      // peer's value in place, which the device would then apply to the wrong
      // prefix-list / AS.
      if (spec.source === "bgp_local_as") {
        next[pname] = peer?.local_as != null ? String(peer.local_as) : "";
      }
      if (spec.source === "peer_out_prefix_list") {
        next[pname] = peer?.out_prefix_list ?? "";
      }
    }
    onChange(next);
  }

  if (isExportPolicy) {
    const peer = values.neighbor_ip ?? "";
    const kind = values.policy_kind ?? "prefix_list";
    const name = values.policy_name ?? "";
    const peers = Array.from(new Set(policyInventory?.peer_bindings.map((binding) => binding.neighbor_ip) ?? []));
    const names = kind === "route_map" ? policyInventory?.route_maps.map((item) => item.name) ?? [] : policyInventory?.prefix_lists.map((item) => item.name) ?? [];
    const visibleNames = name && !names.includes(name) ? [name, ...names] : names;
    return <div className="space-y-3 sm:col-span-2">
      <div className="space-y-1"><p className="text-sm font-medium">{kind === "route_map" ? "Change the outbound route map (advanced)" : "Change the outbound prefix list"}</p><p className="text-xs text-muted-foreground">{kind === "route_map" ? "Choose an existing shared route map for this peer. Its outbound prefix list stays attached." : "Choose an existing shared prefix list for this peer. Its outbound route map stays attached and may also filter routes."}</p></div>
      <div className="grid gap-3 sm:grid-cols-3">
        <label className="space-y-1 text-sm font-medium">Peer<select className={inputClass} value={peer} onChange={(event) => onChange({ ...values, neighbor_ip: event.target.value })}><option value="">Select peer…</option>{peer && !peers.includes(peer) && <option value={peer}>{peer} (missing)</option>}{peers.map((item) => <option key={item} value={item}>{item}</option>)}</select></label>
        <label className="space-y-1 text-sm font-medium">Change attachment<select aria-describedby={policyKindHelpId} className={inputClass} value={kind} onChange={(event) => onChange({ ...values, policy_kind: event.target.value, policy_name: "" })}><option value="prefix_list">Outbound prefix list (recommended)</option><option value="route_map">Outbound route map (advanced)</option></select><span id={policyKindHelpId} className="block text-xs font-normal text-muted-foreground">Changing type clears the selected policy. Saved route-map actions keep their existing type.</span></label>
        <label className="space-y-1 text-sm font-medium">{kind === "route_map" ? "Outbound route map" : "Outbound prefix list"}<select className={inputClass} value={name} onChange={(event) => onChange({ ...values, policy_name: event.target.value })}><option value="">Select {kind === "route_map" ? "route map" : "prefix list"}…</option>{visibleNames.map((item) => <option key={item} value={item}>{item}{!names.includes(item) ? " (missing)" : ""}</option>)}</select></label>
      </div>
      {policyError && <p role="alert" className="text-sm text-destructive">{policyError}</p>}
      {!policyInventory && !policyError && <p role="status" className="text-sm text-muted-foreground">Loading cached routing policy inventory…</p>}
      {policyInventory && <RoutingPolicyInventoryView inventory={policyInventory} selectedPeer={peer} selectedKind={kind} selectedName={name} />}
    </div>;
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {Object.entries(schema).filter(([name]) => !omitParams?.has(name)).map(([name, spec]) => {
        const label = (
          <>
            {spec.label ?? name} <span className="text-muted-foreground">({spec.type})</span>
          </>
        );

        // Apply-time values are never operator input: the controller picks the
        // prefix-list sequence from a fresh read inside the session that writes
        // it, so the list cannot have moved under the decision. Shown, not typed.
        if (spec.deferred) {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <div className={derivedClass}>chosen at apply time</div>
              <p className="text-xs font-normal text-muted-foreground">
                Picked from a fresh read of the prefix-list in the same SSH session that
                writes it, so the entry lands before the list&rsquo;s terminating deny and
                never overwrites an existing one. The preview shows{" "}
                <code>&lt;auto-seq&gt;</code> in its place.
              </p>
            </label>
          );
        }

        if (spec.source === "bgp_local_as") {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
                disabled={!deviceId}
              >
                <option value="">{localAsns.length ? "Select ASN…" : "no ASN discovered"}</option>
                {localAsns.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </label>
          );
        }

        if (spec.source === "bgp_peer") {
          const selectedAsn = asnParam ? values[asnParam] : "";
          const shown = selectedAsn ? peers.filter((p) => String(p.local_as) === selectedAsn) : peers;
          // `inventory_fresh` is absent on API builds that predate it: only an
          // explicit `false` means stale, so the picker never blocks on a
          // backend that has not shipped the field yet.
          const staleCount = shown.filter((p) => p.inventory_fresh === false).length;
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => selectNeighbor(name, e.target.value)}
                disabled={!deviceId}
              >
                <option value="">
                  {!deviceId
                    ? "Pick a router first"
                    : peers.length
                      ? "Select neighbor…"
                      : "no neighbors discovered"}
                </option>
                {shown.map((p) => {
                  const stale = p.inventory_fresh === false;
                  return (
                    // Stale peers stay visible (so the operator sees WHY the
                    // neighbor is missing) but are not selectable: offering them
                    // only produces values the validator will reject.
                    <option key={p.id} value={p.peer_remote_addr} disabled={stale}>
                      {p.peer_remote_addr}
                      {p.peer_remote_as ? ` · AS${p.peer_remote_as}` : ""}
                      {p.label ? ` · ${p.label}` : ""}
                      {stale ? " · stale inventory" : ""}
                    </option>
                  );
                })}
              </select>
              {staleCount > 0 && (
                <span className="text-[11px] font-normal text-amber-700 dark:text-amber-400">
                  {staleCount} neighbor{staleCount === 1 ? "" : "s"} not selectable — inventory is
                  stale; re-poll this router
                </span>
              )}
            </label>
          );
        }

        if (spec.source === "announced_prefix") {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
                disabled={!deviceId}
              >
                <option value="">
                  {!deviceId
                    ? "Pick a router first"
                    : networks.length
                      ? "Select prefix…"
                      : "no prefixes discovered"}
                </option>
                {networks.map((n) => (
                  <option key={n.id} value={n.prefix}>
                    {n.prefix}
                  </option>
                ))}
              </select>
            </label>
          );
        }

        if (spec.source === "rtbh_tag") {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
              >
                <option value="">
                  {rtbh.length ? "Select community…" : "no RTBH communities (add in Settings)"}
                </option>
                {rtbh.map((c) => (
                  <option key={c.id} value={c.tag}>
                    {c.label} ({c.community})
                  </option>
                ))}
              </select>
            </label>
          );
        }

        if (spec.source === "interface_name") {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
                disabled={!deviceId}
              >
                <option value="">
                  {!deviceId
                    ? "Pick a router first"
                    : interfaces.length
                      ? "Select interface…"
                      : "no interfaces discovered"}
                </option>
                {interfaces.map((i) => (
                  <option key={i.id} value={i.if_name}>
                    {i.if_name}
                    {i.if_alias ? ` · ${i.if_alias}` : ""}
                  </option>
                ))}
              </select>
            </label>
          );
        }

        if (spec.source === "peer_out_prefix_list") {
          // DERIVED, never typed. The backend treats this name as a closed
          // allowlist of discovered prefix-lists, and on IOS
          // `ip prefix-list <NAME> permit <cidr>` SILENTLY CREATES a new list
          // when the name is wrong — a typo (or a browser autofill, or a value
          // carried over from another peer) would build a phantom list that
          // filters nothing. So: read-only display of what discovery found.
          const discoveredAt = selectedPeer
            ? discoveredAgo(selectedPeer.route_context_discovered_at)
            : "";
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              {!selectedPeer ? (
                <div className={`${derivedClass} text-muted-foreground`}>
                  select the upstream neighbor first
                </div>
              ) : derivedPfxList ? (
                <>
                  <input
                    className={`${derivedClass} font-mono`}
                    value={derivedPfxList}
                    readOnly
                    autoComplete="off"
                    tabIndex={-1}
                    aria-readonly="true"
                  />
                  <span className="text-[11px] font-normal text-muted-foreground">
                    discovered on this neighbor
                    {discoveredAt ? ` · ${discoveredAt}` : ""}
                  </span>
                </>
              ) : (
                <>
                  <div className={derivedWarnClass}>
                    no outbound prefix-list discovered for this neighbor — run Discover prefixes on
                    this router; this action would be refused
                  </div>
                  {discoveredAt && (
                    <span className="text-[11px] font-normal text-amber-700 dark:text-amber-400">
                      route context: {discoveredAt}
                    </span>
                  )}
                </>
              )}
            </label>
          );
        }

        if (spec.source === "route_map") {
          // Operator picks the NEW map from discovered ones; we surface the
          // neighbor's CURRENT map (chosen direction) as the prior a revert restores.
          const dirParam = Object.entries(schema).find(([, s]) => s.source === "bgp_direction")?.[0];
          const selNeighbor = neighborParam ? values[neighborParam] : "";
          const selDir = (dirParam ? values[dirParam] : "") || "out";
          const peer = peers.find((p) => p.peer_remote_addr === selNeighbor);
          const current = peer ? (selDir === "in" ? peer.in_route_map : peer.out_route_map) : null;
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
                disabled={!deviceId}
              >
                <option value="">
                  {!deviceId
                    ? "Pick a router first"
                    : routeMaps.length
                      ? "Select route-map…"
                      : "no route-maps discovered"}
                </option>
                {routeMaps.map((rm) => (
                  <option key={rm} value={rm}>
                    {rm}
                  </option>
                ))}
              </select>
              {selNeighbor && (
                <span className="text-[11px] font-normal text-muted-foreground">
                  current {selDir} map: {current ?? "none"} (restored on revert)
                </span>
              )}
            </label>
          );
        }

        if (spec.enum && spec.enum.length) {
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <select
                className={inputClass}
                value={values[name] ?? ""}
                onChange={(e) => set(name, e.target.value)}
              >
                <option value="">Select…</option>
                {spec.enum.map((opt) => (
                  <option key={opt} value={opt}>
                    {opt}
                  </option>
                ))}
              </select>
            </label>
          );
        }

        if (spec.subprefix_of) {
          const parentVal = values[spec.subprefix_of];
          return (
            <label key={name} className="block space-y-1 text-sm font-medium">
              {label}
              <input
                className={inputClass}
                value={values[name] ?? ""}
                placeholder={parentVal ? `within ${parentVal}` : "e.g. 192.0.2.128/25"}
                onChange={(e) => set(name, e.target.value)}
              />
              {parentVal && (
                <span className="text-[11px] font-normal text-muted-foreground">
                  any subnet of {parentVal}, including the whole prefix
                </span>
              )}
            </label>
          );
        }

        return (
          <label key={name} className="block space-y-1 text-sm font-medium">
            {label}
            <input
              className={inputClass}
              value={values[name] ?? ""}
              placeholder={
                spec.type === "cidr"
                  ? "e.g. 192.0.2.0/24"
                  : spec.type === "asn"
                    ? "e.g. 65001"
                    : spec.type === "int"
                      ? "e.g. 666"
                      : ""
              }
              onChange={(e) => set(name, e.target.value)}
            />
          </label>
        );
      })}
    </div>
  );
}
