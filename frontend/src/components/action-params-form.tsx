/**
 * Schema-driven parameter form for a device-CLI action template. Shared by the
 * manual-mitigation wizard and the rule-action editor so both present the same
 * guided pickers instead of free-text:
 *   - source "bgp_local_as"     -> ASN dropdown (discovered local AS)
 *   - source "bgp_peer"         -> neighbor dropdown (filtered by the chosen ASN;
 *                                  auto-fills the local-AS param)
 *   - source "announced_prefix" -> prefix dropdown (SSH-discovered networks)
 *   - source "rtbh_tag"         -> RTBH community dropdown (value = its route tag)
 *   - subprefix_of: "<param>"   -> CIDR textbox scoped to the parent prefix
 *   - otherwise                 -> a plain typed textbox
 * The controlled `values` map is the resolved parameter set the caller submits.
 */
import { useEffect, useState } from "react";
import {
  api,
  type TemplateParamSpec,
  type BgpPeer,
  type BgpNetwork,
  type RtbhCommunity,
} from "@/lib/api";

const inputClass =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm " +
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring";

export function ActionParamsForm({
  schema,
  deviceId,
  values,
  onChange,
}: {
  schema: Record<string, TemplateParamSpec>;
  deviceId: number | null;
  values: Record<string, string>;
  onChange: (next: Record<string, string>) => void;
}) {
  const [peers, setPeers] = useState<BgpPeer[]>([]);
  const [networks, setNetworks] = useState<BgpNetwork[]>([]);
  const [rtbh, setRtbh] = useState<RtbhCommunity[]>([]);

  useEffect(() => {
    api.rtbh.list().then(setRtbh).catch(() => setRtbh([]));
  }, []);

  useEffect(() => {
    if (!deviceId) {
      setPeers([]);
      setNetworks([]);
      return;
    }
    api.devices.bgpPeers(deviceId).then(setPeers).catch(() => setPeers([]));
    api.devices.bgpNetworks(deviceId).then(setNetworks).catch(() => setNetworks([]));
  }, [deviceId]);

  const localAsns = Array.from(
    new Set(peers.map((p) => p.local_as).filter((a): a is number => a != null)),
  );
  const asnParam = Object.entries(schema).find(([, s]) => s.source === "bgp_local_as")?.[0];

  function set(name: string, value: string) {
    onChange({ ...values, [name]: value });
  }

  function selectNeighbor(name: string, addr: string) {
    const next = { ...values, [name]: addr };
    const peer = peers.find((p) => p.peer_remote_addr === addr);
    if (peer?.local_as != null) {
      for (const [pname, spec] of Object.entries(schema)) {
        if (spec.source === "bgp_local_as") next[pname] = String(peer.local_as);
      }
    }
    onChange(next);
  }

  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {Object.entries(schema).map(([name, spec]) => {
        const label = (
          <>
            {spec.label ?? name} <span className="text-muted-foreground">({spec.type})</span>
          </>
        );

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
                {shown.map((p) => (
                  <option key={p.id} value={p.peer_remote_addr}>
                    {p.peer_remote_addr}
                    {p.peer_remote_as ? ` · AS${p.peer_remote_as}` : ""}
                    {p.label ? ` · ${p.label}` : ""}
                  </option>
                ))}
              </select>
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
