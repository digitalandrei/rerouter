---
name: ddos-mitigation
description: Domain knowledge for DDoS detection and traffic rerouting — attack types, detection signals, and the mitigation methods Rerouter actually uses (Cisco IOS over SSH: Null0 null-route, tagged-Null0 RTBH the router redistributes upstream, BGP neighbor shut/no-shut). Use when designing detection rules or reroute templates.
---

# Skill: DDoS mitigation & rerouting

Domain background so detection rules and reroute templates match how attacks
actually behave **and** what Rerouter can actually do. Pair with
[bgp-reroute-safety](bgp-reroute-safety.md) and
[traffic-telemetry](traffic-telemetry.md).

> Rerouter does **not** speak BGP and has **no** FlowSpec / scrubber / Cloudflare
> mitigation path. Every mitigation is a Cisco **IOS command over SSH** via a
> validated template. Cloudflare only fronts the app's own UI/API.

## Attack types & signals

| Attack | Primary signal | Notes |
| --- | --- | --- |
| Volumetric flood (UDP/ICMP) | high rx_bps, high rx_pps, high `rx_util_percent` | saturates the link; Null0 / RTBH the target |
| Amplification (DNS/NTP/SSDP/memcached) | high rx_bps; flow shows src ports 53/123/1900/11211 | spoofed sources; needs flow (NetFlow) to see ports |
| SYN flood | high pps, small packets; flow shows TCP-SYN heavy | exhausts state; RTBH the target if the link is at risk |
| Connection/HTTP flood | high pps to an L7 service | L7 detail needs flow; v1's on-router actions are L3 |
| Carpet bombing | bps/pps spread across a whole prefix | per-/32 Null0 is ineffective; blackhole the aggregate prefix (within RTBH limits) |

What you see depends on the source. **SNMP interface polling** (the v1 source)
gives per-interface **volume** only (bps/pps/util/errors) — not per-source or
per-port composition. The **passive NetFlow v9/sFlow collector** (second source,
off by default) adds per-tuple detail: top talkers, top ports/protocols, top source
ASNs — that is where amplification src-ports and attack composition become
visible.

## Mitigation methods (what v1 can do)

All are `device_cli` / `ios_ssh` templates over SSH — see
[bgp-reroute-safety](bgp-reroute-safety.md):

1. **Local Null0 null-route** (`null_route_prefix`) — `ip route … Null0`. Drops
   all traffic to a destination subprefix **on that router**. Narrowest install,
   but only protects the local link; the destination is offline locally.
2. **Tagged-Null0 RTBH** (`blackhole_prefix`) — installs a tagged Null0 static
   that the router's **own** route-map redistributes into BGP with the blackhole
   community, so upstreams drop the prefix at their edge. The victim is fully
   offline upstream; this protects the *rest* of the network. Requires the RTBH
   route-map to already exist on the router.
3. **BGP neighbor shut / no-shut** (`bgp_session_disable` / `bgp_session_enable`)
   — administratively down/up a neighbor in the router's BGP config, e.g. drop an
   attacked transit or bring up a diversion session.

There is **no** L7/WAF, FlowSpec surgical drop, rate-limit, or scrubbing-diversion
template in v1 — those belonged to the de-scoped provider model. If a situation
needs one, alert and handle it out-of-band; do not present it as an in-product
action.

## Choosing a response

- Prefer the **narrowest** action that stops the link/interface damage. Local Null0
  before upstream RTBH where the local link is the only thing at risk.
- Blackhole completes the attacker's goal for that host — use it to protect the
  *rest* of the network, not the victim. Always pair with an alert.
- Carpet-bombing across a prefix: do **not** loop Null0-ing /32s; blackhole the
  aggregate prefix (within the agreed RTBH length limit).
- Always verify the mitigation took effect via the template's on-router `show`
  read-back (traffic should also drop on the monitored interface) — see
  [bgp-reroute-safety](bgp-reroute-safety.md).

## False-positive guards

- Sustained match (per-rule settle window / consecutive samples for SNMP, a window
  for flow), not a single spike.
- Correct flow **sampling rate** applied before comparing flow-derived rates.
- Flow-triggered automation separately enabled and corroborated by fresh,
  contemporaneous same-interface SNMP volume.
- Suppress traffic rules while a reroute is already active on that device.
- Legit traffic surges (launches, flash crowds) look volumetric — observe mode is
  the default, so a fired rule alerts with the would-run plan; prefer manual
  confirmation for high-blast-radius actions until thresholds are trusted.
