---
name: bgp-reroute-safety
description: Safe routing-change mitigations for Rerouter — Cisco IOS over SSH (Null0 null-route, tagged-Null0 RTBH the router redistributes upstream, and BGP neighbor shut/no-shut), with parameter validation, on-router read-back verification, rollback, and locks. Use for any reroute that changes routing.
---

# Skill: Routing-change reroute safety

Guidance for reroutes that change routing. These are the highest-blast-radius
actions in Rerouter. Pair with [reroute-engine.md](../../docs/reroute-engine.md)
and the [reroute-safety-agent](../agents/reroute-safety-agent.md).

> **The controller does NOT speak BGP.** There is no ExaBGP/BGP speaker, no
> FlowSpec, and no scrubber/Cloudflare adapter in v1. Every mitigation is a Cisco
> **IOS CLI command pushed over SSH** (`backend-rust/src/ssh/`) from a validated
> **template** (`provider_type = device_cli`, `mode = ios_ssh`). Any upstream BGP
> effect comes from **the router's own config** (a route-map redistributing a
> tagged Null0 static into BGP, or a neighbor being shut), not from the
> controller announcing routes. The `bgp_rtbh` / `flowspec` / `scrubber` provider
> types are de-scoped legacy enum values with no executor behind them.

## Mitigations (shipped device_cli templates)

### Local null-route (Null0)

- `null_route_prefix` — `ip route {target_net} {target_mask} Null0`. Drops **all**
  traffic to the destination subprefix **on this router**. Stops collateral damage
  to the local link, but the destination is offline locally.
- Rollback: `null_route_withdraw` (`no ip route … Null0`).

### Tagged-Null0 RTBH (dropped upstream)

- `blackhole_prefix` — `ip route {prefix_net} {prefix_mask} Null0 tag {tag}`. The
  router's **own** RTBH route-map matches the tag and redistributes the static into
  BGP with the agreed blackhole community, so upstreams drop the prefix at **their**
  edge (true RTBH). The controller only installs the tagged static over SSH; it
  never originates the BGP advertisement itself.
- **Requires the route-map to already exist on the router.** If the tag isn't
  matched, you get only a local black hole, not upstream RTBH.
- Effect: the host/prefix is fully offline upstream. This protects the rest of the
  network, not the victim. Always alert.
- Rollback: `blackhole_withdraw` (`no ip route … Null0 tag {tag}`).

### BGP neighbor shut / no-shut (router config)

- `bgp_session_disable` — `router bgp {local_asn}` ; `neighbor {neighbor_ip}
  shutdown`. Administratively downs a neighbor (e.g. to stop accepting an attacked
  transit, or to pull a diversion session).
- `bgp_session_enable` — the inverse (`no neighbor … shutdown`), e.g. bring up a
  GRE scrubber session so the router announces and traffic diverts.
- These edit **neighbor state in the router's BGP config** over SSH. The
  controller is not a BGP peer.

## Parameters are typed, never free text

The template renderer substitutes only **type-checked** parameter values
(`ip` / `cidr` / `asn` / `int`); a `cidr` param `X` also exposes `{X_net}` /
`{X_mask}`. Validated values contain no whitespace or newlines, so no extra
commands can be smuggled into the line. The device-CLI layer additionally enforces
a **fail-closed allowlist** covering only the catalogued `show`, Null0 route,
BGP neighbor/prefix-list/route-map, and interface command shapes. Variable
tokens and output-filter syntax are independently constrained. Refuse a prefix
shorter than your agreed RTBH max so an
aggregate is never blackholed by mistake (enforce this in the template/parameter
constraints, not by trusting the operator).

## Verification (mandatory) — on-router read-back

Verification opens a **separate read-only SSH session** and runs the template's
`verification_json` `show`; it passes iff the expected substring is present **and**
the reject substring is absent (case-insensitive). v1 verifies against the router,
**not** a BGP feed:

- null-route / blackhole installed: `show ip route {net}` → expect `Null0`;
- withdraw: `show ip route {net}` → reject `Null0`;
- neighbor down: `show ip bgp neighbors {ip}` → expect `Administratively shut`;
- neighbor up: `show ip bgp neighbors {ip}` → expect `BGP state`, reject
  `Administratively shut`.

If the read-back cannot confirm the intended end-state, the action is `uncertain`:
**lock the device**, disable automatic actions for it, alert, require admin ack.

## Rollback

Every disruptive template is paired with its inverse via `rollback_template_id`
(`null_route_withdraw`, `blackhole_withdraw`, `bgp_session_enable`). Rollback runs
through the same SSH path and is itself verified by read-back and audited. There is
no auto-expiry timer in v1 (that mechanism was de-scoped) — a forgotten mitigation
is cleared by an operator rollback or by recovery rules, not by a self-clearing
timer.

## Gate checklist (every routing action)

- parameters type-checked; line passes the device-CLI allowlist; prefix length
  within the agreed RTBH limit ✔
- operating mode is `enforce` (observe renders the would-run plan and executes
  nothing) ✔
- target device not locked, no active cooldown, no running action, no `uncertain` ✔
- automatic only if global enable, per-rule enable, and the selected template's
  `automatic_allowed` policy all permit it; interface shutdown/no-shutdown and
  route-map changes remain manual-only ✔
- manual actions, rule applies, and rollbacks require the matching server-issued
  one-use preview token for the exact rendered plan; manual also requires the
  `trigger_manual_reroute` permission ✔
- discovered routing inventory is fresh; the prefix is within an announced
  prefix, peer parameters match discovery, and RTBH tags match the catalog ✔
- state persisted before/after each step; read-back verification planned; rollback
  template defined ✔
