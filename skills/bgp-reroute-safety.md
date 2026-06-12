---
name: bgp-reroute-safety
description: Safe BGP-based rerouting for Rerouter — RTBH blackhole, FlowSpec, and scrubbing diversion via announce/withdraw, with permitted-prefix checks, verification against the BGP feed, rollback, and auto-expiry. Use for any provider that changes routing.
---

# Skill: BGP reroute safety

Guidance for reroute providers that change routing (`bgp_rtbh`, `flowspec`,
`scrubber`). These are the highest-blast-radius actions in Rerouter. Pair with
[../docs/reroute-engine.md](../docs/reroute-engine.md) and the
[reroute-safety-agent](../agents/reroute-safety-agent.md).

## Speaker

- Use a controlled BGP speaker (e.g. ExaBGP as a subprocess, or a vetted Rust BGP
  crate) that the controller drives via a narrow command interface.
- The speaker peers with the upstream that honours your blackhole community /
  FlowSpec. The controller never crafts arbitrary BGP by free text.

## RTBH blackhole

- Announce the victim host route (`/32` or `/128`) tagged with the agreed
  **blackhole community**; the upstream drops it at its edge.
- **Permitted-prefix check**: refuse to announce anything outside the provider's
  `permitted_prefixes`, and refuse prefixes shorter than the agreed max (never
  blackhole an aggregate by mistake).
- Effect: the victim host is fully offline. This protects the rest of the network,
  not the victim. Always alert and prefer **auto-expiry** so it lifts when the
  attack ends unless renewed.

## FlowSpec

- Match `{src, dst, proto, port}` and apply drop or rate-limit upstream — surgical
  and keeps the host online.
- Validate the match is specific enough; a too-broad FlowSpec rule is its own
  outage. Confirm the upstream supports the action before relying on it.

## Scrubbing diversion

- Announce the prefix to the scrubber and accept the cleaned return path.
- Verify **both** the diversion announcement *and* a healthy return path before
  declaring success — a half-applied divert is a black hole.

## Verification (mandatory)

Read the **BGP feed** (see [traffic-telemetry](traffic-telemetry.md)) back:

- blackhole: the `/32` with the blackhole community is present; asset bps drops at
  the edge;
- withdraw: the announcement is gone;
- divert: announced to the scrubber and return path healthy.

If the feed cannot confirm the intended end-state, the action is `uncertain`:
lock the asset, disable automatic actions for it, alert, require admin ack.

## Rollback & expiry

Every routing change has a rollback (`withdraw_blackhole_prefix`,
`flowspec_remove_rule`, `stop_diversion`) that is itself audited and verified.
Prefer `auto_expiry_seconds` on blackholes so a forgotten mitigation self-clears.

## Gate checklist (every routing action)

- target within `permitted_prefixes` and length limits ✔
- provider `actions_enabled` and reachable ✔
- asset not locked, no active cooldown, no running action, no `uncertain` ✔
- automatic only if global + per-rule enabled; manual high-level only with re-auth
  + typed confirmation + reason ✔
- state persisted before/after; verification planned; rollback defined ✔
