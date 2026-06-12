---
name: ddos-mitigation
description: Domain knowledge for DDoS detection and traffic rerouting — attack types, detection signals, and the mitigation methods Rerouter uses (Cloudflare under-attack, RTBH blackhole, FlowSpec, scrubbing diversion). Use when designing detection rules or reroute templates.
---

# Skill: DDoS mitigation & rerouting

Domain background so detection rules and reroute templates match how attacks
actually behave. Pair with [bgp-reroute-safety](bgp-reroute-safety.md) and
[traffic-telemetry](traffic-telemetry.md).

## Attack types & signals

| Attack | Primary signal | Notes |
| --- | --- | --- |
| Volumetric flood (UDP/ICMP) | high rx_bps, high rx_pps | saturates the link; blackhole/scrub |
| Amplification (DNS/NTP/SSDP/memcached) | high rx_bps from src ports 53/123/1900/11211 | spoofed sources; FlowSpec by src-port |
| SYN flood | high syn_rate, low syn_ack_ratio | exhausts state; rate-limit / under-attack |
| Connection/HTTP flood | high new_conns_per_sec, high request rate | L7; Cloudflare under-attack / rate-limit |
| Carpet bombing | bps/pps spread across a whole prefix | per-/32 blackhole is ineffective; scrub the prefix |

## Mitigation methods (blast radius, low → high)

1. **Cloudflare Under-Attack mode / firewall / rate-limit** — L7, easily
   reversible, narrowest blast radius. First choice for fronted assets.
2. **FlowSpec drop / rate-limit** — surgical `{src,dst,proto,port}` drop at the
   upstream; good for amplification when you can match the signature.
3. **RTBH blackhole (/32, /128)** — drops *all* traffic to the victim host at the
   edge. Stops collateral damage to the link, but the victim is fully offline.
   Use for a single targeted host when the link is at risk.
4. **Scrubbing-center diversion** — announce the prefix to a scrubber, take the
   cleaned return path. Highest complexity; keeps the victim online.

## Choosing a response

- Prefer the **narrowest** mitigation that stops the link/asset damage.
- Blackhole completes the attacker's goal for that host — use it to protect the
  *rest* of the network, not the victim. Always pair with an alert and, ideally,
  auto-expiry so it lifts when the attack subsides.
- Carpet-bombing across a prefix: do **not** loop blackholing /32s; divert/scrub
  the aggregate.
- Always verify the mitigation took effect (traffic drop at edge / zone state /
  installed rule) — see [bgp-reroute-safety](bgp-reroute-safety.md).

## False-positive guards

- Sustained match (duration / consecutive samples), not a single spike.
- Correct flow sampling rate applied before threshold comparison.
- Suppress traffic rules while a reroute is already active on the asset.
- Legit traffic surges (launches, flash crowds) look volumetric — prefer alert +
  manual confirmation for high-blast-radius actions until baselines are trusted.
