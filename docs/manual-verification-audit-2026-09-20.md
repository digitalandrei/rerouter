# Manual verification audit — 20 September 2026

This audit records the software behavior frozen before the owner-controlled
Prolexic test scheduled for 21 September 2026 at 08:00 Europe/Bucharest.

## Release decision

The manual-run UI offers **Configuration only**. **Additional checks** is shown
disabled for a future version. Configuration-only preview and execution are
restricted to enabled routers with pinned SSH identities and the currently approved
`bgp_export_policy_set` and `iface_tcp_adjust_mss` actions. Multi-router action sets
validate every router independently. The preview shows the
exact apply and inverse command lists. BGP advertisements are not verified.

No router command sequence, soft-clear behavior, recovery rule, or migration is
changed for this release.

## Existing action-specific evidence

The engine already has typed checks, but they do not form one uniform “routing
verification” contract:

| Action family | Existing typed evidence |
| --- | --- |
| IPv4/IPv6 Null0 route | Exact static configuration and exact route resolution to Null0 |
| RTBH route | Static configuration, Null0 resolution, and local BGP route/community |
| Per-peer prefix advertisement | Exact prefix-list state, Established neighbor, and exact advertised prefix |
| BGP export-policy attachment | Exact attachment and policy definitions; optional routing mode proves selected advertised prefixes, but arbitrary route-map attributes are not fully inferred |
| Generic route-map set/unset | Exact route-map attachment only; resulting route attributes/reachability are not proved |
| BGP session enable/disable | Exact shutdown configuration and local neighbor session state |
| Interface shutdown/no-shutdown | Exact interface configuration and local administrative state |
| Interface MSS | Exact MSS configuration only |

Because these guarantees differ, a generic **Routing verification** choice would
misrepresent some actions. A future UI must derive and show the evidence contract
from the prepared actions themselves.

## Failure and rollback behavior

- A refusal before any write is a proven no-effect failure.
- When a later action fails without writing, earlier successful siblings can be
  compensated in reverse order under the bundle failure policy.
- When commands may have run but the resulting state cannot be proved, the
  effect is unknown. The bundle is quarantined and the controller does not issue
  a blind inverse. This includes a failed configuration read-back after a
  configuration-only write.
- A fresh manual recovery preview remains available once exact ownership and
  current state can be proved.

Therefore “additional verification failed” cannot promise automatic rollback
without first separating proven configuration ownership from the missing
operational evidence and defining a safe inverse precondition.

## Current BGP refresh behavior

- Per-peer advertisement and outbound export-policy changes run
  `clear ip bgp <peer> soft out`.
- Generic route-map changes soft-refresh only the direction changed.
- Session enable/disable changes the session itself and does not add a soft
  clear.
- Static/RTBH actions do not name a peer and do not clear every BGP neighbor.

Running both inbound and outbound refreshes for every BGP-related action is
deferred. It adds control-plane work, is redundant for several actions, and can
fail against a down session. It requires exact-image capability and load testing
before use on the live ASRs.

## Future completion gates

1. Generate operator-facing evidence labels from each prepared action.
2. Add route-map outcome proof only for semantics the parser can determine
   exactly; leave arbitrary policies explicitly unproved.
3. Separate “configuration definitely changed” from “operational outcome did
   not converge” before defining any automatic inverse behavior.
4. Certify any expanded soft-clear contract on the exact enrolled ASR images.
5. Replay apply, failed verification, compensation, and revert for every action
   family before enabling **Additional checks**.
