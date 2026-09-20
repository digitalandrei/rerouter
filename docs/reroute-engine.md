# Reroute Engine

The September 17 execution contract is described in
[Manual Mitigations and safe action sets](manual-mitigations.md). Named manual
sets, Rules, and corrective runs now share immutable preparation, consumed
preview authority, native exclusive locks, exact typed verification, and durable
mutation ownership. These requirements supersede older descriptions below of
substring-only verification, unprepared single-action execution, deferred
apply-time preview sequences, and per-device-only compensation. Uncertainty
freezes the whole set; no-op actions never own an inverse.

Reroutes are controlled, audited mitigations that move traffic. This is the most
dangerous part of the system. Everything here exists to make reroutes slow,
explicit, reversible, and blocked whenever state is uncertain.

## Operating mode (observe vs enforce)

The engine sits behind a global operating mode
(`system_settings.operating_mode`):

- **`observe`** — the shipped default. Safe read-only / alert-only: **nothing
  executes, automatic or manual**. When a rule fires, the engine renders the
  rule's attached actions (its `rule_actions` rows — each a template + target
  router + parameters) to their exact would-run commands and attaches that plan to
  the rule event and the email alert. This lets operators validate thresholds and
  templates against live traffic with zero risk.
- **`enforce`** — execution allowed, still subject to every gate below.

Flipping the mode is admin-only, audited, and itself alerted. The mode is
**gate 0**: it is checked before any other gate on every execution path.

## Reroutes are templates, never free text

There is **no** "run this route command" box in v1. Every reroute is an
allowlisted **action template** with a parameter schema. Arbitrary execution is
not a feature.

### Template definition

Each template defines:

- `name`, `description`;
- `provider_type` — only `device_cli` executes in v1 (the Cisco-IOS-over-SSH
  engine in `backend-rust/src/ssh/`). The legacy `cloudflare` / `bgp_rtbh` /
  `flowspec` / `scrubber` provider adapters were de-scoped; the enum value still
  exists but no executor backs it;
- `mode` — `ios_ssh` for the device-CLI templates;
- parameter schema (typed, validated: `ip` / `cidr` / `asn` / `int`);
- `automatic_allowed` (bool);
- `plan_json` — the exact commands to push (see shape below);
- `verification_json` — the read-back `show` check (see shape below);
- optional `rollback_template` (how to undo).

`automatic_allowed` is enforced, not descriptive metadata. New templates start
manual-only. Route-map changes and interface shutdown/no-shutdown remain
manual-only; only the explicitly seeded allowlist may run from an automatic rule.

### Plan / verification shape (device_cli)

Every `device_cli` template stores its commands as JSON, not free text:

```text
plan_json:         {"transport":"ios_ssh","config_mode":true,"apply":["<cmd with {param}>"]}
verification_json: {"method":"ios_show","command":"<show {param}>","expect":<substr present>,"reject":<substr absent>}
```

The renderer substitutes only type-checked parameter values. A `cidr` param `X`
also exposes `{X_net}` and `{X_mask}` (validated values contain no whitespace or
newlines, so extra commands cannot be smuggled in). Verification opens a
*separate* read-only session, runs the `show`, and passes iff `expect` is present
**and** `reject` is absent (case-insensitive substring).

### Shipped catalog (all `device_cli` / `ios_ssh`)

```text
null_route_prefix     ip route {target_net} {target_mask} Null0
                      Local Null0 black hole of a destination subprefix. Drops
                      ALL traffic to it on this router.
                      verify: show ip route {target_net} -> expect "Null0"
                      rollback: null_route_withdraw

null_route_withdraw   no ip route {target_net} {target_mask} Null0
                      verify: show ip route {target_net} -> reject "Null0"

blackhole_prefix      ip route {prefix_net} {prefix_mask} Null0 tag {tag}
                      Tagged Null0 static the router's RTBH route-map
                      redistributes into BGP with the blackhole community, so the
                      prefix is dropped UPSTREAM (true RTBH). Needs a route-map
                      matching the tag.
                      verify: show ip route {prefix_net} -> expect "Null0"
                      rollback: blackhole_withdraw

blackhole_withdraw    no ip route {prefix_net} {prefix_mask} Null0 tag {tag}
                      verify: show ip route {prefix_net} -> reject "Null0"

null_route_prefix_v6 / null_route_withdraw_v6
blackhole_prefix_v6 / blackhole_withdraw_v6
                      IPv6 siblings of the four templates above, using
                      `ipv6 route {prefix} Null0 [tag {tag}]` and `/128` host
                      auto-targets. Verification uses `show ipv6 route`.

bgp_session_enable    router bgp {local_asn} ; no neighbor {neighbor_ip} shutdown
                      Bring a BGP neighbor up — e.g. start the GRE scrubber
                      session so routes announce and traffic diverts.
                      verify: show ip bgp neighbors {neighbor_ip}
                              -> expect "BGP state", reject "Administratively shut"
                      rollback: bgp_session_disable

bgp_session_disable   router bgp {local_asn} ; neighbor {neighbor_ip} shutdown
                      verify: show ip bgp neighbors {neighbor_ip}
                              -> expect "Administratively shut"

bgp_advertise_add     ip prefix-list {prefix_list_name} seq {sequence}
                                    permit {prefix}
                      exec_after: clear ip bgp {neighbor_ip} soft out
                      Advertise a prefix toward ONE upstream peer by adding it to
                      that peer's outbound route-map prefix-list at an EXPLICIT
                      sequence number, then soft-clear outbound. See "Sequenced
                      prefix-list insertion" below — {sequence} is resolved at
                      apply time and is never operator input.
                      The prefix-list name is DISCOVERED per peer and
                      offered read-only by the `peer_out_prefix_list` picker; it
                      is never typed (IOS silently CREATES an unknown list, so a
                      wrong name would advertise nothing yet report success).
                      Discovery order of precedence:
                        1. neighbor <ip> prefix-list NAME out
                        2. neighbor <group> prefix-list NAME out (peer-group)
                        3. neighbor <ip> route-map RM out -> RM's permit stanza
                           `match ip address prefix-list PL`
                        4. neighbor <group> route-map RM out -> same, inherited
                      Only a name that exists as a real `ip prefix-list` stanza is
                      stored, and a route-map that does not yield exactly ONE
                      permit-stanza list (several lists, a `continue`, a deny
                      stanza keyed on a prefix-list) yields NOTHING. Freshness
                      comes from `device_bgp_peers.route_context_discovered_at`.
                      verify: show ip bgp neighbors {neighbor_ip} advertised-routes
                              -> expect "{prefix_net}"
                      rollback: bgp_advertise_remove

bgp_advertise_remove  no ip prefix-list {prefix_list_name} seq {sequence}
                                       permit {prefix}
                      exec_after: clear ip bgp {neighbor_ip} soft out
                      Removes EXACTLY one entry. As a rollback it inherits the
                      sequence the add persisted; run standalone it resolves the
                      entry from a fresh read like the add does.
                      verify: show ip bgp neighbors {neighbor_ip} advertised-routes
                              -> reject "{prefix_net}"

bgp_route_map_set     router bgp {local_asn} ; neighbor {neighbor_ip} route-map
                      {route_map} {direction}
                      Restores the exact previously discovered assignment on
                      rollback (or unsets when none existed). Route-map changes
                      are manual-only and require fresh peer/map inventory.

iface_tcp_adjust_mss  interface {interface} ; ip tcp adjust-mss {mss}
                      MSS clamp (default 1436) applied when a rule activates.
                      verify: show running-config interface {interface}
                                      | include ip tcp adjust-mss
                              -> expect "ip tcp adjust-mss {mss}"
                      rollback: iface_tcp_adjust_mss_remove

iface_tcp_adjust_mss_remove
                      interface {interface} ; no ip tcp adjust-mss
                      verify: show running-config interface {interface}
                                      | include ip tcp adjust-mss
                              -> reject "ip tcp adjust-mss"

iface_shutdown        interface {interface} ; shutdown    (DISRUPTIVE)
                      verify: show interfaces {interface}
                              -> expect "administratively down"
                      rollback: iface_no_shutdown
                      manual-only (automatic_allowed = false)
                      Blocked on interfaces flagged `protected` (see below).

iface_no_shutdown     interface {interface} ; no shutdown
                      verify: show interfaces {interface}
                              -> reject "administratively down"
                      manual-only (automatic_allowed = false)
```

`plan_json` supports an optional `exec_after` array — privileged EXEC commands
(e.g. `clear ip bgp <peer> soft out`) that run AFTER the `configure terminal` …
`end` block closes, never inside it. Verification `expect`/`reject` substrings may
reference `{params}` (e.g. `{prefix_net}`), substituted at render time.

Router read-back uses three internal outcomes: matched, proven mismatch, and
unproven. Only a completed, command-specific filtered configuration read may use
an empty body as proof that an object is absent. Empty interface, BGP
advertisement, BGP route, and route-resolution responses are unproven and freeze
the action or inverse. Configuration stanzas and operational responses must name
the requested object. Valid IOS regular-expression filters remain part of the
read command, and a valid object row does not require an image-specific footer.
Multi-row advertisement output may prove absence only when its completion count
matches the parsed rows; a matching row can prove presence without that footer.
Communities and routing next hops are evaluated inside the exact matching route
block. Exact IPv4 configuration filters reject foreign route lines, while the
intentional IPv6 family-wide read may use valid foreign IPv6 rows to prove that
the requested prefix is absent. Legacy template verification recognizes only
the catalog's command families and binds reject-only evidence to that command's
route or interface target.

A **combination** (remove-from-saturated-upstream + advertise-on-others + MSS
clamp) is expressed as several ordered `rule_actions` on one rule — each its own
verification and rollback — not a single composite template. The runtime record
of one authorized activation of such a set is a **bundle** — see
[Ordered mitigation bundles](#ordered-mitigation-bundles).

**Protected-interface guard.** `device_interfaces.protected` flags the device's
management / transit / SSH path. Before executing a template that targets an
interface (`iface_shutdown` or `iface_tcp_adjust_mss`), the executor resolves the
interface and **blocks** if it is protected, returning a `blocked_reason` and
pushing nothing. Corrective inverses (`iface_no_shutdown` and MSS removal) may
restore a protected path. Set the flag via
`PATCH /api/interfaces/{id}/protected` (`manage_devices`). Every command shape
above is also gated by the fail-closed `ssh::command_allowed` allowlist.

Disruptive templates are paired with their inverse via `rollback_template_id`.
The old `cloudflare_under_attack` / `flowspec_drop` / `divert_to_scrubber`
templates were removed when their providers were de-scoped.

### Sequenced prefix-list insertion (`bgp_advertise_add` / `_remove`)

Every outbound prefix-list on a real edge router ends with a terminating deny:

```text
ip prefix-list no-export   seq 10 deny 0.0.0.0/0 le 32
ip prefix-list pfx-to-viva seq  5 permit 194.105.142.0/24
ip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32
```

`ip prefix-list <name> permit <cidr>` with no sequence number makes IOS
auto-assign `highest + 5`, so the new permit lands **after** that deny and is
never reached. The CLI reports success, the router advertises nothing, and only
the post-apply verification catches it — fail-safe, but the feature does not
work. Migration `20260916000400` therefore renders an EXPLICIT sequence.

**How the sequence is chosen** (`reroute::prefix_list`, pure + unit-tested).
The target list is read fresh, at apply time, **inside the SAME SSH session that
pushes the config** (`show ip prefix-list <name>`). From that text:

1. Walk the entries in sequence order and stop at the first one that MATCHES the
   prefix — network bits equal for the entry's length, and the prefix length
   inside the entry's `ge`/`le` range (no qualifiers = exactly that length; `ge`
   alone opens the top to /32; `le` alone opens the bottom to the entry's own
   length).
2. A matching **permit** means the prefix is already advertised through this
   list: **no configuration change**, go straight to verification. If that entry
   is exactly this prefix its sequence is persisted so a rollback can remove
   precisely it; if it is a broader covering entry, no sequence is persisted
   (naming it would have a rollback withdraw more than was asked).
3. A matching **deny** is the shadowing entry. The new permit goes at the
   midpoint of the open interval between the preceding entry's sequence and that
   deny's — e.g. `(5, 10)` → **7**. The midpoint, not `low + 1`, so repeated
   insertions halve the gap instead of exhausting one end.
4. If that interval holds **no free integer** (`seq 5` then `seq 6`, or a
   shadowing deny at `seq 1`), the action **fails closed**: nothing is pushed,
   and the reason names both sequences and tells the operator to renumber the
   prefix-list. Rerouter never renumbers the router's list, never guesses, and
   never falls back to the bare append that caused the original no-op.
5. With **no** shadowing entry the permit still gets an explicit sequence
   (`last + 5`) rather than IOS auto-assignment — determinism the rollback needs.
6. A read that is empty, truncated, denied, malformed, or shows a duplicate
   sequence is a **refusal**, never an assumption that the list is empty.
7. The chosen sequence is checked against the occupied set one last time before
   it is emitted. **On IOS a write that reuses an existing sequence REPLACES that
   entry**, so an occupied number would silently overwrite a live filter entry.

`bgp_advertise_remove` mirrors this: a matching deny (or no match) is a no-op; a
permit that is exactly the prefix is removed by its sequence; a **broader**
permit is refused, because removing it would withdraw prefixes nobody asked
about.

**Why not cached inventory.** The IOS replace-on-reuse behaviour is exactly why
an hour-old snapshot is not good enough: the sequence it names may have been
taken since, and the write would overwrite a live entry. Only a read taken
moments before the write can rule that out.

**Why this is not a discovery run.** It is ONE extra `show` in a session that is
already open — no second connection, no database reconcile, no drift audit.
`discover_prefixes_and_store` and `reroute::inventory_audit` stay off every
trigger path (the lint in `inventory_audit` enforces that), so nothing here can
stall a mitigation behind another SSH handshake during a flood.

**The read is part of the durable record.** `reroute_outputs` stores the
`show ip prefix-list <name>` response as the session's first step, so a
post-incident review can see the list exactly as it looked when the sequence was
chosen.

**Persist before the side effect.** The resolved sequence reaches
`reroutes.parameters_json` (and the re-rendered `planned_steps_json` /
`reroute_steps`) BEFORE the command reaches the router. A crash in between leaves
an `uncertain` reroute that still names the exact entry, and startup recovery
locks the device as usual.

**Rollback is exact, not content-matched.** The rollback inherits the persisted
`sequence` and renders `no ip prefix-list {name} seq {n} permit {cidr}` — full
content included, so IOS refuses it if the entry is not what we wrote. Rollbacks
continue to bypass fresh-inventory validation by design; when the original
persisted no sequence (the broader-entry no-op, or a reroute from before this
change), the rollback simply resolves from its own fresh read, which is always
safe.

**The preview is honest and unsendable.** Until it is resolved, `{sequence}`
renders as the literal `<auto-seq>` and the plan carries `sequence_pending:
true`. That is what an observe-mode preview and the manual-reroute UI show. It is
also not a valid token in any `command_allowed` shape, so a plan that somehow
reached the transport unresolved fails closed at the SSH boundary.

**The read itself is allowlisted and probed.** `show ip prefix-list [<name>]` is
on the `ssh::command_allowed` read set, granted by the RRT parser view
(`deploy/cisco/rerouter-view.ios` and the copy in the device Settings tab), and
checked by the SSH capability probe ("Read prefix-lists") so an
under-privileged account shows up before an incident rather than during one.

## Two-phase state machine

```text
planned -> pending -> running -> verifying -> succeeded
                             \-> failed
                             \-> uncertain
```

Persist state **before and after every step**. `reroute_outputs` stores each
step's command, response, and status. Never treat "command sent" as success:
move to `verifying` and confirm the routing state actually changed.

## Safety gates (checked again at execution time)

Even if a rule fired, the reroute engine re-validates *all* of these before doing
anything. The gates are **device-scoped** (the target of a `device_cli` action is
a router, not an asset/prefix). Any failure aborts and logs:

- **gate 0:** `operating_mode == enforce` — in `observe` mode the engine stops
  here and returns the would-run plan instead (see "Operating mode" above);
- not a dry-run request (dry-run renders the plan only, even in enforce mode);
- no global maintenance lock;
- all inventory-backed values resolve to canonical, fresh device inventory
  (24h for SNMP interface/BGP data, 48h for SSH routing context); Null0/RTBH
  targets must be contained in recently discovered announced space and RTBH tags
  must exist in the approved catalog;
- the target **device** is not locked (an uncertain action or crash recovery
  locks it until acknowledgement);
- no other action is already running on this device;
- no unresolved (`uncertain`) prior action on this device;
- the device is not inside its post-action cooldown window;
- the global action rate limit is not exceeded;
- **control-plane reachability (preflight):** the target device answers **SSH at
  privileged EXEC AND the account can run every command a reroute needs**. A reroute
  pushes config over SSH, so the probe runs the same **command-access checks** as the
  Settings "Check access" panel (`ssh::probe_capabilities`: the config reads + a no-op
  `configure terminal`, changing nothing) — a device that logs in but is denied a
  required command (low privilege / restrictive parser view) is caught here, not
  mid-push. The action is refused up front (`BlockReason::DeviceUnreachable`) rather
  than reserving a slot and failing mid-push. To avoid re-probing a device we just
  talked to (and tripping its SSH connection throttle), a successful SSH contact
  within the last **60 s** (`devices.last_ssh_ok_at`, stamped by the probe and by
  every successful reroute push) passes without opening a new session. This is a hard
  gate on **every** trigger (manual, automatic, rollback). A poll-loop probe
  (`reachability_interval_seconds`, default 3 min) classifies the device into
  `devices.ssh_status` — `reachable` (privileged **and** all command-access checks
  pass) / `no_privilege` (SSH works but the account can't do the work: not privilege
  15, or reached `#` but was denied a required command — `last_ssh_error` names them;
  an actionable config fix, still NOT reroute-usable) / `unreachable` — for display
  and to keep the recency window warm. See `reroute::reachability`;
- **host identity:** first-contact SSH key pinning must commit successfully before
  a configuration action can run; a concurrent or later mismatch fails closed;
- **stability (AUTOMATIC only):** a device must have been *continuously*
  SSH-reachable for the **stability window** (`STABILITY_WINDOW`, 1 min) before
  automatic mitigations targeting it resume — so a just-recovered or flapping
  device is not auto-acted upon. `devices.ssh_reachable_since` is set when SSH
  becomes reachable, cleared on any non-reachable probe **and on controller
  startup** (so the clock restarts after a restart). A reachable-but-not-yet-stable
  device blocks **automatic** triggers (`BlockReason::DeviceStabilizing`); **manual
  and rollback triggers are NOT stability-gated** (the operator may act during the
  window — the UI warns — and a manual rollback is corrective). Detection is
  unaffected: rules still fire and alert; only the mitigation action is gated (its
  `blocked_reason` shows in the fired-rule alert's `executed_actions`);
- for manual: the caller has `trigger_manual_reroute` (enforced by the API before
  it calls the executor), with an optional reason recorded for the audit log. In
  enforce mode the caller must also consume a five-minute, single-use token bound
  to the exact server-rendered plan, audit reason, user, and action scope.

For automatic triggers, the firing edge only auto-executes in enforce mode when
the global switch, rule switch, and template `automatic_allowed` policy are all
on. Prefix containment and fresh inventory are hard gates. Per-action password/
TOTP re-auth and typed-text confirmation remain de-scoped; global arming requires
step-up authentication and manual execution requires the exact-preview token.

## Inventory drift detection & auto-disarm

The gates above catch a router-side change — a prefix-list renamed, a route-map
rewritten, a `network` statement withdrawn — but only *at fire time*, i.e. during
an actual attack. Until then the rule looks healthy and stays armed, and the
operator finds out their mitigation is unusable at the worst possible moment.

A **drift audit** closes that window. Every SSH routing-inventory discovery run
(`ssh::discover_prefixes_and_store`) finishes by re-running the same **read-only**
validators — `templates::canonicalize_inventory_params` and
`templates::prefix_target_is_contained` — over the stored `params_json` of every
enabled `rule_actions` row bound to that device. It executes nothing.

### The rule that governs the whole feature

Auto-disarm may fire **only on a positive, confirmed drift signal**:

1. the discovery read for that device was **conclusive** — every read succeeded,
   none was denied, and the snapshot it produced was reconciled in that run; **and**
2. the stored parameter genuinely no longer validates against the inventory that
   run just reconciled.

It must never fire on an inconclusive, denied, failed or empty-but-unproven read,
on a stale-but-unrefreshed snapshot, or on a database error. This is an
adversarial requirement, not tidiness: anyone who can make a router return an
empty or failing read would otherwise be able to switch off the operator's
automatic mitigations right before a flood.

The conclusive/inconclusive distinction is therefore **threaded out of the
discovery run** as `reroute::inventory_audit::InventoryRead`, never re-derived
from the database — after an inconclusive run the database deliberately looks
exactly as it does after a clean one (the previous snapshot is kept). A read
counts as conclusive only when *both* the `router bgp` section read contained a
`router bgp` stanza *and* the route-map / `ip prefix-list` pair produced a
trustworthy snapshot. A `sqlx` error anywhere in a validator's error chain is
classified `Indeterminate` and decides nothing.

### It never runs on an incident path

Two structural interlocks, both fail-safe:

- **Discovery is never run inline before firing.** The only callers of
  `discover_prefixes_and_store` are the background loop and the operator's
  explicit "Discover prefixes" button. Refreshing inventory just before a
  mitigation would spend incident time on the one resource a volumetric attack
  saturates — the router control plane — where SSH is the first thing to go slow
  (russh inactivity timeout 60 s). Liveness is already covered more cheaply and
  more strictly by the reachability probe and `STABILITY_WINDOW` (above).
- **A device or rule that is mid-incident is skipped entirely.** The audit refuses
  to look at a device with a reroute in flight (`reroutes.state IN
  ('planned','pending','running','verifying')` — the same set the executor's own
  "already running on this device" gate uses), and skips any action whose rule's
  `rule_states.current_state` is not `clear` (i.e. `matching` or `firing`). A
  discovery run that lands while a rule is mitigating therefore cannot disarm the
  rule that is mitigating. It defers and re-checks next run.

### On confirmed drift

In one transaction:

1. `rule_actions.inventory_state = 'drifted'`, `inventory_drift_reason` = the
   concrete validator message, `inventory_checked_at = UTC_TIMESTAMP()`;
2. `rules.automatic_reroute_enabled = 0` plus `auto_disarmed_at` /
   `auto_disarmed_reason`. **Only automatic execution.** `rules.enabled` and
   `alert_enabled` are untouched, so the rule keeps detecting and alerting, and
   manual operator-triggered execution stays available (it still goes through
   preview and the fire-time validation, which refuses it with the same visible
   reason);
3. an audit row (`rule_action_inventory_drift`, plus `rule_auto_disarmed` when a
   rule was actually disarmed) and an alert (`rule_auto_disarmed`, critical and
   always-immediate, or `rule_action_inventory_drift` when the rule was not armed
   in the first place).

Logs: `warn!(event_type = "rule_action_inventory_drift", …)` and
`warn!(event_type = "rule_auto_disarmed", …)`. A repeat audit that finds the same
drift refreshes `inventory_checked_at` but does not re-alert.

### Self-heal, but only halfway

When a later conclusive audit finds the action validates again, `inventory_state`
returns to `'ok'` and the reason is cleared (audited as
`rule_action_inventory_recovered`). **Automatic execution is never re-armed.**
`automatic_reroute_enabled` stays 0 and the `auto_disarmed_*` record stays as the
explanation until a human re-arms it through the normal gate — global enable plus
step-up re-authentication. `PATCH /api/rules/{id}` additionally **refuses** to
re-arm a rule while any of its enabled actions is still marked `drifted` (the
executor would refuse them anyway): fix the action or the router, then let the
hourly run — or the "Discover prefixes" button, which runs the same audit
immediately — clear the marker. A successful re-arm clears `auto_disarmed_at` /
`auto_disarmed_reason`.

### Silent expiry

`ROUTING_INVENTORY_MAX_AGE_HOURS` is 48 h. Discovery therefore runs **hourly**
(`scheduler::PREFIX_DISCOVERY_INTERVAL`, plus a random per-device delay of up to 5
minutes so a fleet does not open SSH to every router in the same second, and the
existing 2-minute post-boot settle delay). At the old daily cadence **two**
consecutive failed runs silently aged the route context out and every dependent
action started being refused at fire time with nobody told; hourly it takes ~48,
and the expiry alert has many chances to page first.

Independently of the drift audit — and deliberately **also on an inconclusive
read**, which is exactly the case that matters — each run checks the freshness
marker each dependent source is actually gated on
(`device_bgp_peers.route_context_discovered_at`,
`device_route_maps.last_discovered_at`, `device_bgp_networks.last_discovered_at`)
against that window, for the sources this device's enabled rules really use. If
any has aged out it raises a critical `routing_inventory_expired` alert naming the
device, the expired markers and the dependent rules. Expiry **never disarms**: the
router never said anything, so nothing may be concluded from it.

## Cooldowns & rate limit

Three throttles are enforced by the executor, all config-driven (`[safety]`):

```text
same_device_cooldown_seconds      300   per-device: after any action on a device,
                                          it is in cooldown before the next one
same_rule_cooldown_seconds        900   per-rule: after a rule's actions run, that
                                          rule is throttled (rule-triggered only)
global_action_rate_limit_count      3   global circuit breaker: at most N executed
  / _window_seconds               600     actions per rolling window, all devices
```

Per-device and per-rule cooldowns are recorded in the `cooldowns` table
(scope `device` / `rule`); the global limit counts actual `reroutes` rows in the
window. Set any value to `0` (cooldowns) or the count to `0` (rate limit) to
disable that throttle. These apply to manual and automatic actions. Corrective
rollback bypasses cooldown/rate throttles but still obeys mode, maintenance and
device locks, reachability, serialization, persistence, and verification.

Inside an **ordered bundle** these throttles are scoped, never waived. The
cooldown fallback derived from durable history excludes *only* previously
authorized siblings of the same `bundle_id`, because those are one activation the
operator previewed and confirmed once; every unrelated device or rule cooldown
still applies, and an explicit `cooldowns` row is never bypassed. The global rate
limit keeps per-action accounting, but a bundle reserves its full size up front
and is refused whole if it does not fit. See
[Ordered mitigation bundles](#ordered-mitigation-bundles).

## Locks

Lock scopes: the device-CLI engine uses the `device` scope (and `global`). Locks
can be manual, automatic after crash recovery, or automatic after action
uncertainty. A
locked scope blocks all reroutes touching it until cleared (exact reconciliation for
safety-induced locks).

## Manual reroutes

Manual reroutes are first-class:

```text
1. User selects a reroute template and one or more target routers (devices).
2. User fills parameters per target (guided by ASN / neighbor / prefix / RTBH
   pickers; the scrubber neighbor IP, say, can differ per router).
3. SPA asks the execution endpoint for the exact would-run commands,
   verification, and rollback plan per target.
4. In enforce mode the API stores a five-minute hash of that plan and returns a
   one-time preview token. Execute must present it; the server renders a fresh
   plan and atomically consumes the token only when the plan is unchanged.
5. The Rust API checks `trigger_manual_reroute` and records the optional reason.
6. For each target the controller re-checks all device-scoped safety gates and
   runs the executor independently (multi-router fan-out; one device locked or in
   cooldown is skipped without blocking the others).
7. Controller persists the planned row, audit, and started alert before SSH, then
   pushes config while capturing every step's output.
8. Controller verifies the resulting state with a read-only `show`.
9. UI shows result + raw output; the audit log records everything; configured
   email/Teams deliveries are queued asynchronously.
```

Manual reroutes support **dry-run**: render the exact plan without changing any
routing (in observe mode every trigger behaves this way regardless).

### Run a rule's defined mitigation manually (supervised path)

Between alert-only and unattended automatic execution there is a supervised
middle ground: an operator manually runs a rule's own configured actions from
its detail page. Active alerts and the dashboard provide shortcuts while firing.
`POST /api/rules/{id}/apply` is opt-in per rule (`rules.manual_apply_enabled`,
default off, set in the rule editor) and requires at least one defined action. It runs each
enabled `rule_action` through the *same* gated executor as a `manual` trigger
attributed to the operator, so it inherits every protection: exact preview and
confirmation in both operating modes, `trigger_manual_reroute`,
and honours device locks, the global maintenance lock, per-device and per-rule
cooldowns, the rate limit, and the protected-interface guard. Because the trigger
is `manual`, the global **automatic** master switch does not gate it — this is a
deliberate operator action — but `rule_id` is set, so the per-rule cooldown still
applies. This is distinct from `automatic_reroute_enabled` (hands-off execution
on the firing edge); a rule may enable either, both, or neither.

In enforce mode this path also requires a server-rendered dry run and consumes a
five-minute one-use preview token bound to the action set, reason, rule, and
operator before execution. A **confirmed enforce-mode apply runs asynchronously
as one ordered bundle** and returns `202` with a `bundle_id`; the preview and
observe-mode responses are unchanged. See
[Ordered mitigation bundles](#ordered-mitigation-bundles).

### Flow auto-target (derive the host from flow data)

A null-route / blackhole action on a **flow rule** (e.g. TCP dport 443) can be
marked **auto-target** (`rule_actions.auto_target = 'flow_dst_host'`) instead of
carrying a fixed prefix. At fire / apply time the engine resolves the heaviest
**destination** IP in the matching flows (the rule's interface + direction +
protocol + port selector, over a short recent window) and null-routes it as a
`/32` (IPv4) or `/128` (IPv6). The IPv4 host reuses `null_route_prefix` /
`blackhole_prefix`; an IPv6 victim swaps to the template's `v6_sibling_template_id`
(`null_route_prefix_v6`), since IPv6 uses `ipv6 route <pfx>/128 Null0` and the
renderer is family-aware (a `cidr` param pinned `family:"v6"`).

Guardrails (see [flow-telemetry.md](flow-telemetry.md)):

- **Containment** — the resolved host MUST fall inside one of the null-route
  device's announced prefixes (`device_bgp_networks`); otherwise the action is
  skipped (never executed). If the device has no discovered prefixes, auto-target
  refuses and asks for prefix discovery. We only ever black-hole our own space.
- **Sampling confidence** — a LOW-confidence flow reading **blocks automatic**
  execution (doctrine); a manual apply still proceeds (the operator sees the
  resolved IP). Either way the resolved host is rendered into the would-run plan
  before anything runs.
- **Source corroboration** — flow auto additionally requires its separate config
  switch, an enrolled exporter source, and a contemporaneous same-interface SNMP
  sample within the configured ratio band. Network ACL/uRPF protection is still
  required because UDP source allowlisting is not cryptographic identity.
- Auto-target is only attachable to a flow rule + a host-route template (enforced
  by the API); the prefix param is resolved, not typed.

## Rollback

Every disruptive template defines a rollback (its paired inverse, via
`rollback_template_id`). A mitigation lifts only via an explicit rollback — there
is **no** auto-expiry / self-clearing after N minutes (de-scoped: a template
describes *what* it does, not how long it lasts). Rollback runs against the same
device + parameters as a fresh audited action, with its own verification, exposed
as `POST /api/reroutes/{id}/rollback`. The original must have reached execution;
cancelled/pre-command failures cannot be rolled back. A server-rendered dry run
and one-time preview token are mandatory in enforce mode. Rollbacks are
serialized per original action, reject an active/already-successful sibling, and
permit a retry only after a failed rollback.

## Ordered mitigation bundles

A real mitigation is rarely one command. Diverting an attacked prefix to a
scrubbing provider means advertising it to the scrubber on every border router
**and** withdrawing it from the saturated upstreams — a dozen-plus actions the
operator previewed and confirmed once. As above, that combination is the rule's
ordered `rule_actions` set, never a composite template. A **bundle** is the
runtime record of one authorized activation of that set: one preview, one
confirmation, one audited unit of work.

Both paths that activate a rule's whole action set form a bundle: the
**supervised apply** (a confirmed enforce-mode `POST /api/rules/{id}/apply`) and
**unattended automatic activation**. An automatic activation is one authorized
decision too, so it gets the same identity, ordering, all-or-nothing admission and
compensation — otherwise the first action's cooldown would block the rest of an
unattended mitigation, and a mid-activation failure would leave the network
half-diverted with nobody watching.

The bundle's `trigger_type` (`manual` or `automatic`) is what selects which gates
apply: `guard::decide` enforces the `automatic_actions_enabled` master switch and
verify-or-refuse **only** for `automatic`. It is threaded through the runner
explicitly, never defaulted, because running an automatic activation under
`manual` would silently bypass the master switch. Automatic execution remains
gated as before — enforce mode, the global switch, and the per-rule enable — and
`LOW` flow-sampling confidence still suppresses an action before the bundle is
built.

### Bundle identity

`reroute_bundles` holds one row per activation; every sibling `reroutes` row
carries `bundle_id` and `bundle_position` (copied from `rule_actions.position`,
so durable history keeps the order actually used even if the rule is edited
afterwards).

The identity exists to scope cooldowns. The guard derives a cooldown from
`MAX(reroutes.started_at)` per rule and per device as a fallback, which counted
the bundle's own first sibling as "a recent action" and blocked the remaining
thirteen (audit finding SPEC-13). Cooldown history now excludes **only**
previously authorized siblings of the same `bundle_id`. Nothing else is exempt:
an unrelated activation on the same rule or device throttles exactly as before,
and an explicit `cooldowns` row is never bypassed. A bundle defers its cooldown
rows until the whole batch is finished, then records one per device it actually
touched — including devices whose sibling failed, because a failed push may still
have changed the box.

### Admission is all-or-nothing

The global rate limit keeps **per-action** accounting — a 14-action bundle costs
14 — but the budget is reserved atomically before anything runs
(`guard::admit_bundle`, under the global advisory lock). Capacity that other
in-flight bundles have reserved but not yet spent counts too, so two concurrent
bundles cannot both be admitted against the same free budget. A bundle that does
not fit is refused **whole**, with nothing executed — the apply returns
`409 {"error":"bundle_not_admitted"}` and the bundle row is closed as `failed`.
Spending the budget mid-bundle is how a mitigation ends up half-applied.

The shipped default `global_action_rate_limit_count = 3` is **not** changed by
this feature. A deployment that runs bundles larger than the budget must raise it
deliberately — see [operations-runbook.md](operations-runbook.md).

### Ordered execution and failure policy

Siblings execute sequentially in `position` order. `reroute_bundles.failure_policy`
decides what happens at the first non-success:

```text
abort_and_compensate  stop, then roll back the siblings that already succeeded,
                      in reverse order (default for new operator bundles)
abort                 stop, leave applied siblings in place for the operator
continue              historical best-effort fan-out: keep going (preserved for
                      callers that want independent per-device attempts)
```

**Execution order is a safety property, not a display preference.** The safe
order is additive first, destructive last: advertise the prefix to the scrubber
**before** withdrawing it from the ISP upstreams. Under `abort_and_compensate` a
failure anywhere in the additive phase then aborts *before* anything is torn
down, so the black-hole window never opens. The reverse order can withdraw the
traffic's only remaining path and then fail to provide the new one.

`POST /api/rules/{rule_id}/actions/reorder` (`edit_rules`, body
`{"order": [action_id, ...]}`) renumbers `position` for the whole set in one
transaction. The submitted list must be exactly that rule's action set — any
missing, duplicated, or foreign id is rejected whole — so a stale editor cannot
silently drop an action, which would silently shorten a mitigation.

### Compensation, and where it stops

Under `abort_and_compensate` the siblings that own proven mutations are rolled back in
reverse order as ordinary `trigger_type = rollback` actions: each one is a fresh
audited, verified reroute, exempt from cooldown and rate throttles like any
corrective rollback, and still subject to mode, maintenance, and device locks.

**Uncertainty freezes the entire set.** A sibling that ends `uncertain`
retains ownership and prevents all further apply or compensation commands,
including commands on another device. The bundle then finishes
`compensation_blocked`: a **critical** `reroute_bundle_partial` alert plus an
audit row name known-applied and ambiguous reroutes. An authorized operator
reconciles recorded state and previews recovery (see [operations-runbook.md](operations-runbook.md)). A
sibling whose template has no rollback, or whose rollback itself fails, ends the
same way. Reporting a half-applied mitigation loudly beats forcing config onto a
device whose state could not be read; it is never silently retried.

Bundle states:

```text
planned              admitted, nothing executed yet
running              at least one sibling has started
succeeded            every sibling succeeded
aborted              stopped at a non-success; applied siblings left in place
compensating         rolling back applied siblings
compensated          applied siblings rolled back; nothing left in force
compensation_blocked a device lock (or a missing/failed rollback) stopped
                     compensation — siblings REMAIN APPLIED, admin required
failed               refused before any sibling executed (e.g. not admitted)
```

### Asynchronous execution

A confirmed enforce-mode `POST /api/rules/{id}/apply` (`dry_run: false`) no
longer blocks on SSH. It returns `202` and continues in the background:

```json
{ "bundle_id": 42, "async": true, "state": "running",
  "total_actions": 14, "failure_policy": "abort_and_compensate",
  "results": [] }
```

`results` carries only the actions skipped before admission (unresolvable target,
aged-out inventory); per-action outcomes are read from the progress endpoint.

`GET /api/reroute-bundles/{id}` (`view_asset`) returns the bundle state,
`completed_actions` / `total_actions`, `failure_reason`, one row per sibling in
execution order (position, device, template, state, failure reason), and
`still_applied_reroute_ids` — derived from durable state, not from the in-memory
run, so it survives a restart.

Previews (`dry_run: true`) and **everything in observe mode remain synchronous
and unchanged**: they render the would-run plan without opening an SSH session,
so the preview → token → execute gate is untouched and observe mode still renders
all N would-run plans while executing nothing. The hand-off exists because
holding one HTTP request open across ~28 SSH sessions lets the reverse proxy cut
the operator off mid-mitigation with the preview token already consumed.

### Restart during a bundle

Existing recovery marks in-flight siblings `uncertain` and locks their devices;
`bundle::recover_on_startup` then closes every bundle left `planned`, `running`,
or `compensating` as `aborted`, so the UI never shows a mitigation as still
progressing after a crash. See [state-recovery.md](state-recovery.md).

## Verification examples

Verification is always an IOS `show` read parsed for an expected/rejected
substring (case-insensitive):

- **null_route / blackhole**: `show ip route <net>` must contain `Null0` after a
  black hole (and must *not* contain it after a withdraw).
- **bgp_session_enable**: `show ip bgp neighbors <ip>` must contain `BGP state`
  and must *not* contain `Administratively shut`.
- **bgp_session_disable**: the same `show` must contain `Administratively shut`.

If the verification read fails or cannot prove success or failure, the action is
`uncertain`: lock the **device**, alert (critical), and require admin
acknowledgement. See [state-recovery.md](state-recovery.md).
