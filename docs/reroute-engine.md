# Reroute Engine

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

bgp_session_enable    router bgp {local_asn} ; no neighbor {neighbor_ip} shutdown
                      Bring a BGP neighbor up — e.g. start the GRE scrubber
                      session so routes announce and traffic diverts.
                      verify: show ip bgp neighbors {neighbor_ip}
                              -> expect "BGP state", reject "Administratively shut"
                      rollback: bgp_session_disable

bgp_session_disable   router bgp {local_asn} ; neighbor {neighbor_ip} shutdown
                      verify: show ip bgp neighbors {neighbor_ip}
                              -> expect "Administratively shut"

bgp_advertise_add     ip prefix-list {prefix_list_name} permit {prefix}
                      exec_after: clear ip bgp {neighbor_ip} soft out
                      Advertise a prefix toward ONE upstream peer by adding it to
                      that peer's outbound route-map prefix-list, then soft-clear
                      outbound. The prefix-list name is discovered per peer
                      (neighbor `route-map NAME out` -> route-map
                      `match ip address prefix-list PL`) and offered by the
                      `peer_out_prefix_list` picker.
                      verify: show ip bgp neighbors {neighbor_ip} advertised-routes
                              -> expect "{prefix_net}"
                      rollback: bgp_advertise_remove

bgp_advertise_remove  no ip prefix-list {prefix_list_name} permit {prefix}
                      exec_after: clear ip bgp {neighbor_ip} soft out
                      verify: show ip bgp neighbors {neighbor_ip} advertised-routes
                              -> reject "{prefix_net}"

iface_tcp_adjust_mss  interface {interface} ; ip tcp adjust-mss {mss}
                      MSS clamp (default 1436) applied when a rule activates.
                      verify: show running-config interface {interface}
                              -> expect "ip tcp adjust-mss {mss}"
                      rollback: iface_tcp_adjust_mss_remove

iface_tcp_adjust_mss_remove
                      interface {interface} ; no ip tcp adjust-mss
                      verify: show running-config interface {interface}
                              -> reject "adjust-mss"

iface_shutdown        interface {interface} ; shutdown    (DISRUPTIVE)
                      verify: show interfaces {interface}
                              -> expect "administratively down"
                      rollback: iface_no_shutdown
                      Blocked on interfaces flagged `protected` (see below).

iface_no_shutdown     interface {interface} ; no shutdown
                      verify: show interfaces {interface}
                              -> reject "administratively down"
```

`plan_json` supports an optional `exec_after` array — privileged EXEC commands
(e.g. `clear ip bgp <peer> soft out`) that run AFTER the `configure terminal` …
`end` block closes, never inside it. Verification `expect`/`reject` substrings may
reference `{params}` (e.g. `{prefix_net}`), substituted at render time.

A **combination** (remove-from-saturated-upstream + advertise-on-others + MSS
clamp) is expressed as several ordered `rule_actions` on one rule — each its own
verification and rollback — not a single composite template.

**Protected-interface guard.** `device_interfaces.protected` flags the device's
management / transit / SSH path. Before executing a template that targets an
interface (any param with `source: "interface_name"` — `iface_shutdown`,
`iface_tcp_adjust_mss*`), the executor resolves the interface and **blocks** if it
is protected, returning a `blocked_reason` and pushing nothing. This prevents the
controller from cutting or black-holing its own path to the device. Set the flag
via `PATCH /api/interfaces/{id}/protected` (`manage_devices`). Every disruptive
command shape above is also gated by the fail-closed `ssh::command_allowed`
allowlist.

Disruptive templates are paired with their inverse via `rollback_template_id`.
The old `cloudflare_under_attack` / `flowspec_drop` / `divert_to_scrubber`
templates were removed when their providers were de-scoped.

## Two-phase state machine

```text
planned -> pending -> running -> verifying -> succeeded
                             \-> failed
                             \-> uncertain
```

Persist state **before and after every step**. `action_outputs` stores each
step's command/API call, response, and status. Never treat "API/announce sent" as
success — move to `verifying` and confirm the routing/zone state actually changed.

## Safety gates (checked again at execution time)

Even if a rule fired, the reroute engine re-validates *all* of these before doing
anything. The gates are **device-scoped** (the target of a `device_cli` action is
a router, not an asset/prefix). Any failure aborts and logs:

- **gate 0:** `operating_mode == enforce` — in `observe` mode the engine stops
  here and returns the would-run plan instead (see "Operating mode" above);
- not a dry-run request (dry-run renders the plan only, even in enforce mode);
- no global maintenance lock;
- the target **device** is not locked (a prior uncertain/failed action that needs
  admin acknowledgement locks it);
- no other action is already running on this device;
- no unresolved (`uncertain`) prior action on this device;
- the device is not inside its post-action cooldown window;
- the global action rate limit is not exceeded;
- **control-plane reachability (preflight):** the target device answers **SSH at
  privileged EXEC**. A reroute pushes config over SSH, so a device that does not
  answer SSH cannot be mitigated — the action is refused up front
  (`BlockReason::DeviceUnreachable`) rather than reserving a slot and failing
  mid-push. To avoid re-probing a device we just talked to (and tripping its SSH
  connection throttle), a successful SSH contact within the last **60 s**
  (`devices.last_ssh_ok_at`, stamped by the probe and by every successful reroute
  push) passes without opening a new session. This is a hard gate on **every**
  trigger (manual, automatic, rollback). A poll-loop probe
  (`reachability_interval_seconds`, default 3 min) classifies the device into
  `devices.ssh_status` — `reachable` / `no_privilege` (SSH works but the account
  isn't privilege 15 — an actionable config fix, still NOT reroute-usable) /
  `unreachable` — for display and to keep the recency window warm. See
  `reroute::reachability`;
- for manual: the caller has `trigger_manual_reroute` (enforced by the API before
  it calls the executor), with an optional reason recorded for the audit log.

For automatic triggers, the *rule* decides: the firing edge only auto-executes in
enforce mode when the rule's `automatic_reroute_enabled` is on. There is no
permitted-prefix-range gate and no re-auth / typed confirmation step (those were
de-scoped along with the multi-provider model and the `safety_level`
classification). The reachability gate above is a control-plane (SSH) preflight,
distinct from the de-scoped multi-provider "provider reachability".

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
disable that throttle. These apply to manual and automatic actions alike.

## Locks

Lock scopes: the device-CLI engine uses the `device` scope (and `global`). Locks
can be manual, automatic after a failed
action, automatic after crash recovery, or automatic after action uncertainty. A
locked scope blocks all reroutes touching it until cleared (admin ack for
safety-induced locks).

## Manual reroutes

Manual reroutes are first-class:

```text
1. User selects a reroute template and one or more target routers (devices).
2. User fills parameters per target (guided by ASN / neighbor / prefix / RTBH
   pickers; the scrubber neighbor IP, say, can differ per router).
3. SPA renders the exact would-run commands + verification per target.
4. The Rust API checks the caller has `trigger_manual_reroute` and records the
   optional reason. (No re-auth / TOTP / typed-confirmation step — de-scoped.)
5. For each target the controller re-checks all device-scoped safety gates and
   runs the executor independently (multi-router fan-out; one device locked or in
   cooldown is skipped without blocking the others).
6. Controller pushes the config over SSH, capturing every step's output.
7. Controller verifies the resulting state with a read-only `show`.
8. UI shows result + raw output; audit log records everything; email alert sent.
```

Manual reroutes support **dry-run**: render the exact plan without changing any
routing (in observe mode every trigger behaves this way regardless).

### Apply a firing rule's mitigation (supervised path)

Between alert-only and unattended automatic execution there is a supervised
middle ground: an operator manually applies a *firing* rule's own configured
actions from its alert (Alerts page) or from the dashboard's active-matches list.
`POST /api/rules/{id}/apply` is opt-in per rule (`rules.manual_apply_enabled`,
default off, set in the rule editor) and **only permitted while the rule's state
is `firing`** (you mitigate a live breach, not a cleared one). It runs each
enabled `rule_action` through the *same* gated executor as a `manual` trigger
attributed to the operator, so it inherits every protection: blocked in observe
mode (returns the would-run plan per action), requires `trigger_manual_reroute`,
and honours device locks, the global maintenance lock, per-device and per-rule
cooldowns, the rate limit, and the protected-interface guard. Because the trigger
is `manual`, the global **automatic** master switch does not gate it — this is a
deliberate operator action — but `rule_id` is set, so the per-rule cooldown still
applies. This is distinct from `automatic_reroute_enabled` (hands-off execution
on the firing edge); a rule may enable either, both, or neither.

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
- Auto-target is only attachable to a flow rule + a host-route template (enforced
  by the API); the prefix param is resolved, not typed.

## Rollback

Every disruptive template defines a rollback (its paired inverse, via
`rollback_template_id`). A mitigation lifts only via an explicit rollback — there
is **no** auto-expiry / self-clearing after N minutes (de-scoped: a template
describes *what* it does, not how long it lasts). Rollback runs against the same
device + parameters as a fresh audited action, with its own verification, exposed
as `POST /api/reroutes/{id}/rollback`.

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
