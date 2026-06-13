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
```

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
- for manual: the caller has `trigger_manual_reroute` (enforced by the API before
  it calls the executor), with an optional reason recorded for the audit log.

For automatic triggers, the *rule* decides: the firing edge only auto-executes in
enforce mode when the rule's `automatic_reroute_enabled` is on. There is **no**
provider-reachability gate, no permitted-prefix-range gate, and no re-auth / typed
confirmation step (those were de-scoped along with the multi-provider model and
the `safety_level` classification).

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
