# Reroute Engine

Reroutes are controlled, audited mitigations that move traffic. This is the most
dangerous part of the system. Everything here exists to make reroutes slow,
explicit, reversible, and blocked whenever state is uncertain.

## Operating mode (observe vs enforce)

The engine sits behind a global operating mode
(`system_settings.operating_mode`):

- **`observe`** — the shipped default. Safe read-only / alert-only: **nothing
  executes, automatic or manual**. When a rule fires (threshold above/below for
  the configured duration), the engine renders the attached template in
  **dry-run** — exact provider, method, prefix, parameters — and attaches that
  would-run plan to the rule event and the email alert. This lets operators
  validate thresholds and templates against live traffic with zero risk.
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
- provider type compatibility (`cloudflare` / `bgp_rtbh` / `flowspec` / `scrubber`);
- `mode` (e.g. `cloudflare_api`, `bgp_announce`, `bgp_withdraw`, `flowspec`);
- parameter schema (typed, validated);
- `safety_level` (`low` / `medium` / `high`);
- `manual_confirmation_required` (bool);
- `automatic_allowed` (bool);
- expected success markers / verification method;
- optional `rollback_template` (how to undo).

### Example templates (simple first)

```yaml
name: cloudflare_under_attack
provider: cloudflare
mode: cloudflare_api
safety_level: low
automatic_allowed: true
params: { zone_id }
verify: zone security_level == "under_attack"
rollback: cloudflare_restore_security_level

name: blackhole_prefix          # RTBH
provider: bgp_rtbh
mode: bgp_announce
safety_level: high
manual_confirmation_required: true
params: { prefix, blackhole_community }
verify: bgp announcement present with community
rollback: withdraw_blackhole_prefix

name: flowspec_drop
provider: flowspec
mode: flowspec
safety_level: high
params: { src, dst, proto, port }
verify: flowspec rule installed upstream
rollback: flowspec_remove_rule

name: divert_to_scrubber
provider: scrubber
mode: bgp_announce
safety_level: high
manual_confirmation_required: true
params: { prefix, scrubber_target }
verify: prefix announced to scrubber; return path healthy
rollback: stop_diversion
```

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
anything. Any failure aborts and logs:

- **gate 0:** `operating_mode == enforce` — in `observe` mode the engine stops
  here and emits the would-run plan instead (see "Operating mode" above);
- automatic reroutes globally enabled **and** this rule's
  `automatic_reroute_enabled` is true (for automatic triggers);
- a valid action template is attached;
- telemetry for the asset is fresh and valid;
- detection confidence is high (no parser/collector errors);
- the provider is reachable and `actions_enabled`;
- the target prefix is within the provider's permitted ranges;
- no other action is running on this asset;
- not inside any applicable cooldown window;
- no global maintenance lock; asset not in manual lock;
- no unresolved (`uncertain`) prior action on this asset;
- for manual: caller has `trigger_manual_reroute`; for high safety level,
  re-auth + typed confirmation + reason present.

## Cooldowns & rate limits

```text
same rule cooldown:          15 min
same asset action cooldown:   5 min
same prefix/provider:        30 min
global automatic rate limit:  3 actions / 10 min
```

## Locks

Lock scopes: `global`, `asset`, `provider`, `prefix`, `template`. Locks can be
manual, automatic after a failed action, automatic after crash recovery, or
automatic after action uncertainty. A locked scope blocks all reroutes touching it
until cleared (admin ack for safety-induced locks).

## Manual reroutes

Manual reroutes are first-class:

```text
1. User selects asset + reroute template.
2. User fills parameters.
3. SPA renders the exact reroute preview (prefix, provider, method, communities).
4. For high safety level: the Rust API enforces fresh re-auth (password + TOTP),
   typed confirmation, and a reason.
5. Controller receives the request, re-checks all safety gates, locks the asset.
6. Controller executes via the provider, capturing every step.
7. Controller verifies the resulting state.
8. UI shows result + raw output; audit log records everything; email alert sent.
```

Manual reroutes support **dry-run**: render the plan, test provider auth, and run
the verification read only — without changing any routing.

## Rollback & expiry

Every disruptive template should define a rollback and, where it makes sense, an
**auto-expiry** (e.g. a blackhole that lifts after N minutes unless renewed) so a
forgotten mitigation does not persist indefinitely. Rollback is itself an audited
action with verification.

## Verification examples

- **blackhole**: confirm the `/32` announcement with the blackhole community is
  present in the BGP feed; confirm asset bps drops at the edge.
- **cloudflare_under_attack**: read zone security level back as `under_attack`.
- **flowspec_drop**: confirm the rule is installed upstream.
- **scrub divert**: confirm announcement to the scrubber and a healthy return path.

If verification cannot prove success or failure, the action is `uncertain`: lock
the asset, disable automatic actions for it, alert, and require admin
acknowledgement. See [state-recovery.md](state-recovery.md).
