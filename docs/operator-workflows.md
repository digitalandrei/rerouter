# Operator workflows

This is the current operating-mode and authority reference. It supersedes older
statements that describe Observe as blocking all manual execution.

## Inspect and run manually

1. Keep Observe and the automatic master switch off during ordinary inspection.
2. Open a saved mitigation or rule action set and inspect its current inventory,
   before/after projection, inverse, commands, and verification evidence.
3. Resolve every blocker. A preview never grants standing execution authority.
4. Request the exact server preview, record a reason, then explicitly confirm its
   short-lived one-use token. Authorized manual runs and reverts work in Observe
   and Enforce and re-check every gate at admission.
5. Follow the bundle until every action is verified. Execution success and
   remaining owned changes are separate facts.

A Rule with an ordered action set is also a mitigation definition. Its detection
condition controls automatic triggering; it does not change the action set. When
**Manual apply** is enabled, an operator may run that defined mitigation from the
Rule detail page regardless of the current detection state, using the same exact
preview, confirmation, and execution gates.

## Automatic work

Autonomous starts require Enforce, the automatic master switch, the relevant
rule preference, automatic-capable templates, and every safety gate. Condition
and timed recovery require Enforce plus the master switch, their recorded
authority, eligible owned changes, and the recovery safety gates. Recovery may
apply a persisted inverse for a manual-only activation; `automatic_allowed`
restricts new automatic activation rather than corrective owned work.
Disarming pauses new autonomous work and autonomous-origin compensation. An
already authorized manual-origin compensation may finish its failure policy.

## Configuration-only verification

Configuration-only verification is the manual-run scope for enabled routers in
the current release. Every enabled device with a pinned SSH host identity is
eligible implicitly. It never activates automatically. The following entries
are optional stricter identity and rate-limit overrides:

```toml
[[safety.configuration_test_devices]]
device_id = 3
host = "router.example.invalid"
port = 22
pinned_host_fingerprint = "SHA256:..."
# Optional; defaults shown.
action_rate_limit_count = 32
action_rate_limit_window_seconds = 600
```

When an override exists, the current database identity must match its device id,
host, port, and pinned fingerprint at capability lookup, preview, confirmation,
and execution. A run may target one enabled device and may use only `bgp_export_policy_set` and
`iface_tcp_adjust_mss` actions. The manual-run page selects **Configuration
only**. Ineligible sets remain blocked. **Additional checks** is visible but
disabled for a future version. Review the exact projection and commands, and
confirm the short-lived preview token normally.

This mode proves the exact configuration before and after each action. An Idle
BGP peer is allowed because advertised-route and Established-state evidence is
outside this proof scope; the result must state that routing was not verified.
The reviewed soft-out refresh command remains part of an export-policy plan,
and IOS command errors still fail normally. They are never suppressed.

Configuration-only runs have no timer, rule, automatic, or unattended recovery
path. Use the explicit manual **Revert** workflow; its fresh preview inherits the
persisted configuration-only scope and restores owned changes in reverse order.
Immediate compensation after a failed manual run inherits the same scope. Older
stored snapshots with no `verification_mode` deserialize as `routing`.

The action-specific route, BGP, and interface checks already present in the
engine remain unavailable as a manual-run scope until their operator contract is
completed and certified against the enrolled ASR images. They are not silently
substituted for Configuration only.

## Recovery

Use the persisted original inverses in reverse order. Drift or uncertain state
freezes recovery; inspect and reconcile rather than inventing an inverse. Taking
manual control cancels a future automatic deadline. A manual revert always gets
a fresh exact preview and explicit confirmation.

The **Active Runs** view is server-paginated at 25 logical runs per page. Search
matches run id, saved/source name, trigger, lifecycle, or operator. Device accepts
an exact numeric id or a case-insensitive name fragment. Date inputs are browser
local calendar days converted to inclusive UTC lower and exclusive next-day UTC
upper bounds against run creation time. Opening a row loads that run's full
action evidence and, when present, its latest recovery child; list refreshes do
not fetch every action or every page.

Manual-revert blockers and automatic-recovery errors are displayed separately.
**Cancel automatic recovery** appears only when a timer-based or rule-driven
automatic recovery is still eligible and unclaimed. It cancels that future
automatic revert without sending router commands; the current changes remain
until an operator previews and confirms a manual revert. Runs configured for
manual recovery do not show this action. **Reconcile device state** is available for an
uncertain action and for a failed inverse that has persisted changed evidence;
it remains a read-only comparison and does not acknowledge arbitrary failures.

## EMDD policy prerequisites

These snippets are reference material for a network administrator. The release
and conversion tooling never sends router commands.

On eMA2, create and independently review two IPv4 prefix lists before the seven
dependent saved actions can become Ready:

```ios
ip prefix-list rr-194105142-only seq 10 permit 194.105.142.0/24
ip prefix-list rr-194105142-only seq 20 deny 0.0.0.0/0 le 32
ip prefix-list rr-colt-without-194105142 seq 10 permit 194.102.117.0/24
ip prefix-list rr-colt-without-194105142 seq 20 deny 0.0.0.0/0 le 32
```

After an administrator provisions them, refresh cached routing-policy inventory,
inspect the complete 16-action set, and confirm that Akamai receives only
`194.105.142.0/24` while COLT retains `194.102.117.0/24` and excludes
`194.105.142.0/24`. Until then, keep the draft blocked as Needs setup.

The 19 September read-only eMA3 inspection found the same direct IPv4-AF policy
shape as eMA1. All nine BGP peers were Idle and Po1 had no MSS clamp, so the
configuration parser evidence is useful but does not certify activation or
verification against an operational peer. The user controls live execution after
deployment. Existing removed SSH write permissions on eMA1/eMA2 are intentional;
deployment preserves them and does not re-enroll accounts or repair permissions.

## Release recovery boundary

The stopped-window database snapshot, old root-owned controller, frontend,
environment, and configuration form one rollback unit. Before the new controller
starts, a failed migration or conversion may restore that complete unit and
verify old readiness. Once the new controller starts, it may have accepted
durable operator writes. Automatic database rollback is then forbidden: stop the
application service, preserve the new schema and evidence, compare reroute,
definition, and audit changes, then choose a forward fix or an explicitly
authorized full restore. The old 67-migration binary cannot run against a schema
that records migrations 68–69.
