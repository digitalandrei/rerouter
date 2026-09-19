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

## Automatic work

Autonomous starts require Enforce, the automatic master switch, the relevant
rule preference, automatic-capable templates, and every safety gate. Condition
and timed recovery require Enforce plus the master switch, their recorded
authority, eligible owned changes, and the recovery safety gates. Recovery may
apply a persisted inverse for a manual-only activation; `automatic_allowed`
restricts new automatic activation rather than corrective owned work.
Disarming pauses new autonomous work and autonomous-origin compensation. An
already authorized manual-origin compensation may finish its failure policy.

## Recovery

Use the persisted original inverses in reverse order. Drift or uncertain state
freezes recovery; inspect and reconcile rather than inventing an inverse. Taking
manual control cancels a future automatic deadline. A manual revert always gets
a fresh exact preview and explicit confirmation.

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
verification against an operational peer. The user controls lab execution after
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
