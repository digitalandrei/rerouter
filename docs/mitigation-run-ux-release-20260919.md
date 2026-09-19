# Mitigation run lifecycle clarity — 2026-09-19

## Product decision

A mitigation run is the primary operational object. A saved manual mitigation is
the reusable definition; its individual actions are evidence beneath each run.
Execution completion and current router state are displayed separately.

The UI derives a single operator-facing state from durable run evidence:

- **Applying** while the ordered steps are still executing.
- **Applied manually** or **Applied automatically** when known changes remain.
- **Partially applied** when execution stopped and known changes remain.
- **Reverting** while recovery is scheduled, claimed, or running.
- **Needs attention** when an effect is unknown or recovery is blocked.
- **Failed — changes reverted** after successful compensation.
- **Reverted** after an explicit recovery closes the original run.
- **No changes needed** when a successful run consisted only of no-ops.
- **Failed — no changes applied** when a failed run owns no remaining change.

Known remaining changes and unknown effects are separate values. A run with an
unknown effect does not advertise a revert as available; it requires
reconciliation. Configuration-only runs always state that BGP advertisements
were not verified.

## Interface behavior

The dashboard has an **Active mitigations** section and a separate **Recent
mitigation activity** section. Each logical original run appears once. Recovery
children remain evidence beneath the original run. Bundled per-action lifecycle
alerts are omitted only from the dashboard alert feed, before pagination; the
raw alert history remains complete and standalone reroutes remain visible.

Saved mitigation details place **Current state** before the ordered action
definition. Each active run shows its identity, state, known/unknown effects,
routers, operator, start time, recovery timing, verification scope, revision
relationship, and an exact **Review & revert** link. Multiple active runs remain
separate and require explicit selection.

The run screen uses **Return to mitigation details** for saved definitions and
**Return to manual mitigations** for ad-hoc runs. Neither control changes router
state. Revert remains preview-first and requires a separate confirmation.

Healthy applied runs do not show a recovery alarm. The red “changes still
applied” panel is reserved for partial, failed, uncertain, or recovery-blocked
outcomes.

## Market references

The design adapts two established ideas without copying product complexity:

- Kentik presents one mitigation row with explicit lifecycle status and
  state-dependent actions.
- FastNetMon gives an active block a persistent identity and reverses that exact
  identity.

Rerouter applies those ideas to an ordered, reversible multi-router run while
keeping full action evidence available below the run summary.

## Verification

- Complete backend suite passed on the dedicated MariaDB test schema.
- Complete backend suite passed on an isolated MySQL 8 schema; the temporary
  schema, restricted account, and owned SSH tunnel were removed afterward.
- 59 frontend tests, typecheck, production build, Rust formatting and strict
  Clippy passed.
- Desktop and mobile mocked browser checks covered Dashboard, saved mitigation
  details, and the Active-run dialog. No horizontal overflow, page errors,
  missing mocked reads, or write requests were observed.
- The deployment driver preserves the currently applied eMA3 run and its eight
  owned changes. It contains no preview, apply, revert, notification, or router
  request.

Detailed browser and release evidence is under
`/tmp/rerouter-workflow-review-20260919/mitigation-clarity/`.

## Deployment result

Deployed source `3276418925c6dde0e6cf9fae809b5ffc4b3846cd` to EMDD.
The controller and public frontend hashes match the reviewed release, schema 69
remains current, and health/readiness return OK. The configuration and session
environment are unchanged.

The deployment preserved the application data byte-for-byte across its guarded
snapshots: 13 rules, two saved definitions, 24 saved definition actions, one
original run, eight action records, and zero active locks. Run 1 remains
`succeeded`, lifecycle `active`, with 8/8 actions complete and eight owned
changes. It has no recovery child or recovery claim. The eMA3 saved definition
reports Ready; the original eMA1/eMA2 definition remains Needs setup.

No preview, apply, revert, notification test, router command, or router
connection was issued during deployment. The restorable backup is
`/root/rerouter-backups/mitigation-clarity-3276418925c6`; its compressed database
evidence is 40,457,282 bytes with SHA-256
`b13c9291903a0aa39097270e730bf34e11af0704650b33fb363455a6aa646088`.
