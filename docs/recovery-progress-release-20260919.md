# Recovery progress release — 2026-09-19

Status: **deployed and read-only verified**.

Deployed source and both release markers:
`59ce8be0baa69c87918550ab35adb627cb0e1f0e`.

## Problem and root cause

A whole-run manual revert creates a new `reroute_bundles` row whose
`parent_bundle_id` identifies the original mitigation run. The manual acceptance
path did not write that child ID into the original row's
`recovery_bundle_id`. That column belongs to the scheduler recovery protocol and
is populated by scheduled/automatic recovery paths.

The router changes were correctly reversed and their evidence was durable, but
the read interface could not discover the manual recovery child from the source
row alone. After settlement, the original therefore looked like a successful
run with zero remaining changes and `recovery_bundle_id = NULL`. The interface
could not reliably distinguish **Reverted** from an original run that made only
verified no-op changes.

## Implemented behavior

The shared run-summary read model now derives the latest recovery child in one
batch query over `parent_bundle_id`. It returns two additive fields:

```json
{
  "latest_recovery_bundle_id": 2,
  "latest_recovery": {
    "id": 2,
    "parent_bundle_id": 1,
    "state": "succeeded",
    "total_actions": 8,
    "completed_actions": 8,
    "started_at": "…",
    "finished_at": "…",
    "failure_reason": null
  }
}
```

Selection is deterministic: the child with the greatest bundle ID is the latest
attempt. Running, successful, and failed children are all visible. Recovery
children do not themselves expose another recovery link. List, detail, dashboard,
and saved-definition summaries share the same batch-derived representation.

The existing `recovery_bundle_id` field is unchanged. No scheduler state is
reinterpreted or backfilled, no live row is corrected, and no schema migration is
needed. The parent run remains the mitigation lifecycle owner; the child remains
the execution evidence for its revert.

## Current finished EMDD evidence

The deployment preserved this exact settled application state:

- Source bundle **#1**: manual, succeeded, lifecycle inactive, 8/8 actions,
  zero remaining mutations, no recovery claim, and
  `recovery_bundle_id = NULL`.
- Recovery child **#2**: `parent_bundle_id = 1`, manual, succeeded, lifecycle
  inactive, 8/8 actions, zero remaining mutations.
- Sixteen reroute rows are present: eight successful changed original actions
  owned by bundle #1 and eight successful changed inverse actions owned by
  bundle #2. Every inverse refers to an original action from bundle #1.
- Both immutable action ledgers contain eight successful changed entries.
- There are no in-flight reroutes or bundles, recovery claims, device change
  windows, or active locks.

The eMA3 definition contains seven BGP export-policy changes and one interface
MSS change. Recovery preparation clones each original immutable template
snapshot, changes only its machine name to
`prepared_inverse_of_<original-reroute-id>`, and retains its display name. The
eight child steps therefore appear, in reverse recovery order, as:

1. `Change BGP export policy` for the COLT peer.
2. `Interface MSS Clamp` for Po1; this step executes the prepared inverse that
   restores the prior MSS state.
3. Six `Change BGP export policy` steps for the Akamai peers in reverse original
   order.

The interface must contextualize these as revert actions; the retained display
name describes the original action family, while the persisted prepared command
and state evidence describes the actual inverse.

## Safety constraints

This change is read-only presentation logic. It does not create execution
authority, prepare or consume a preview token, schedule recovery, alter ownership,
or write router configuration.

The assistant did not run a mitigation, revert, router discovery, SSH test,
notification test, or router command while implementing and testing this change.
All execution tests used fake SSH and dedicated test-database rows.

## Verification completed

- Rust `cargo test --all-targets` against the dedicated MariaDB test schema:
  **283 passed, 0 failed**.
- Focused run-summary, lifecycle, whole-run revert, manual-mitigation, and
  configuration-only recovery tests passed.
- Strict `cargo clippy --all-targets -- -D warnings` passed.
- `cargo fmt --all -- --check` passed.
- Frontend test suite: **72 passed, 0 failed**.
- Frontend TypeScript typecheck and production build passed.
- The Impeccable detector completed with no findings.
- Batched Playwright verification covered desktop and mobile settled and running
  recovery states. Evidence is under `/tmp/rerouter-visual-qa`; it recorded no
  page errors, mutation requests, missing endpoints, or horizontal overflow.
  The recovery-progress presentation correction was confirmed.
- Astra final integration and execution-safety review approved the release
  before deployment.

The run-summary regression proves:

- a manual child is exposed while the source is `recovery_claimed`, even when
  the scheduler-owned field is null;
- the link remains after the source settles inactive with zero ownership;
- the newest of multiple recovery attempts is selected;
- the child summary has no recursive recovery link;
- active and logical-only lists still contain one source mitigation, while raw
  history still contains recovery children;
- a successful latest child provides evidence to distinguish a reverted run
  from an all-no-op original.

## Deployment execution

The reviewed driver is
`scripts/deploy-recovery-progress-release.sh`; its mock/recovery check is
`scripts/test-deploy-recovery-progress-release.sh`. The reviewed driver was used
for this release after its mock preservation and recovery checks passed.

The driver requires and verifies:

- current controller marker `3276418…` and a caller-supplied exact current
  controller SHA-256;
- current frontend marker `9193046…` and a caller-supplied exact current
  frontend index SHA-256;
- config SHA-256
  `6e659bfdd917f68b573b7cb5397a3080749cb27417e89750f00b8a0ba1b36972`;
- schema count 69 with latest migration `20260919000200`;
- Observe mode and the automatic-actions master switch off;
- the exact settled bundle #1 / child #2, reroute, ledger, lock, claim, and
  device-window state described above.

Before stopping the controller, the staged binary runs config validation and a
DB-only readiness check for preset #2. That preset fetch exercises the new
latest-recovery query against live MySQL but exits before migrations, workers,
HTTP listeners, SSH, or execution paths. Preset #1 must remain `needs_setup`.

During the stopped window the driver backs up:

- the full database, including routines and triggers;
- controller and frontend artifacts;
- config, environment, and release markers;
- exact before snapshots of both bundles, all reroutes, both action ledgers,
  presets and actions, rules and actions, encrypted device credential fields,
  and system settings.

No migration is expected. The controller's normal startup migration check must
be a no-op. Backend and frontend artifacts are swapped while the controller is
stopped, and only `rerouter-controller.service` is restarted. The recovery policy
restores artifacts only before the new controller is exposed; after a new start
attempt it stops the controller and retains the new database and evidence for
reconciliation.

The script contains no mitigation preview, apply, revert, router discovery,
router test, notification test, or router execution request.

## Deployment verification

The deployment completed with this evidence:

- Controller SHA-256:
  `a2a76529510918ab5cf2c97c1290383e6853db3d7e997e219cf92c8b11547ed7`.
- Frontend index and public index SHA-256:
  `dfef225f9cc057cbdacaeaf5e5808d036b8c6573722e1f041944d1248722587f`.
- Restorable backup:
  `/root/rerouter-backups/recovery-progress-59ce8be0baa6`.
- `rerouter-controller.service` started at **2026-09-19 17:50:48Z**. Loopback
  readiness and health checks passed. The readiness loop recorded one harmless
  initial `curl` connection refusal while the service was still starting, then
  succeeded normally.
- Public HTTPS readiness and health checks passed, and the public index hash
  matched the reviewed frontend artifact.
- The running executable matched the deployed controller artifact. The deployed
  frontend tree matched the reviewed release tree.
- Schema remained at 69 with latest migration `20260919000200`; startup applied
  no new migration.
- Operating mode remained Observe and automatic actions remained disabled.
- Source bundle #1 remained succeeded and inactive with 8/8 completed actions
  and zero remaining mutations. Child bundle #2 remained succeeded and inactive
  with 8/8 completed actions and zero remaining mutations.
- All sixteen reroutes remained succeeded with `mutation_effect = changed`:
  eight originals and their eight successful inverses. Both action ledgers
  remained complete, for sixteen successful changed entries total.
- Active locks and device change windows remained zero. No reroute, bundle, or
  recovery claim was in flight.
- Preset #2 remained ready and preset #1 remained needs setup through the
  installed binary's DB-only diagnostics.
- Config and environment remained byte-for-byte unchanged. Bundles, reroutes,
  action ledgers, presets, rules, encrypted credential fields, settings, and
  other protected stopped-window snapshots matched after restart.
- The installed binary's DB-only preset diagnostic exercised the new
  latest-recovery query against live MySQL. The exact preserved database state,
  together with the reviewed and tested presentation logic, establishes the
  expected source **Reverted** state and child #2 recovery evidence.
- Router actions executed during deployment: **0**.

The desktop/mobile Playwright evidence above was produced before deployment.
No authenticated live post-deployment visual session was performed or is implied
by the public health and static-asset verification.
