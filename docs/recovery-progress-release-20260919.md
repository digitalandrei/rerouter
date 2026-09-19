# Recovery progress release — 2026-09-19

Status: **prepared and tested; not deployed**.

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

## Prepared behavior

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

The release is prepared against this exact settled application state:

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
- Astra final integration and execution-safety review approved the prepared
  release.

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

## Prepared deployment

The reviewed driver is
`scripts/deploy-recovery-progress-release.sh`; its mock/recovery check is
`scripts/test-deploy-recovery-progress-release.sh`. Neither has been run for this
release.

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

## Required post-deployment checks

Before marking this release deployed, the operator must verify:

- controller service active, loopback `/api/ready` and `/api/health` successful,
  and the running executable identical to the reviewed controller artifact;
- deployed controller and frontend hashes match the release;
- the deployed frontend tree matches the reviewed release tree;
- config and environment remain byte-for-byte unchanged;
- schema remains at 69 and the migration count/version are unchanged;
- preset #2 remains ready and preset #1 remains needs setup through the installed
  binary's DB-only diagnostics;
- bundles #1 and #2, all sixteen reroutes, both action ledgers, presets, rules,
  credentials, and settings match their stopped-window snapshots exactly;
- zero in-flight reroutes/bundles, recovery claims, device change windows, and
  active locks;
- read-only summary responses expose child #2 as bundle #1's latest recovery and
  present the source as reverted, without treating child #2 as another active
  mitigation.

Deployment remains incomplete until the post-deployment checks above are
recorded.
