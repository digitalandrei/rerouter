# State Recovery

The controller must understand current state after any restart or crash. Because
reroutes move real traffic, the cost of assuming "nothing happened" is wrong
routing. The default assumption after a crash mid-action is **uncertainty**.

## Persisted runtime state

- last device reachability and telemetry health;
- last valid telemetry sample and counter baselines;
- active detection-rule states and consecutive-match counters;
- planned / pending / running / verifying reroutes;
- in-flight mitigation bundles and each sibling's bundle membership + order;
- immutable prepared plans, mutation effects, exact before/after state and inverses;
- durable device ownership, including siblings that never started;
- last step output and verification status per action;
- active locks and cooldowns (device-scoped);
- device + interface inventory and discovered BGP peers/prefixes.

## Controller startup sequence

```text
1. Load configuration, preflight the database, and apply migrations.
2. Find reroutes in state planned / pending / running / verifying.
3. For each row, atomically mark it `uncertain`, create a linked device lock
   (`locks.reroute_id`, kind `auto_crash`), enqueue a critical alert, and write an
   audit row.
4. If any recovery transaction fails, abort startup. The untouched/rolled-back
   row is retried on the next start; the service never continues with a partial
   recovery trail.
5. Reconstruct each interrupted bundle's original mutation ownership. Mark it
   `compensation_blocked` if changed or ambiguous originals remain, or `aborted`
   if none remain. Preserve/reconstruct ownership windows and release unused
   rate reservations. Persist the result, critical alert and audit together.
   The controller does not continue or compensate writes after a restart.
6. Start the supervised alert, telemetry, detection, retention, and API tasks.
   Inventory, baselines, and rule state remain durable in MariaDB; SSH sessions
   are opened on demand rather than reconnected at startup.
7. Startup does not re-read routers. Explicit read-only reconciliation compares
   the current router state with durable action snapshots.
8. Conflicting or incomplete evidence leaves uncertainty and ownership intact.
   A recorded acknowledgement note cannot override the evidence.
```

Do **not** assume no reroute happened just because the process crashed. A
null-route pushed to the device milliseconds before a crash may still be
installed in its routing table.

## Uncertain state handling

For any `uncertain` action:

- show it prominently in the GUI (dashboard + device detail);
- disable automatic reroutes for the affected device (it stays locked);
- send an email/Teams alert according to configured subscriptions;
- require explicit, audited reconciliation using
  `acknowledge_uncertain_reroute` (also granted to the seeded operator role);
- retain bundle ownership until every original mutation is proved restored.

An SSH apply error is uncertain even when a later text check sees the intended
configuration. The transport may have failed after only part of the plan,
including an unverified companion command such as a BGP soft clear, so the
controller locks the device for review instead of claiming success or a clean
failure.

## Manual verification after recovery

Use **Reconcile**, `POST /api/reroutes/{id}/reconcile`. The compatibility
`acknowledge-uncertain` endpoint performs the same evidence-bound operation.
An exact after-state match records the owned change as `reconciled_after`; an
exact before-state match records no lasting change as `reconciled_before`.
Neither matching state causes additional configuration commands. A conflict
leaves quarantine intact. Legacy rows without sufficient snapshots cannot be
automatically reconciled or assigned invented rollback evidence.

Only the resolved action's correlated uncertainty lock can clear; unrelated
locks remain. Known-applied siblings retain ownership and require a newly
previewed inverse. Recovery loads original action IDs, uses recorded parameters,
and reverses only owned mutations. It never reverses a no-op or treats an inverse
as a new mitigation to undo. See [Manual Mitigations](manual-mitigations.md).

## Failure modes

The static frontend has no live state of its own — every failure mode reduces
to the controller and the database. Handle and surface:

- controller down — the SPA (still served statically by Nginx) gets `/api/`
  errors and must show a clear degraded state: last-known data marked stale,
  no live actions possible, manual-trigger disabled with a clear reason;
- database unavailable — the controller degrades safely; **no reroutes** while
  state cannot be persisted (persisting before/after every step is mandatory);
  the API reports the degraded condition to the SPA.

Each failure mode must have a visible UI state and an audit/log entry.
