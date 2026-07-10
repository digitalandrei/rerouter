# State Recovery

The controller must understand current state after any restart or crash. Because
reroutes move real traffic, the cost of assuming "nothing happened" is wrong
routing. The default assumption after a crash mid-action is **uncertainty**.

## Persisted runtime state

- last device reachability and telemetry health;
- last valid telemetry sample and counter baselines;
- active detection-rule states and consecutive-match counters;
- planned / pending / running / verifying reroutes;
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
5. Start the supervised alert, telemetry, detection, retention, and API tasks.
   Inventory, baselines, and rule state remain durable in MariaDB; SSH sessions
   are opened on demand rather than reconnected at startup.
6. (Aspirational — **NOT implemented.**) Automatic SSH re-verification of the
    routing state on recovery is future work; today the controller does not
    re-read the device on startup.
7. The device stays locked and the reroute stays `uncertain` until an **admin
    acknowledges** it (`POST /api/reroutes/{id}/acknowledge-uncertain`) — there is
    no automatic clear.
```

Do **not** assume no reroute happened just because the process crashed. A
null-route pushed to the device milliseconds before a crash may still be
installed in its routing table.

## Uncertain state handling

For any `uncertain` action:

- show it prominently in the GUI (dashboard + device detail);
- disable automatic reroutes for the affected device (it stays locked);
- send an email/Teams alert according to configured subscriptions;
- require explicit admin acknowledgement (audited) before automatic actions
  resume on that device.

An SSH apply error is uncertain even when a later text check sees the intended
configuration. The transport may have failed after only part of the plan,
including an unverified companion command such as a BGP soft clear, so the
controller locks the device for review instead of claiming success or a clean
failure.

## Manual verification after recovery

Automatic startup re-verification is not implemented. The operator should use
the same IOS `show` evidence used during normal execution
([reroute-engine.md](reroute-engine.md)):

- `show ip route <prefix>` to confirm the `Null0` route is present (RTBH /
  blackhole) or absent (after a withdrawal);
- `show ip bgp neighbors <ip>` to confirm the session is — or is no longer —
  reported as administratively shut;
- compare current device traffic against expectation.

After checking the router, the operator records an acknowledgement. The original
row becomes `failed` with `verification_status = acknowledged`, and only the lock
linked to that reroute is cleared; unrelated manual/device locks remain. If the
configuration must be undone, run the server-previewed rollback after the lock is
cleared. The controller never claims recovered success from an acknowledgement.

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
