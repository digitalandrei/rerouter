# State Recovery

The controller must understand current state after any restart or crash. Because
reroutes move real traffic, the cost of assuming "nothing happened" is wrong
routing. The default assumption after a crash mid-action is **uncertainty**.

## Persisted runtime state

- last device reachability and telemetry health;
- last valid telemetry sample and counter baselines;
- active detection-rule states and consecutive-match counters;
- pending / running / verifying reroutes;
- last step output and verification status per action;
- active locks and cooldowns (device-scoped);
- device + interface inventory and discovered BGP peers/prefixes.

## Controller startup sequence

```text
1. Load assets and providers.
2. Load monitored assets and rules.
3. Load last telemetry baselines.
4. Load active rule states.
5. Find reroutes in state pending / running / verifying.
6. Mark unresolved running reroutes as `uncertain`.
7. Apply a safety lock to each affected device (`auto_crash`).
8. Reconnect telemetry + device SSH sessions.
9. Re-read actual routing state from the affected device over SSH.
10. Attempt verification where possible (does `show ip route <prefix>` still
    show a `Null0` route? does `show ip bgp neighbors <ip>` report the session
    as administratively shut?).
11. Clear the lock only if verification proves the outcome, or an admin
    acknowledges it.
```

Do **not** assume no reroute happened just because the process crashed. A
null-route pushed to the device milliseconds before a crash may still be
installed in its routing table.

## Uncertain state handling

For any `uncertain` action:

- show it prominently in the GUI (dashboard + device detail);
- disable automatic reroutes for the affected device (it stays locked);
- send an email alert;
- require explicit admin acknowledgement (audited) before automatic actions
  resume on that device.

## Verification on recovery

Recovery leans on the same verification used during normal execution
(see [reroute-engine.md](reroute-engine.md)) — an IOS `show` read over SSH,
judged by expect-present / reject-absent matching:

- `show ip route <prefix>` to confirm the `Null0` route is present (RTBH /
  blackhole) or absent (after a withdrawal);
- `show ip bgp neighbors <ip>` to confirm the session is — or is no longer —
  reported as administratively shut;
- compare current device traffic against expectation.

If verification confirms the intended end-state, the action can be resolved to
`succeeded` (or rolled forward); if it proves the action did not take effect,
resolve to `failed`. Only genuine ambiguity stays `uncertain`.

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
