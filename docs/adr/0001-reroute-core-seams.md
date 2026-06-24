---
status: accepted
date: 2026-06-24
---

# Deepen the reroute core behind an SSH port and a typed Reroute Guard

To make the safety-critical reroute path unit-testable without a real device or
database, the reroute core is restructured around two seams: an `SshExecutor`
**port** (russh is one adapter, an in-memory fake is the other) so the two-phase
apply/verify state machine can be driven with canned device output, and a
`RerouteGuard` module that concentrates every safety gate behind a typed
`BlockReason`, with a pure `decide(GateInputs)` core so gate *precedence* (the
order in which maintenance lock, device lock, cooldowns, and the rate limit
apply) is testable with no I/O. The `Rerouter` keeps one public `execute()`
method, so the API contract and callers are unchanged.

## Considered options

- **SSH port only** — unlocks the pure verdict logic but leaves the safety gates
  scattered and untyped.
- **SSH port + Reroute Guard** (chosen) — the highest-leverage, safety-relevant
  testability for the cost; the gate precedence becomes assertable.
- **Full functional-core / imperative-shell** (also extract a persistence/store
  seam) — rejected for now: see Consequences.

## Consequences

- **The DB store seam is deliberately deferred.** The reroute state writes stay
  on inline `sqlx`, so `execute()` outcome tests run against a CI-gated test
  database (the existing `pool_or_skip()` pattern), not a pure in-memory store.
  This is an *explicit no*, not an oversight — a future architecture review
  should not re-suggest the store seam without a new reason.
- **The double-apply race stays a real-DB integration test.** It is closed by a
  MariaDB `GET_LOCK` advisory lock; a faked store could not exercise it, so the
  honest test is against a real database. Pulling the store seam forward would
  give false confidence here.
- `BlockReason` must render to the exact strings `execute()` returns today so the
  API and frontend are unaffected.
