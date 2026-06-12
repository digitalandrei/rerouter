//! Reroute executor. Re-checks EVERY safety gate at execution time (even when a
//! rule fired), drives the state machine, persists each step's output, and runs
//! verification. See ../docs/reroute-engine.md.
//!
//! Gate order (any failure aborts + logs the reason):
//!   GATE 0 — operating_mode == enforce. In `observe` mode (the default,
//!   read-only / alert-only) NOTHING executes — automatic or manual. Instead,
//!   render the would-run plan (template + parameters + provider) in dry-run
//!   and attach it to the rule event / alert so operators see exactly what
//!   enforce mode would have done. Then:
//!   automatic enabled (global + per-rule) | template valid | telemetry fresh |
//!   confidence high | provider reachable + actions_enabled | target within
//!   permitted prefixes | no running action on asset | not in cooldown |
//!   no global/asset lock | no unresolved `uncertain` | (manual) authz + re-auth.

// TODO(milestone 3): evaluate_gates(ctx) -> GateDecision; execute(plan) with
// before/after persistence and verification; on ambiguity -> Uncertain + lock.
