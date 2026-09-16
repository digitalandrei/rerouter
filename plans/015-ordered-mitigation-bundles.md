# Plan 015 — Ordered mitigation bundles (one-click multi-action mitigation)

**Status:** DONE — implemented, full local gate green (2026-09-16)
**Priority:** P1 (supersedes and implements roadmap item [14.07](014-full-project-review-roadmap.md))
**Origin:** Customer request (2026-09-16) — a single one-click mitigation that both
withdraws the attacked prefixes from the ISP upstreams and advertises them toward a
scrubbing provider (Prolexic), across two routers: 2 + (6 × 2) = **14 actions**.

## Doctrine position

The request as phrased ("one global template") is **refused by doctrine**; the
shape it asks for is **blessed**:

> A **combination** … is expressed as an ordered set of `rule_actions` on one rule —
> each action keeps its own verification and rollback — not a single opaque composite
> template. The UI may offer a one-click preset that attaches such a bundle.
> — [docs/doctrine.md:341-345](../docs/doctrine.md)

So: no composite template. One rule, 14 ordered `rule_actions`, one preview, one
confirmation, one audited bundle.

## Why it does not work today (all verified at `d9bc4a9`)

| # | Defect | Effect on a 14-action bundle | Evidence |
|---|---|---|---|
| 1 | `effective_cooldown` reads durable history without excluding the current bundle | action #1 blocks the other 13 (rule 900s) and same-device siblings (300s) | `reroute/guard.rs:305-312` |
| 2 | Global rate limit 3 per 600s, counted per action | refuses from action #4 on | `config.rs:269-272`, `guard.rs:352-377` |
| 3 | Best-effort loop, `rollback_of_reroute_id: None` | ISP withdrawn + scrubber advertise failed = **black-hole**, no compensation | `api/rules.rs:1329-1347` |
| 4 | `uncertain` locks the device | blocks the corrective rollback too | `reroute/executor.rs:742-752`, `guard.rs:423-433` |
| 5 | Synchronous HTTP, ~28 SSH sessions | Nginx cuts at 120s → 504 with the preview token already consumed | `deploy/nginx/emdd.vivanet.ro.conf:77`, `ssh/mod.rs:40` |
| 6 | UI never sends `position` | the safe order (advertise before withdraw) is not guaranteed | `api/rules.rs:1510`, `frontend/src/lib/api.ts:893-902` |

Defect 1 is audit finding [SPEC-13](../docs/audit-2026-09-15.md), P1, unremediated.

## Design

### Bundle identity

A **bundle** is one authorized activation of one rule's ordered action set. New
table `reroute_bundles`; every sibling `reroutes` row carries `bundle_id`.

- Cooldown history excludes **only** previously authorized siblings of the same
  bundle. Unrelated device/rule cooldowns are untouched.
- Global rate limiting keeps **per-action** accounting (roadmap 14.07 is explicit:
  do not disable it to make a bundle pass). Instead admission becomes
  **all-or-nothing**: a bundle reserves its full size up front under the global
  advisory lock. Either the whole bundle fits the remaining budget or it is
  refused before anything executes. This is strictly safer than today, where the
  budget is consumed mid-bundle and leaves a partial mitigation.
- Deployments running bundles larger than the budget must raise
  `global_action_rate_limit_count` deliberately. The default is **not** changed.

### Ordered execution and failure policy

Execution follows `position`, sequentially. New per-bundle `failure_policy`:

| Policy | Behaviour |
|---|---|
| `abort_and_compensate` (default for new bundles) | stop at the first non-success; roll back already-succeeded siblings in reverse order |
| `abort` | stop at the first non-success; leave applied siblings in place |
| `continue` | current best-effort behaviour; preserved for existing callers |

The safe ordering for the customer's case is additive-first: advertise to the
scrubber (positions 0–11), then withdraw from the ISP (positions 12–13). With
`abort_and_compensate`, a failure in the additive phase aborts **before** anything
destructive runs, so the black-hole window never opens.

Compensation runs as `trigger_type: "rollback"`, which `guard::decide` already
exempts from cooldowns and the rate limit (`guard.rs:185-199`).

**Compensation cannot cross a device lock.** If a sibling ends `uncertain` the
device is locked pending admin acknowledgement, and doctrine forbids acting
through that lock. The bundle then ends `compensation_blocked` with a critical
alert naming the exact siblings still applied. This is reported, never silently
retried.

### Asynchronous execution

Both activation paths form a bundle — the supervised apply and unattended
automatic rule activation — because the cooldown self-block and the half-applied
failure mode hit automatic execution just as hard, and there nobody is watching.
`BundleRun::manual` / `BundleRun::automatic` bind `trigger_type`, which is what
selects the gates: `guard::decide` enforces the `automatic_actions_enabled` master
switch and verify-or-refuse ONLY for `"automatic"`, so running an automatic
activation under `"manual"` would silently disarm both. The constructors make that
mismatch unrepresentable rather than merely documented.

`POST /api/rules/{id}/apply` with `dry_run: false` in enforce mode returns `202`
with a `bundle_id` and no longer blocks on SSH. Progress is read from
`GET /api/reroute-bundles/{id}`. Dry-run (preview) stays synchronous and unchanged,
so preview-token binding is untouched.

### Frontend

- `position` sent explicitly on every `addAction`, with reorder controls.
- Bulk add: multi-router × multi-prefix in one form (cartesian product), replacing
  ~110 interactions with one.
- `ApplyMitigationDialog` polls the bundle and shows per-action progress.
- The three-step preview → token → execute flow is **unchanged** — it is a
  doctrine gate, not friction to remove.

## Acceptance

- Ordered same-device and cross-device bundles complete under shipped default
  cooldowns; unrelated device/rule cooldowns still block.
- A bundle whose size exceeds the remaining rate budget is refused whole, with
  nothing executed.
- A mid-bundle failure under `abort_and_compensate` leaves no applied sibling.
- A mid-bundle `uncertain` leaves the device locked, the bundle
  `compensation_blocked`, and a critical alert listing the still-applied siblings.
- Restart during a bundle marks in-flight siblings `uncertain` and locks their
  devices (existing recovery, now bundle-aware).
- Observe mode still renders all 14 would-run plans and executes nothing.

## Stages

| Stage | Content | Status |
|---|---|---|
| A | Migration, bundle identity, cooldown exclusion, all-or-nothing admission | DONE |
| B | Ordered runner, failure policy, compensation | DONE |
| C | Async execution + bundle progress API | DONE |
| D | Frontend: position, reorder, bulk add, progress | DONE |
| E | Docs (reroute-engine, database, runbook) | DONE |

## Defect found and fixed while testing

`outstanding_bundle_actions` summed reserved capacity with `SUM(...)`, which MariaDB
returns as DECIMAL. Decoding that into `Option<i64>` FAILS, and the fail-closed
fallback (`i64::MAX`) then refused every bundle while reporting an ordinary
rate-limit refusal. It only manifests once a second bundle exists, so a clean-database
test passed for the wrong reason. Fixed with an explicit `CAST(... AS SIGNED)`, and
`reserved_capacity_of_another_bundle_blocks_admission` now asserts the reported count
is the real reservation (~4995) rather than merely that a refusal happened.

## Verification (2026-09-16, disposable MariaDB 11.4.12 on 127.0.0.1:19315)

- `cargo fmt --check` PASS; `cargo clippy --locked --all-targets -- -D warnings` PASS.
- `cargo test --locked --all-targets` PASS — **116 tests**, including 4 new DB-backed
  bundle tests, 3 new `BundleRun`/policy unit tests and a route-shape conflict test;
  re-run repeatedly with zero failures.
- Negative control: reverting the cooldown exclusion makes
  `bundle_sibling_survives_cooldown_but_a_stranger_does_not` fail with
  `left: Some(<timestamp>), right: None`, and reverting the `CAST` makes the
  reservation test fail with `recent = i64::MAX`. Both tests pin real defects.
- `npm run typecheck` PASS; `npm run build` PASS.
- The migration re-applies cleanly against an already-migrated schema (the
  `information_schema` guards make a partially-applied run safe).
- NOT done: no end-to-end run against a real IOS device, and no test drives a full
  bundle through the executor with a fake SSH seam (the repo has no such harness —
  a standing gap noted in the 2026-09-15 audit). Compensation and the async runner
  are therefore verified by construction and unit-level gates, not by execution.
- NOT done: the new SQL was exercised on MariaDB 11.4 only. The customer box runs
  **MySQL 8.4**, where this project has already been bitten by a cross-engine
  difference (prepared `START TRANSACTION`). `reorder_actions` uses the required
  `pool.begin()`/`commit()` pattern and the lint test enforces it, but the new
  aggregate read and the migration should be run once against a MySQL 8.4 scratch
  schema before deployment.
