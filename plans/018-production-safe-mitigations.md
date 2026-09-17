# Production-safe Rules and Manual Mitigations

Baseline: `1cce375`. The user approved the complete audit remediation plus a
shared named mitigation library, independent rule copies, temporary run
overrides, exclusive writes, and bundle-wide freeze on uncertainty.

Implementation tracks cover:

- Immutable actor-bound execution plans, complete action preparation, durable
  ownership, exact before/after and inverse state, rate reservations, atomic
  lifecycle publication, startup recovery and read-only reconciliation.
- Complete SSH responses, IOS rejection classification, narrow native-lock
  command handling, physical router identity, exact routing verification,
  shared-policy refusal, prefix-list counts, and forward catalog repairs.
- Named preset CRUD, atomic rule saves/imports, shared ordered builder,
  temporary overrides, progress/history, retained failures and stale-preview
  invalidation, with existing RBAC and legacy route/API compatibility.
- Observation identity and per-metric availability, flow decoder integrity,
  durable fair notification intents, history-aware retention, installation
  permissions, dependency updates and strict test isolation.

The detailed operating contract is [Manual Mitigations](../docs/manual-mitigations.md).
Historical audit findings remain in the September 15 report; this work replaces
the execution assumptions described there rather than claiming that its old
passing tests established safety.

## Implementation status

Implemented against `1cce375`. Following software verification, the owner
authorized commit, push, release build and deployment to EMDD for testing in
observe mode. The original [roadmap](014-full-project-review-roadmap.md)
remains the acceptance checklist. The primary review owns the safety contract
and integration assessment; Sol 5.6 implementation tracks covered execution,
SSH, APIs/editor, telemetry, notifications and installation hardening.

The application now uses the same prepared action engine for named templates,
unsaved Run once, Rules and the legacy manual adapter. The new API and menu,
revisioned preset CRUD, independent rule imports, atomic disarming saves,
temporary overrides, accessible ordering, bulk BGP/MSS expansion, durable
progress/history and reload recovery are implemented. Recovery is tied to
original mutations and never inverts a no-op or a successful inverse.

Integration review additionally closed a mutable-template race at actuation,
replacement-path drift before destructive siblings, final projected-state
drift, inherited recovery ownership, scope/source mismatches, and notification
queue starvation behind old alerts with no recipients. Uncertainty keeps the
whole set frozen and preserves original recovery evidence.

## Executed verification

Initial validation used synthetic data and fake SSH. Database tests used restricted
accounts and newly created `rerouter_test_*` schemas on the existing MariaDB
11.4.12 service. No database daemon, production application data, production
service or router was changed during that implementation phase. Release
preparation subsequently tested isolated schemas on EMDD's existing MySQL
8.4.7 server using restricted accounts and a task-owned SSH tunnel.

| Check | Result |
| --- | --- |
| `scripts/check-release.sh` | PASS: formatting, strict all-target Clippy, all Rust tests, frontend typecheck/tests/build and embedded-UI build |
| Rust tests | 245 passed: 171 library + 74 integration; zero failed/ignored/skipped, including a repeated run against the populated test schema |
| Frontend interaction/unit tests | 8 passed |
| Playwright browser harness | PASS: desktop/mobile, keyboard editor ordering, independent imports, overrides, trigger-only Run once, bulk/MSS, preview/result flow, archived preset and reload/resume |
| Fresh MariaDB migrations | All 67 applied successfully |
| MariaDB upgrade | Baseline 60 migrations plus all seven forward migrations applied successfully with legacy action, reroute, detection and recipient fixtures |
| MySQL 8.4.7 compatibility | All 245 Rust tests passed in isolated schemas; fresh 67-migration installation and baseline-60-to-67 fixture upgrade passed |
| Upgrade evidence | Original JSON preserved; legacy rollback evidence not invented; firing preserved while unproven counters reset; recipients linked; device history FK restricts deletion; observe/automatic-off defaults preserved |
| Missing database configuration | Integration executable fails visibly when `REROUTER_TEST_DATABASE_URL` is absent |
| Diff validation | `git diff --check` passes |
| Failure injection | PASS: before/middle/after-write disconnects, verification-read failure, ambiguous compensation stopping earlier inverses, terminal DB publication failure after mutation, and durable startup quarantine |
| Installer | Isolated prefixed fresh installs under umasks 0022 and 0077, explicit ancestor/file modes, and idempotent reinstalls preserving operator contents/modes; no system installation |
| Rust dependency scan | Refreshed RustSec at `f58ccfe51a5954186716998f01360d1079a8a3a5` retains accepted RUSTSEC-2023-0071 for RSA 0.9.10 and 0.10.0-rc.18, plus RUSTSEC-2024-0388 for derivative. Yanked-version warnings remain for chacha20 0.10.0 and der 0.8.0; the scan is not represented as clean |
| npm dependency scan | Final registry scan passed with zero findings after release authorization |

Toolchain: Rust 1.95.0, Node 22.22.2, npm 10.9.7, Vite 8.0.16. The release gate
log is retained locally under
`/tmp/rerouter-codex-test-20260917/release-gate-final.log`; browser screenshots
are under `/tmp/rerouter-browser-20260917/`. These are local test artifacts,
not deployed monitoring evidence.

Release validation logs, including the MySQL suites and optimized release build
evidence, are retained under `/tmp/rerouter-emdd-20260917/` and
`/tmp/rerouter-codex-test-20260917/release-build.log`. The MySQL pass exposed a
test-only signed/unsigned lock-owner result mismatch; explicit unsigned casting
now makes that assertion portable across both engines. No execution-engine
change was needed for this correction.

The database fault test uses a constraint scoped to its fixture in the dedicated
test schema. The server correctly refused trigger creation under its binlog
policy; neither privileges nor global settings were changed to bypass that
restriction. The constraint is removed by the test.
Cleanup checks `information_schema` before dropping it, avoiding MariaDB's
`IF EXISTS` extension that is absent from the documented
[MySQL 8.4 ALTER TABLE syntax](https://dev.mysql.com/doc/refman/8.4/en/alter-table.html).

## Readiness decision and open acceptance

**Not certified for production actuation.** The software gate passes, but it
does not establish the requested 100% confidence in a distributed router
operation. Keep observe mode and automatic execution disabled. EMDD's live
settings were checked during release preparation and already had that posture;
this report and the deployment authorization are not arming approval.

Remaining release evidence:

- Certify representative IOS/IOS-XE images and account privileges, including
  native exclusivity across management planes, exact output shapes, BGP/forwarding
  convergence, disconnect behavior and multi-router recovery.
- Complete the roadmap's exhaustive process/database fault matrix at every
  execution, verification, finalization and compensation boundary. Current
  automated tests exercise selected interruption, ownership, concurrency,
  persistence and verification cases, not every timing combination.
- Complete any wider roadmap accessibility, deployment and agent-workflow
  acceptance beyond the new editor/execution browser checks; this report does
  not silently close those historical items.
- Retain the documented RSA and unmaintained-dependency risk decisions.

Release progression remains supervised single actions, supervised bundles,
then separately armed automation after the corresponding certification passes.
