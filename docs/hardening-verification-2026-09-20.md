# ASR hardening verification — 20 September 2026

Baseline: `441f93d2f8f34a0036230f37ab37cf666e548022`. This document originally
recorded the pre-deployment software gate. The implementation was subsequently
committed and deployed through `4fcb7ccad8cd1854b841c5ca19c515acd8589ce0` with
schema 76. No automatic action was armed by those deployments.

## Scope delivered

Typed router evidence and canonical timer provenance; complete diagnostic
redaction; multi-source recovery ownership and transactional settlement;
dimension-specific flow completeness; bounded cancellation-safe lock sessions;
durable automatic decisions and supervised workers; cooperative cadence and
bounded discovery scheduling; notification repair; and paginated Active Runs.
Successful known activations release their transient device ownership. Partial
or unproven changes retain source-specific quarantine. Queued condition recovery
is revoked when telemetry relapses, and read-only preparation does not hold the
operator policy fence.

## Software evidence

- MariaDB complete gate: formatting, strict Clippy, 352 Rust tests, Python tooling
  tests, capture SQL validation, frontend checks/build, and embedded UI build.
- Final frontend: TypeScript check and 76 tests in 21 files, including slow refresh
  coalescing, obsolete response cancellation, and retained error evidence.
- Final optimized controller built with `cargo build --locked --release --features embed-ui`.
- Fresh-schema tests and upgrades from 56 and 69 migrations passed on the existing
  MariaDB 11.4 and MySQL 8.4 services. The manifest contains 76 migrations.
- MySQL 8.4: the same 352 Rust tests passed; no failures.

All database work used restricted accounts and only task-created
`rerouter_test_h0920_*` schemas. “Fresh schema” means an empty Rerouter test
database, not a database-server installation. No MySQL/MariaDB installation was
installed, replaced, restarted, stopped, or reconfigured. No query or migration
targeted another project's database.

## Measured fixtures

The Active Runs database fixture contains 150 runs. Six 25-row pages required
30 SELECTs, five per page, including enrichment. The browser exercised actual
pagination/search against a fully mocked API: each normal refresh made one list
request plus two selected detail requests. The final browser run recorded
183,210 response bytes across 24 requests, about 16.4 MB used browser heap,
92,548 KiB Chromium main-process RSS, and correct cancellation of a deliberately
delayed 6.5-second obsolete response. These are fixture measurements, not ASR
or production capacity certification.

Twenty simultaneous evaluation passes over twenty rules committed exactly twenty
firing events, without duplication. On the local test service the complete pass
set took approximately one second. Machine-readable latency, memory, request,
and query measurements are retained in the release evidence directory.

Timestamped replay used the dry-run tool's proposed counts in the real detector.
All twelve transitions across six scenarios preserved firing/recovery windows:
single interfaces, member-limited aggregates, evaluation-limited aggregates,
NULL recovery fallback, disabled counts, and explicit durations. Thresholds,
hysteresis, durations, and bucket denominators remain unchanged. No live cadence
proposal was applied and no rule was re-armed.

## Release boundary

The review package includes reconstructible source, migration hashes, the
optimized controller, frontend assets, and an Observe/automatic-off configuration
reference. Its preflight tooling compares captured ownership and predicted
repairs; it preserves legitimate nonzero locks, windows, and frozen claims.
Production preflight/deployment remains a separate step and must defer during
active execution. Cisco certification still requires owner-controlled evidence
from the exact enrolled IOS/IOS-XE images and router-load checks.

## Follow-up deployment and recovery evidence

The later releases added active-definition locking, direct prepared execution,
durable server-owned manual workflows, and configuration-only recovery scope.
The first direct recovery attempt (bundle 8) was proven `known_no_write`; the
scope repair then allowed bundle 9 to restore all eight eMA3 changes successfully.
Bundle 7 is inactive with zero remaining mutations, and its device windows and
source memberships were released. Production deployment evidence is retained in
`/root/rerouter-deployment-evidence/recovery-scope-repair-20260920`.

The subsequent adversarial-review fixes passed the complete MariaDB software
gate: strict formatting and Clippy, 232 Rust unit tests, every integration suite,
89 frontend tests, tooling checks, production frontend build, and embedded UI
build. The MySQL 8.4 all-target run passed through the corrected lifecycle test;
after the final multi-device rate-scope change, the affected Configuration-only,
bundle-admission, and manual-plan suites passed again on MySQL 8.4. All database
tests used the restricted task schemas and existing services.
