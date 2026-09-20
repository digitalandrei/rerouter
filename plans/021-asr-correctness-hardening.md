# Current-ASR correctness and performance hardening

Baseline: `441f93d2f8f34a0036230f37ab37cf666e548022`.
Status: implementation complete; software verification passed. Owner-controlled ASR certification and deployment remain separate. This records the user-approved revised
plan, superseding the adversarial draft's timer, ownership, completeness,
notification-upgrade and cadence assumptions.

## Scope and invariant

Fix the thirteen review findings and the directly related crash/cancellation
defects. Use existing telemetry, templates and operator workflows on the current
Cisco ASRs. No IPFIX, expanded analytics, NMS, multi-vendor work or new templates.
Observe/automatic-off defaults, actor-bound previews, verified inverse ownership
and conservative uncertainty remain mandatory. Existing rule firing/recovery
windows must not shrink when collection intervals change.

## Packages

| Package | Work | Status |
| --- | --- | --- |
| A | Typed router evidence, timer source identity, SSH diagnostic redaction | Implemented and verified |
| B | Notification rendering, URL sanitization, legacy delivery repair, fair materialization | Implemented and verified |
| C | Per-dimension collector completeness, persisted coverage and existing status displays | Implemented and verified |
| D | Multi-source recovery ownership, transactional finalization, reconciliation and eligibility | Implemented and verified |
| E | Bounded lock runtime, atomic detection, cancellation, live cadence and flush notifications | Implemented and verified |
| F | Server-side Active Runs filters, summary/detail types, bounded race-safe refresh | Implemented; 76 UI tests and browser load check passed |
| G | Retuning report, migration/load/browser checks, documentation and release package | Implemented and verified |

Sol 5.6 workers implement isolated packages. The coordinator allocates migrations,
integrates changes and owns the final acceptance gate. There are at most three
workers. Database tests are coordinated serially; targeted package checks precede
the complete integrated gate and independent review.

## Reserved migration identifiers

- `20260921000100_recovery_ownership.sql`: package D.
- `20260921000200_flow_bucket_quality.sql`: package C.
- `20260921000300_alert_delivery_repair.sql`: package B.
- `20260921000400_expire_previews.sql`: coordinator; expire unused credentials
  in both `execution_plans` and legacy `action_previews`.
- `20260921000500_flow_publication_barrier.sql`: collector publication generation
  and completeness barrier for chunked contributor registration.
- `20260921000600_recovery_decision_event.sql`: persist the existing
  recovered-awaiting-revert transition without changing historical event values.

Old migration files are immutable. Expected final schema comes from the complete
migration manifest, not a hard-coded count.

## Required behavior

Router reads distinguish matched state, proven mismatch and unproven output.
Command-specific completed-empty filtered output may prove absence; empty
interface/advertisement responses cannot. The timer belongs to the canonical
source before hashing, and successful completion anchors its deadline once.

Recovery derives one consistent original/inverse ownership model, validates all
sources transactionally, retains device/source quarantine membership, and settles
child/source/claim/window/audit state atomically. Successful inverses are never
repeated. Unproven restoration freezes the set; known failure permits fresh
manual preview but blocks unattended retry. Startup/reconciliation use the same
idempotent repair without router commands or invented ownership evidence.

Flow quality is dimension-specific and independent of sampling and per-counter
availability. Missing coverage is unavailable, never zero. Complete measured zero
retains the confidence of its proven base evidence. Cumulative backlog counters
do not poison subsequent buckets. Decisions, observation cursors, events, alerts
and automatic admission markers commit together before external side effects.

Legacy notification repair groups attempts by alert and target, preserves sent
and suppressed work, retry budgets/backoff, and unattempted alerts. Existing
pending duplicates of proven historical success are settled. Explicit recipient
subscriptions remain unchanged. Secret-bearing diagnostics are sanitized before
logging/persistence and historical Teams diagnostics are scrubbed.

Runtime uses bounded admitted work and reusable cancellation-safe lock sessions;
nested locks must not require another session from an exhausted pool. Device
pollers stop cooperatively and never own the lifetime of an active writer.
Scheduling skips missed deadlines; discovery/probes do not delay telemetry.

Active Runs preserves search/source/lifecycle/device text/date semantics with
server pagination and one list plus at most two detail requests per refresh.
Obsolete requests cannot publish state. Timing proposals are dry-run, include
single and aggregate rules, retain duration/threshold/hysteresis controls, scale
sample budgets conservatively, and require clear/disarmed state before applying.

## Validation and operational boundary

Permanent regressions cover all confirmed findings, mixed/multi-source recovery,
crash boundaries, flow loss/confidence, legacy delivery histories, nested locks,
live cadence/cancellation and UI request races. Verify fresh migrations and
upgrades from the 56-migration audit baseline and current 69-migration schema.
Run the complete local software gate, browser checks and representative replay/
load checks (at least 150 active runs and 20 concurrent rules).

Database tests use only approved restricted accounts and dedicated test schemas
on existing services. Never launch a database daemon, kill processes by name,
or operate on system.slice services for cleanup. No real router commands,
notification sends, deployment, arming or live timing changes are authorized by
this implementation. Cisco image certification and owner-controlled observation
remain separate. A release package must compare captured ownership and predicted
repairs rather than requiring globally empty locks or claims.

Final evidence and external certification boundaries are recorded in
[`docs/hardening-verification-2026-09-20.md`](../docs/hardening-verification-2026-09-20.md).


## Integration findings addressed

Integration review additionally found and corrected incomplete contributor
publication, composite-key retention, async future stack growth, compensation
lock-session reuse, source-proof gaps in legacy recovery, timer work occupying
background capacity, unsupervised automatic jobs, and a hot retry loop after flow
evaluation failure. Historical notification repair now preserves a rate-limit
classification while scrubbing capability URLs; proven sent attempts take
precedence over a stale non-sent intent summary.

The frontend browser fixture used 150 runs. Normal refreshes made one summary
request and two selected detail requests, including the recovery child. Its
measured browser memory and request/latency artifact is kept with the release
verification logs; these fixture measurements are not router capacity claims.

Operational/API contracts are recorded in
[`docs/hardening-api-contracts.md`](../docs/hardening-api-contracts.md), migration
checks in [`docs/hardening-migration-validation.md`](../docs/hardening-migration-validation.md),
and offline release/retuning tools in
[`docs/hardening-release.md`](../docs/hardening-release.md).

Final gates: 352 Rust tests on each database engine; 76 frontend tests; strict Clippy, formatting, tooling checks, browser load checks and optimized embedded build. Fresh-schema and 56/69-baseline upgrades passed on both engines against the 75-migration manifest. No live timing change or automatic re-arm was applied.
