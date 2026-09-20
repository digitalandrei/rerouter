# ASR hardening release preparation

These tools prepare evidence only. They do not call the Rerouter API, write the
database, send router commands, deploy files, arm automation, or send
notifications. Run the final software, migration, replay, load, and browser gate
from the integrated source before producing the release directory.

## Cadence retuning dry run

Export a sanitized JSON snapshot containing `captured_at`,
`metrics_rollup_seconds`, `settings`, `devices`, `interfaces`, `rules`, and
`owned_run_rule_ids`. Rules include their metric, aggregation kind, complete
member-interface IDs, `recovery_mode`, current lifecycle and automatic flag, thresholds,
durations, and firing/recovery sample counts. No credentials belong in this
snapshot.

```bash
python3 scripts/retune-sample-counts.py snapshot.json \
  --poll-interval 1=10 --poll-interval 2=10 \
  --output retune-report.json
```

The report is a dry run. It preserves thresholds, recovery hysteresis and all
duration fields. For counter-based SNMP rules it computes the effective old and
new evidence cadence, using the slowest member plus the metrics rollup cadence
for aggregate rules, and rounds counts upward so nominal windows cannot shrink.
Zero disables a count and remains zero. Flow rules use time-window persistence
and are not rewritten. A NULL recovery threshold is displayed with its resolved
threshold fallback without changing the stored NULL.

Only faster device intervals of at least five seconds are accepted. Every
affected rule must be clear, have no owned active run, and have automatic
execution disarmed. Observe mode and the automatic master switch being off are
also required. Any ambiguity blocks all request output. When unblocked, the
ordered request list increases rule counts before shortening device polling;
rollback restores device cadence before lowering counts. It never emits a
request to re-arm automation. Requests use the API's partial-update `PUT`
routes for both rules and devices; they do not invent unsupported `PATCH`
routes or alter action revisions.

An optional capture mode reads a URL from the explicitly named file and issues
only the SELECT statements embedded in the script through the local `mysql`
client. It never reads `.env`. Supply the application metrics-rollup cadence
explicitly because it is configuration, not database state:

```bash
python3 scripts/retune-sample-counts.py --db-url-file /secure/readonly-db-url \
  --metrics-rollup-seconds 10 > sanitized-snapshot.json
```

Use only the approved restricted account and approved capture target. Review the
snapshot before moving it into release evidence.
The capture command refuses `root`, removes inherited `DATABASE_URL`, and accepts
only the `rerouter` schema or a dedicated `rerouter_test_*` schema. It invokes
the client with `--no-defaults` first, passes the decoded password through
`MYSQL_PWD`, and honors an explicitly percent-encoded `socket` URL parameter.

## Timing evidence

Structured `hardening_timing` records distinguish collection, evidence
advancement, bucket commit, durable decision persistence, and router execution.
`flow_bucket_committed` records include the unchanged bucket width so an offline
report can compute close-to-commit delay independently of rate denominators.
Incomplete or interrupted stages retain that outcome rather than appearing as
successful latency samples.

```bash
python3 scripts/report-hardening-timing.py controller-json.log \
  --before-replay before.json --after-replay after.json --output timing.json
```

The replay files contain actual engine transitions with a shared scenario ID,
rule ID, transition, elapsed seconds, and explicit threshold-window start. Missing
or mismatched transitions fail validation. The integration replay obtains counts
from the dry-run tool and checks single-interface and aggregate collection,
aggregate evaluation cadence, disabled counts, explicit durations, and recovery
fallbacks. This fixture evidence does not select a live ASR polling interval.
Router-load and exact IOS/IOS-XE-image validation remain owner-controlled steps.

## Release evidence directory

```bash
python3 scripts/prepare-hardening-release.py \
  --repo "$PWD" --output /tmp/rerouter-hardening-release \
  --controller backend-rust/target/release/rerouter-controller \
  --frontend frontend/dist \
  --baseline stopped-before.json --candidate stopped-after.json \
  --predicted-repair reroute_bundles.42.remaining_mutations \
  --predicted-repair alert_deliveries.91.delivery_intent_id
```

The generated manifest records the source `HEAD`, hashes every current source
file, the binary dirty patch, each migration discovered from the migration
directory, the controller binary, and the complete frontend artifact directory.
Migration count is derived from the manifest. A deterministic
`source-package.tar.gz` contains tracked and non-ignored untracked source files,
the migration manifest, an Observe/automatic-off candidate reference, and any
explicitly supplied controller/frontend artifacts. This archive is the
reconstructible candidate; `dirty.patch` remains a convenient review view and
is not expected to carry untracked files. `.env`, ignored secrets,
`node_modules`, and `target` remain excluded unless a binary or frontend
directory is explicitly supplied as an artifact. The output directory must be
outside the repository so the package cannot capture itself.

`candidate-safety-reference.json` is reference evidence only. The tool does not
read or change live operating mode or automatic-action settings.
`capture-read-only.sql` is reference SQL for owner-controlled stopped-window
captures; it is not executed by the tool.

Normalized stopped-window snapshots must contain every section emitted by
`capture-read-only.sql`: bundles, execution plans, reroutes, bundle-action
ledgers, locks, device windows, window-source memberships, recovery-attempt
sources, legacy action previews, alert deliveries, and alert delivery intents.
On an older schema, optional ownership/intent sections are present as empty
arrays through guarded reference queries. Missing sections are an error.

Baseline comparison rejects active planned/pending/running/verifying/
compensating execution and claimed/running recovery. Frozen claims for blocked
recovery are preserved and compared, just like quarantine membership. It does not demand globally empty
locks: ordinary unresolved safety locks remain visible in the report. Every
changed historical field must be named as a predicted repair. Consumed preview
snapshots/hashes/materialization links and persisted inverse/ownership evidence
cannot be waived. Alert delivery history permits only explicitly predicted
intent links and URL-error scrubs; identities, outcomes, and timestamps remain
fixed.
Unused preview/plan expiry and repaired intent fields require explicit predicted
markers. Preview consumption, hashes and actor/scope identity remain protected.
New delivery-intent rows require explicit `alert_delivery_intents.ID.__row__`;
their target identity and creation evidence cannot later be waived.
New or removed ownership rows require an explicit composite identity marker such
as `device_change_window_sources.7:42.__row__`; ordinary history rows cannot be
added or removed through this escape hatch.

The manifest does not certify Cisco images, router behavior, or model/source
approval. Record those owner-controlled results separately. The prepared
directory is review input; deployment remains a separate explicit operation.

The existing named `deploy-*-release.sh` scripts are pinned to earlier release
artifacts and schema baselines. They are not deployment commands for this
package. Use its migration manifest and the stopped-window comparison when a
separate deployment is authorized; preserve nonzero safety ownership and defer
while execution is active.

The package intentionally omits dependency caches, compiler/toolchain binaries,
container images, database dumps, credentials, live configuration, and router
captures. It does not prove that the optional controller/frontend artifacts were
built from the archived source; their hashes make that separate build attestation
possible. It performs no deployment, migration, API call, notification, mode
change, or automation arming.
