# eMA3 configuration-only testing and policy clarity

User authorized a separate eMA3-only saved mitigation and explicitly selected
configuration-only verification for lab tests with Idle BGP peers. The assistant
must never execute mitigations, reverts, router writes, or notification tests.
The user performs those tests after deployment. Preserve eMA1/eMA2 restrictions,
the original preset, all rules, Observe mode, and automatic-actions-off.

## Work and ownership

- Sol `ema3_preset_prepare`: guarded creation SQL, pure and temporary-table tests;
  then backend/frontend/config deployment tooling. Parent applies reviewed SQL.
- Sol `policy_ux_clarity`: readable policy inventory, explicit preservation and
  filtering explanations; lab verification choice and truthful preview/history.
- Sol `lab_verification_backend`: typed verification mode, eligibility, immutable
  authority/provenance, apply/revert/compensation and recovery restrictions.
- Astra parent: contracts, review, integration acceptance, application-data
  creation and deployment orchestration. Astra `lab_verification_design` supplied
  a read-only safety design; no implementation by Astra.

## Saved definition

Create `e-manuel-apply-ema3-test`, derived from the eight eMA1 steps of original
preset 1 revision 4. Target only device 3 (eMA3): six Akamai peers
23.45.23.197/199/201/203/205/207 select `pfx-to-viva`; Po1 MSS becomes 1436; COLT
213.249.122.145 selects `no-export`. Preserve order and every original action.
The cached eMA3 lists permit only 194.105.142.0/24 or deny all respectively.
Do not target M247 or install router policies. Creation writes only definition,
action, and system audit rows; no execution plans, bundles, timers, or locks.

Artifacts: `/tmp/rerouter-workflow-review-20260919/ema3-preset/`.
The creation SQL passed temporary-table integration testing on the existing
restricted MariaDB schema, including reapplication and prefix/ge broadening
refusal. Four pure preparation tests passed. Parent creation session: 60970;
read back and verify its outcome before continuing any creation operation.

## Lab contract

- `verification_mode`: `routing` (default for missing legacy fields) or
  `configuration_only`; unknown values fail.
- Explicit manual per-run choice. Saved definitions confer no execution scope.
- Only one designated device per lab run, all enabled actions using
  `bgp_export_policy_set` or `iface_tcp_adjust_mss`.
- `[[safety.configuration_test_devices]]` contains `device_id`, `host`, `port`,
  `pinned_host_fingerprint`. Default empty; configure only the captured eMA3
  identity. Recheck identity at preview, consumption, and actuation.
- Read-only `GET /api/manual-mitigations/capabilities` exposes eligible IDs and
  supported lab templates to viewers. No probing/SSH during capability reads.
- Scope is bound into request/token snapshot, prepared action, inverse, bundle
  provenance, and execution equivalence. Revert and immediate compensation
  inherit the original scope; callers cannot downgrade a production inverse.
- Omit only BGP advertisement evidence when preparing permitted lab export
  policy actions. Preserve exact configuration snapshots, original attachments,
  complementary policies, ordering, drift refusal, locks, command allowlisting,
  and read-back verification. MSS retains its ordinary configuration evidence.
- Deny rule/automatic starts and timer recovery for configuration-only runs.
  Immediate manual-origin failure compensation and explicit manual revert remain
  available through their normal safety gates and immutable provenance.
- Report successful lab outcomes as configuration verified, routing not verified;
  never infer routing success from a configuration-only run or reconciliation.
- No database migration anticipated; durable scope lives in existing JSON.

## Verification and deployment

Use fake SSH and existing dedicated test schemas only. No new database daemons
and no name-based process cleanup. Existing restricted MariaDB URL is private at
`/tmp/rerouter-codex-test-20260917/database-url`; never print credentials.

Required acceptance: legacy/routing behavior unchanged; Idle lab configuration
apply/revert/compensation; default/unknown scope; token tampering; mixed or changed
targets and pinned identity drift; automatic/timer refusal; configuration drift;
restart/reconciliation provenance; UI eligibility, invalidation, labels, timers.
Run appropriate Rust/frontend release gates and mocked desktop/mobile checks.

Deploy only after acceptance. Back up old matching controller, configuration,
environment, and frontend. Preserve SESSION_SECRET. Before new service exposure,
restore matching old artifacts on failure. After new start is attempted, stop
and preserve evidence on failure rather than rolling back possible new lab
records. Only the application controller service may be restarted.
Verify health/version/schema/config/definitions read-only; never invoke a live
preview, mitigation, revert, discovery, notification test, or reconciliation.

## Integration progress and owned test resources

- Live definition creation succeeded and readback verified: preset 2,
  `e-manuel-apply-ema3-test`, revision 1, eight actions targeting only device 3.
  Original preset 1 revision 4 and all 16 actions unchanged. Runs/bundles/locks
  remain zero, rules remain 13. Backup:
  `/root/rerouter-backups/ema3-definition-55fed2a0639f`.
- UI policy clarity and lab flow currently pass 51 frontend tests, typecheck,
  production build. Root reviewed status/capability-outage handling and requested
  those fixes; completed. Policy clarity mock browser pass passed; new lab-mode
  mock harness is prepared but not yet run after final backend contract freeze.
- Backend core has passed Clippy, library tests (187), and focused preparation/
  lifecycle tests. Root review demanded real preview/consume/locked execution,
  explicit revert, induced compensation, and negative authority/identity tests;
  Sol backend is implementing these. Positive MSS-only core test passed, but
  BGP+MSS+withdraw stateful fake coverage is still required before acceptance.
- Remote MySQL test-only resources owned by this session:
  schema `rerouter_test_ema3_lab_20260919_11141e`, account
  `rrt_test_ema3_0919_11141e` at localhost and 127.0.0.1, grants only that schema.
  Private URL and ownership manifest in the task artifact directory:
  `mysql-lab-database-url`, `mysql-lab-owner.json`. Fresh migration 69 initialized
  successfully using the previously verified 69-migration binary in --migrate
  mode. No scheduler/API/router probe was started.
- Owned MySQL test SSH tunnel: tool session 84684, PID 2193633, localhost port
  13381, control socket `mysql-lab-ssh.sock` under the artifact directory. PID,
  start ticks, cgroup, and argv recorded in `mysql-lab-tunnel.json`. Close only
  through this owned socket after tests, then remove the one owned schema and
  two owned account entries; never stop either database service.
- Prepared live config is `config.lab.toml`; original `config.before.toml`,
  hashes in `config-manifest.json`, exact four-field eMA3 identity in private
  `ema3-lab-identity.json`. Only the allowlist entry is added; no live config
  change has happened. Deployment tooling and its recovery mock are prepared
  and reviewed, but not deployed. No mitigation, revert, or router write occurred.

## Final software acceptance

Both full Rust runs passed: 279 tests on MariaDB and 279 on MySQL 8.4. The complete
release gate passed strict Clippy, formatting, frontend typecheck, 51 frontend
tests, frontend production build and embedded-UI compilation. Optimized release
build passed. Policy and lab-mode mocked desktop/mobile checks passed; only
intercepted synthetic saves/previews were used, never a live run.

The stateful fake now proves BGP policy plus MSS apply, explicit whole-run revert,
and compensation of a proved no-write MSS failure after an earlier BGP change.
The apparent fixture stall was the intentional 30-second unknown-effect verifier,
not a production lock bug; unknown effects remain quarantined. Non-vacuous
compensation assertions prove the original mutation, inverse and restored state.

Live production budget is 3 actions/600 seconds and would not fit the new 8-step
test. A separate per-lab-device budget defaults to 32/600, atomically reserved;
normal and lab counters are isolated. Tests cover eight-step capacity, exhaustion
and concurrent admission. The original production limit is unchanged. Optional
LabDevice budget fields have serde defaults; deployed identity still has four
explicit fields. No schema migration is required.

Deployment remains the final step at this commit. Use the reviewed deploy script,
config manifest and staged hashes. Do not execute or revert any live mitigation.

## Deployment completed

Release `4129744de24ee346dfc9ae34e7238d1bd1ee356c` is deployed and read-only
verified: schema 69, 13 rules, 19 templates, only lab device 3. The original and
new definitions are unchanged by deployment; runs, bundles and active locks
remain zero. The environment is unchanged. All 46 public frontend files match.
Backup: `/root/rerouter-backups/ema3-lab-4129744de24e`.
See `docs/ema3-lab-release-20260919.md` for acceptance evidence.

The owned MySQL test schema/account and tunnel were removed, and the private
test URL was deleted. The temporary deployment SSH connection was closed using
its own control socket after process identity verification. Database services
were never stopped. No live mitigation, revert or router write was performed.
