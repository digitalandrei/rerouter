# Logical workflows, policy changes, and durable recovery

Approved implementation baseline: `5b5326f` (2026-09-19).

## Authorization and constraints

- Sol 5.6 agents implement; Astra plans and reviews integration/safety.
- Implement, validate, convert compatible EMDD application definitions, and deploy.
- **Never execute a mitigation, revert, or test action on any live router.**
  No eMA1/eMA2 actions, and eMA3 testing belongs to the user after deployment.
  Do not clear firing rules, arm automation, or send test notifications.
- Preserve unrelated router configuration, application credentials, sessions,
  audit evidence, and rule conditions. Router prerequisite configurations are
  documentation only; do not install them during deployment.
- Use existing DB services and dedicated restricted test schemas with fake SSH.
  Never launch a database daemon or stop server services as test cleanup.
  Session-owned processes require captured and reverified identities for cleanup.

## Latest user correction: Observe permits explicit manual execution

The approved plan originally retained Observe as entirely read-only. The user
explicitly superseded that on implementation: manual mitigations must remain
available in Observe mode with automation disabled. Implement this consistently:

- Observe disables autonomous execution; authorized manual runs and manual
  reverts require an exact server preview and explicit confirmation in either mode.
- Inspection never grants execution authority. Operator previews can issue
  one-use authority in Observe; preview itself never changes router configuration.
- Automatic starts, condition recovery, and timed recovery require Enforce and
  the automatic master switch. Show automatic recovery as paused when disallowed.
- Keep the shipped Observe / automation-off defaults. Remove contradictory
  read-only/no-manual claims from code, tests, UI, docs, and examples.
- This capability is for the user. Agents must not exercise it on live devices.

## Accepted product behavior

- Manual Mitigations: searchable list, Add at upper right, inline Run/Revert/Edit/
  Delete; separate details/editor/run routes; dirty-state protection; archive
  definitions without changing active runs/history; Draft/Needs setup/Ready.
- Share Actions and revert evidence across definitions, rules, and runs.
  Per router show Before, After all actions, After revert, diff, policy contents,
  exact commands and verification evidence. Apply projections sequentially.
- New Change BGP export policy selects router/peer and existing prefix list or
  route map. Change only that direct outbound attachment; preserve the other.
  Capture exact original binding and policy content, including IPv4 AF context;
  reject inherited/ambiguous unsupported contexts. Keep route-map changes
  manual-only. Label legacy entry mutations without repurposing their IDs.
- Policy inventory exposes list entries (sequence/action/prefix/ge/le), map
  clauses/matches/sets/dependencies, bindings, freshness, and completeness.
- Mitigations has URL-backed Active/Detections/Alerts/History tabs. Active state
  depends on remaining changes, separately from execution success.
- Whole-run revert uses original persisted inverses in reverse order. No-op
  actions own no inverse. Drift refuses writes; uncertainty freezes recovery.
- Manual runs optionally request Revert after a duration; default is manual.
  Persist authorization/deadline, starting after successful activation; claim
  recovery atomically. Take manual control cancels future automated recovery.
- Rules separately configure clear conditions and automatic revert. With owned
  changes and auto revert off, show recovered/awaiting manual revert, retain
  ownership and prevent reactivation. Preserve old behavior through backfill;
  defaults for new automatic recovery preferences are off.
- Remember me: seven-day absolute maximum, same one-hour idle timeout (explicit
  user choice). Preserve DB sessions/signing key across restart. Network/5xx means
  reconnecting, only authentication rejection means login. No mutation retries.
- Harden resource states throughout: loading/current/stale/confirmed empty/
  unavailable/forbidden, timestamp and retry. Never synthesize healthy defaults.
- Repair keyboard selectors/autocomplete/sort/navigation, focus and labels;
  preserve shell while lazy routes load. Group navigation, contextual deep links,
  URL filters, paginated audit/details, truthful rule/flow descriptions.

## Live EMDD inventory from planning (read only)

Application server: `root@89.136.200.206`, SSH port `2222`; host `ematrix`.
Service `rerouter-controller.service`, working directory `/srv/rerouter`.
Database MySQL 8.4, 67 applied migrations through `20260917000700`.
Observe, automatic actions false, global maintenance false. No bundles, reroutes,
or device locks. Three devices: eMA2 (id1), eMA1 (id2), eMA3 (id3).

13 rules (IDs 1,4,5,6,7,9,10,11,12,13,14,15,16), zero actions on every rule.
Rules 4/5/7 were firing; preserve state. Rule1 disabled, others enabled; automatic
and manual-apply flags false. Preserve all targets, conditions, thresholds, and
current detection behavior. Labels may be misleading: display actual conditions
alongside names instead of silently changing thresholds or target interfaces.

18 predefined templates, IDs4..21. One saved manual set: id1,
`e-manuel-apply`, revision3, 16 enabled ordered steps:

1. Twelve `bgp_advertise_add` steps for 194.105.142.0/24 on Akamai peers:
   eMA1 .197,.199,.201,.203,.205,.207 and eMA2 .209,.211,.213,.215,.217,.219
   in 23.45.23.0/24, all currently bound to `no-export`.
2. MSS1436 on Po1 of eMA1 and eMA2.
3. Two `bgp_advertise_remove` steps on COLT: eMA1 213.249.122.145,
   eMA2 213.249.122.169, currently bound to `pfx-to-viva`.

Real direct bindings are inside `router bgp 34501 / address-family ipv4`.
`no-export` denies all. eMA1 `pfx-to-viva` permits 194.105.142.0/24 then denies
all; eMA2 additionally permits 194.102.117.0/24. Lists are shared with peers,
including M247 (which also has outbound `prepend-3`). Do not change list contents.

User explicitly chose **preserve only 194.105.142.0/24 scope**:

- eMA1 six Akamai bindings -> pfx-to-viva; COLT -> no-export; retain MSS.
- eMA2 needs a dedicated list permitting only 194.105.142.0/24 for Akamai, and a
  list retaining 194.102.117.0/24 while excluding 194.105.142.0/24 for COLT.
  Neither suitable policy exists; document prerequisites, keep all seven dependent
  steps Needs setup and block the complete set. Retain MSS and all16 steps.
- Recreate saved definition as a versioned draft; retain a restorable prior export
  and conversion report. Current deletion candidates: none. Do not delete merely
  stale, incomplete, or fixable definitions, or any history.
- Backup application data before conversion. Report every preserved/converted/
  blocked/archived item and why. Never auto-provision router prerequisites.

## Work tracks and shared seams

1. `policy_backend` (Sol): policy inventory/action/preparation/projection,
   SSH allowlist and scope, migration `20260919000100`, focused tests.
2. `lifecycle_backend` (Sol): draft validation, shared previews/authority, whole-run
   recovery/timers/rules, API routing, migration `20260919000200`, focused tests.
3. `auth_foundations` (Sol): auth/session regression, resilient shell, keyboard
   selectors, shared resource-state primitives. Optional migration003 only if needed.
4. Subsequent Sol tasks: core manual/run/policy UI and API integration; broad
   page hardening/audit; documentation/conversion/release tooling.
5. Astra: contract coordination, source/diff and safety reviews, acceptance and
   deployment orchestration. No live router testing.

Existing ActionDraft uses `reroute_template_id`, `device_id`, `params`, `enabled`.
Reuse it for inspection. Missing policy parameters/references may be draft-valid;
unknown template/device foreign keys are not part of this feature.
Suggested endpoints: cached `GET /api/devices/{id}/routing-policies`, authority-free
`POST /api/action-sets/inspect`, paginated `GET /api/reroute-bundles`, whole-run
`POST /api/reroute-bundles/{id}/revert`, `POST .../{id}/take-control`.

## Acceptance checklist

- [x] Saved list/details/editor CRUD, readiness, dirty state, RBAC, active-run selection.
- [x] Complete grouped projection/inverse, policy contents/diff, Observe inspection.
- [x] Exact AF attachment changes; shared list and complementary policy preserved.
- [x] EMDD second-prefix fixture proves no scope broadening.
- [x] Explicit manual execution available in Observe only via valid confirmation;
  all autonomous execution still disabled with Observe or master off.
- [x] Whole-run revert, drift/no-op/partial/uncertain/repeated-token failure paths.
- [x] Restart-safe deadlines and exactly-once recovery admission, takeover races.
- [x] Independent rule clear condition/recovery preference with held active state.
- [x] Session reconstruction, cookie persistence, idle/absolute expiry/revocation,
  outage reconnect and original return route.
- [x] Truthful failed/stale/loading/empty states and supporting-screen fixes.
- [x] Keyboard plus desktop/mobile visual checks using mocks only.
- [x] Full software release gate, fresh and upgrade migrations on dedicated schemas,
  MariaDB and MySQL compatibility.
- [x] Restorable EMDD backup, versioned conversion, report and missing policy docs.
- [x] Release deployed; health/version/schema verified read-only; no actions triggered.

Baseline frontend:8 tests/typecheck/build passed during planning. Browser sandbox
prevented rendering then; retry with authorized local mocked test tooling for
implementation verification. Source review does not certify a live IOS image.

Existing restricted local test credentials are stored privately in
`/tmp/rerouter-codex-test-20260917/database-url`; never print the contents.
The test harness validates schema/account and serializes cross-process suites.

## Acceptance status — 19 September 2026

Implementation and local acceptance are complete. The frozen release gate passed
274 Rust tests, 36 frontend tests across 13 files, typecheck, strict Clippy, the
frontend production build, and the development embed-UI Rust build. The optimized
release build passed. The MySQL 8.4 all-target run separately passed all
274 Rust tests with zero failures. The bounded browser confirmation passed nine desktop and
four mobile routes with no overflow or page errors and truthful outage states.

Fresh and 67→69 upgrade migrations passed on dedicated MariaDB and MySQL 8.4.7
schemas. The real-snapshot conversion preserved 13 rules and their states, all
18 existing templates, and all 16 saved action IDs/positions; migration adds one
policy template. Fourteen BGP entry mutations become direct export-policy
attachments and two MSS actions remain unchanged. Seven eMA2 actions remain
Needs setup until the two documented prefix lists exist. Deletions and executed
reroutes were zero. Reapplication refused atomically.

Remember-me acceptance confirms a seven-day absolute session maximum with the
same one-hour idle timeout. Observe permits only exact-previewed, explicitly
confirmed manual work; autonomous starts and recovery remain disabled unless
Enforce, the automatic master switch, and their narrower authority gates agree.

Deployment completed from source `77a3f73daa7461ebc67112dab2020e64dca61020`.
The stopped-window backup, migration, conversion, readiness, executable, public
frontend, rules and safety state were verified. Observe and automatic-off remain
in force, with zero reroutes, bundles, locks or deletions. Owned database fixtures,
grants and tunnel were cleaned up without touching database services or the
existing MariaDB account. No router action, revert, test or prerequisite
provisioning occurred; live actuation remains uncertified and user-owned.
Five public JavaScript/CSS assets also matched the release byte-for-byte. The
routing-policy cache was empty during an early post-start read within the normal
scheduled discovery delay; no discovery was forced. Normal inventory refresh and
the two missing eMA2 lists remain prerequisites for live readiness of the seven
known dependent steps and the complete preset.

## Integration review follow-ups (resolved before acceptance)

- Policy projection now formats exact IOS state, distinguishes absent state,
  preserves legacy scope, deduplicates global definitions, and covers mixed
  peer/MSS/static-route and second-prefix fixtures.
- Real preparation and inspection use a fake read transport for positive exact
  Observe previews; missing credentials and unsupported contexts refuse closed.
- UI evidence renders multiline configuration, actual configuration diffs, and
  ignores stale inspection responses after an edit; interaction tests cover it.
- Session regression traverses remember-login and TOTP promotion, cookie expiry,
  reconstruction, revocation, outage recovery, and the original return route.
- Rules, supporting pages, doctrine/glossary, conversion and release tooling,
  database compatibility, browser confirmation, and independent Astra review are
  complete. Production backup, conversion, deployment and read-only verification
  are also complete; only user-owned live router testing remains outside acceptance.

## Additional live read authorized by the user

The user subsequently authorized configuration inspection of eMA3 and reported
removing SSH write permissions from eMA1/eMA2. Preserve those restrictions.
Parent read only eMA3 with five `show` commands; no config commands or action tests.
The sanitized snapshot is
`/tmp/rerouter-workflow-review-20260919/ema3-policy-snapshot.json` (captured
2026-09-19T06:34:46Z). It confirms IPv4 AF direct bindings matching eMA1, all nine
BGP peers Idle, and no MSS clamp on Port-channel1. Use locally for parser fixtures;
configured policy must not be labeled a verified advertisement. Live action tests
remain exclusively the user's post-deployment task.

An isolated Chromium review harness is prepared at
`/tmp/rerouter-workflow-review-20260919/browser-review.mjs`. It intercepts all app
requests and aborts other origins, serves the local production bundle from disk,
and uses synthetic fixtures. Browser launch succeeds with approved sandbox
escalation; no live server is necessary. Run batched desktop/mobile review after
frontend stabilizes, fix findings once, then confirm once.

## Verification resources owned by this implementation session

- Full frozen software gate passed after the strict-Clippy and independent review
  fixes. Log: `/tmp/rerouter-workflow-review-20260919/release-gate.log`.
- Independent Astra backend review identified held-rule clearing/takeover
  ownership, actual catch-all prefix deny classification, recovery claim release,
  condition-recovery takeover race, and pagination overflow. Sol lifecycle_backend
  owns their fixes/regressions. Independent frontend review's seven route/async/
  diff/history/returnTo findings have been assigned and reported fixed with34 tests.
- First browser batch found mobile manual-table overflow and a nested main
  landmark; both were fixed. The single bounded confirmation passed nine desktop
  and four mobile routes with no overflow or page errors.
- EMDD application source snapshot re-read safely to
  `/tmp/rerouter-workflow-review-20260919/emdd-app-before.json`; conversion fixture
  now uses these real IDs, zero-based positions, ordering and MSS string values.
- Dedicated MySQL8.4.7 test schemas used by this session were:
  `rerouter_test_wf0919_f3c6ab`, `rerouter_test_wf0919_fresh_f3c6ab`,
  `rerouter_test_wf0919_upgrade_f3c6ab`; restricted account
  `rrt_test_wf0919_f3c6ab` at localhost/127.0.0.1 had grants only on those schemas.
  Cleanup removed all five task URL credential files. Ownership manifests and
  non-secret evidence remain in the temporary review directory.
- The task-owned SSH test tunnel used tool session98996, SSH PID1882864, local port13379,
  control socket `/tmp/rerouter-workflow-review-20260919/mysql-test-ssh.sock`.
  PID/start/cgroup/argv captured in `mysql-test-tunnel.json`. Cleanup removed the
  three MySQL and two MariaDB schemas and added grants, removed the owned MySQL
  account entries, and closed this tunnel through its control socket. The existing
  MariaDB account and both database services were preserved.
- Verified prior release binary SHA256397c689d... copied to
  `/tmp/rerouter-workflow-review-20260919/controller.baseline-5b5326f`; used only
  with --migrate and explicit restricted test URL to create67-migration upgrade
  baseline. Never run its scheduler/API for testing.
