# Plan 014: Remediate the 2026-09-15 full-project audit

**Written against:** `08126a182283688b91617cd0d81a0ad24ad4f233` (`main`), including the pre-existing Claude settings change.

**Status:** TODO — the audit is complete; the fixes in this roadmap are not implemented.

**Source:** [Full-project audit](../docs/audit-2026-09-15.md). Finding IDs below refer to that report. Keep Standards and Spec conclusions separate when closing findings; one fix may address evidence from both axes.

## Outcome and boundaries

Restore enforce-mode safety and trustworthy monitoring, then repair deployment, agent workflows and usability. Preserve observe-by-default, default-disabled automatic/flow actions, validated templates, server RBAC, verified rollback and conservative uncertainty. The absence of hosted CI is an owner decision; validation stays local.

Each numbered work item is a reviewable change group. Add regression coverage for its demonstrated failure before changing safety/data behavior. Historical migrations are immutable; schema/catalog repairs use new forward migrations. Update affected contracts, examples and doctrine in the same change. Do not execute production reroutes, publish issues, merge or deploy as part of this roadmap without the corresponding implementation/deployment instruction.

The existing audit established 106 passing Rust tests, frontend typecheck/build and embedded-UI build. It did not establish live IOS, browser, MySQL 8.4, production load or deployment acceptance. Treat those as explicit validation requirements where relevant, not as inherited passes.

## Implementation order

Effort: S = small bounded change; M = several coordinated changes; L = safety/data redesign with substantial regression coverage. Risk refers to the fix, not the severity of the existing defect. All rows start TODO.

| Item | Change | Findings | Priority | Effort / risk | Dependencies |
| --- | --- | --- | --- | --- | --- |
| 14.01 | Enforce preview authority and final execution gates | SPEC-01, SPEC-02 | P1 | L / high | — |
| 14.02 | Require complete and accepted SSH responses | SPEC-03, SPEC-04 | P1 | M / high | — |
| 14.03 | Repair Null-Route seeds and IPv6 inventory | SPEC-05, SPEC-06 | P1/P2 | M / medium | — |
| 14.04 | Preserve action ownership, recovery and terminal publication | SPEC-10, SPEC-11, SPEC-12 | P1/P2 | L / high | 14.01 for mutation serialization |
| 14.05 | Make notification fanout durable and fair | SPEC-07, SPEC-08, SPEC-09 | P1/P2 | L / medium | — |
| 14.06 | Base detection on fresh, available metric evidence | SPEC-14, SPEC-15 | P1 | L / high | — |
| 14.07 | Apply ordered execution bundles without self-cooldown | SPEC-13 | P1 | M / high | 14.01, 14.04 |
| 14.08 | Preserve outcomes and truthful incident/safety state | FE-01, FE-02, FE-03, FE-08, FE-09, FE-14 | P1/P2 | M / medium | Coordinate 14.01, 14.06 contracts |
| 14.09 | Expose interface protection correctly | FE-04 | P1 | S / medium | 14.01 protection serialization |
| 14.10 | Repair rule edits and atomic action-batch creation | SPEC-20, FE-06, FE-10, FE-15 | P2 | M / medium | Coordinate 14.06/14.07 migrations |
| 14.11 | Correct flow framing, identity lifetime and activity timestamps | SPEC-16, SPEC-17, SPEC-18, SPEC-19 | P2 | M / medium | 14.06 availability propagation |
| 14.12 | Reject obsolete previews and unsupported SSH UI changes | FE-05, FE-07 | P2 | S / medium | 14.01 preview contract |
| 14.13 | Correct chart units and sample smoothing | FE-11 | P2 | S / low | — |
| 14.14 | Restore keyboard access and readable error contrast | FE-12, FE-13 | P1 accessibility | M / low | — |
| 14.15 | Update affected dependency resolutions | STD-11 | P2 | S–M / medium | — |
| 14.16 | Repair installation and upgrade instructions | STD-05, STD-06, STD-10 | P2 | S / medium | — |
| 14.17 | Repair discovery, review workflows and governance drift | STD-01, STD-02, STD-03, STD-04, STD-07, STD-08, STD-09 | P2/P3 | M / low | Final policy wording follows runtime fixes |

Start 14.01–14.06 as separate workstreams, with migration numbers coordinated. Independent dependency, deployment, accessibility and permission corrections can proceed alongside them. Armed-mode sign-off requires the execution, recovery, detection and outcome work; observe-mode monitoring sign-off additionally requires reliable alerts and truthful state. Neither sign-off follows from compilation alone.

## Work items and acceptance

### 14.01 — Execution authority and gate serialization

- Replace bare operator `ActionRequest` actuation with an internal validated-preview capability carrying actor, scope, exact normalized plan/parameters, rollback targets and reason. Automatic execution and automatic recovery use distinct authority variants. A caller's earlier operating-mode read must never stand in for preview authorization.
- Continue using existing token storage and conditional single-use validation, but consume/check the token on the connection committing execution eligibility. Carry the authorized immutable plan to apply; if current inventory/prior rollback state would change it, refuse and require a new preview.
- Extend `POST /api/rules/{id}/clear` to support a render-only preview and a confirmed request with `preview_token`. Bind the entire resolved recovery set to the preview. Update the frontend `api.rules.clear` payload/response contract and replace the direct clear action in Rules with preview→review→confirm→results; correct any “executes nothing” copy. Clears with no actuation can remain state-only, but must never acquire permission to act because mode changed while waiting.
- Establish one documented lock order and policy revision/serialization protocol shared by settings, relevant rule/template/protection changes and execution reservation. Preserve the existing original-reroute rollback serialization. Recheck current mode, actor permissions, automatic/rule/template enables, locks, protection and throttles before the transition that commits to starting. Disarm prevents not-yet-started operations; an already-started operation retains recovery/uncertainty handling.
- Apply gates by trigger: automatic forward actions require global/per-rule/template enables and applicable flow evidence; operator forward actions require preview/RBAC and ordinary forward throttles. Corrective rollback retains its documented automatic-enable, cooldown/rate, stability and stale-inventory exemptions. Mode, locks, serialization and protection against a disruptive inverse still apply; operator-triggered rollback also requires preview/RBAC. Disabling the original rule's automation must not prevent undoing its prior mitigation.
- **Acceptance:** Real MariaDB plus fake SSH barriers around preview comparison, preflight and reservation. Tokenless observe→enforce applies zero commands; disarm/disable/protect before the start boundary applies zero commands; actor/scope/plan mismatch, expiry and replay refuse. All manual, rule-apply, rollback and manual-clear entrypoints satisfy the same invariant. Concurrent settings changes cannot deadlock the chosen lock order.

### 14.02 — SSH response integrity

- Return a successful read only after the expected terminal prompt/completion. EOF/close before completion and timeout are structured failures. A denied verification command fails even when it returns to a normal prompt. Keep valid empty output from completed filtered `show` commands usable.
- Interpret explicit IOS errors for every applied command, stop the remaining plan, preserve the partial response sequence and propagate partial/ambiguous apply as uncertain even if readback matches. Do not erase output when producing a transport error.
- **Interfaces:** Enrich the internal SSH result/error contract with completion and partial-command outcomes; preserve external reroute state names and error details. Keep the allowlist and existing supported IOS command shapes.
- **Acceptance:** First/middle/last command rejection, denied soft clear, matching state after rejection, EOF before output, partial output, timeout and completed-empty verification. Each ambiguous path persists uncertainty and blocks subsequent work on the device; successful complete plans remain successful.

### 14.03 — Catalog and address-family repair

- Add a forward migration fixing IPv4 Null-Route apply/withdraw placeholders and verification commands to the `prefix` schema. Convert legacy `{parent,target}` to the validated execution prefix when reading legacy saved actions or preparing their inverses; preserve original audit snapshots.
- Extend BGP discovery to parse supported IPv4 and IPv6 address-family network statements and remove withdrawn discovered networks consistently. Keep fresh announced-space containment mandatory.
- **Acceptance:** Fresh schema and upgrade fixtures containing legacy rule actions and reroutes; all 18 seeded plans and their inverses render with valid sample parameters and pass the command/sequence allowlist. Mixed-family discovery persists correct normalized prefixes and enables only contained current targets. No direct SQL inventory workaround should be needed for the advertised IPv6 workflow.

### 14.04 — Durable action/recovery ownership

- Make terminal state, required correlated lock, audit and terminal alert/outbox insertion one transaction. On an ambiguous commit, leave a conservative recoverable state; use a stable event identity to prevent duplicate lifecycle publication during reconciliation.
- Protect activation events from retention while linked actions remain unresolved or successfully applied without a completed inverse. Recovery must enumerate outstanding original actions from durable ownership; absence of a retained “latest fired” event is not proof that nothing needs undoing.
- Add a forward migration changing the reroute-to-device FK to `ON DELETE RESTRICT`. The API returns conflict for a device with any reroute history and directs the operator to disable it; history-free device deletion still works. Serialize deletion with actuation and retain timestamps/original parameters.
- **Acceptance:** Fault each finalization write/commit; restart at each boundary; verify lifecycle and lock consistency. Retain/roll back a mitigation older than two days and across multiple rule activations. Refuse deletion for running/uncertain/succeeded/historical reroutes, including concurrent delete/apply; verify disabling leaves all evidence intact. Audit historical NULL-link rows before any backfill and fail closed on ambiguous ownership.

### 14.05 — Delivery intents and retries

- Materialize each alert's resolved email/Teams audience as durable per-target work before sending. Track pending/retry/settled state separately from append-only attempt history. Enforce a unique alert/channel/target identity and resume unattempted targets after restart.
- Make alert retention state-aware: preserve unresolved delivery intent and its payload beyond the ordinary two-day window. Prune settled work according to policy; deleting an alert must never cascade away outstanding delivery work.
- Select only unresolved work eligible for its next attempt; completed rate-limit histories cannot remain candidates. Prioritize critical eligible work without losing ordinary work. Preserve existing dedup, backoff, attempt caps and prevention of recursive delivery-failure alerts.
- Link verified user recipients through validated unique normalized-email matches at creation; backfill unambiguous matches only. Keep external addresses and recompute admin-tier eligibility from current roles. User deletion must not silently convert an unrelated external recipient into a mandatory admin target.
- **Acceptance:** More than 50 retry→sent/settled/exhausted items plus new critical work; failures after each recipient and between channels; SMTP absent for more than two days then restored; rate-limit delay; fifth-failure/meta-alert persistence failure; role/subscription changes. Verify no target is stranded and no completed target loops indefinitely. Record the unavoidable send-before-ack uncertainty rather than claiming exactly-once external delivery.

### 14.06 — Observation identity and metric availability

- Persist last-consumed observation identity/time for each rule; aggregate rules additionally track each member's consumed sample. Advance a sample-count gate only after every required member supplies new valid evidence. Flow duration/recovery uses advancing closed-bucket evidence, not repeated evaluator wall time. Stale/invalid gaps reset unproven matching/recovery streaks.
- Carry per-metric availability through SNMP/flow normalization, storage, rule selection and API projections. Unknown status is unknown; absent byte/packet fields are unavailable. After a missing/invalid error read, require a new pair of valid error reads and their own observation times before publishing an error rate. Good volume evidence stays usable independently.
- **Interfaces/migrations:** Add durable rule observation cursors and metric validity/baseline-time fields with conservative defaults for existing rows. Coordinate frontend availability handling; preserve measured zero as a valid distinct value. Keep public rule persistence controls and bounds.
- **Acceptance:** Repeat a sample three times, use mixed 10/30/60-second member polling, resume after stale/invalid/controller gaps, and exercise firing/recovery persistence. Missing error/status walks and bytes-only/packets-only templates cannot fire or clear unsupported metrics. After a gap, the unchanged 900,000 error counter is unavailable until a new valid pair exists, then yields zero; it never fabricates 30,000/s.

### 14.07 — Execution bundle identity

- Persist a distinct execution-group identity for one authorized rule activation/manual apply, separate from rule ID and action-definition IDs. Record that identity on every sibling reroute.
- Cooldown history excludes only previously authorized siblings of that same group; other activations/manual requests remain blocked. Record final device/rule cooldowns for all attempted devices while keeping durable-history fallback. Global rate limits continue counting individual actions; do not disable them to make a bundle pass.
- **Acceptance:** Ordered two/three-action same-device and cross-device bundles under default cooldowns, unrelated concurrent activity, partial refusal/uncertainty and restart. Persisted results identify exactly which siblings ran or were blocked. Recovery uses original parameters and reverses only applied siblings.

### 14.08 — Truthful operational UI

- Add the previously proposed Vitest + React Testing Library setup for the concrete component regressions in this roadmap; run it locally. Browser interaction checks use a separate local Playwright setup and do not create hosted CI.
- Keep apply/rollback results visible until dismissal; refresh parent data without unmounting the result. Show business failure separately from HTTP success and provide original/new action IDs. An ambiguous transport response directs the operator to reconciliation/history before retry.
- Use explicit loading/unknown/cached/current/error state for settings, detections, alerts and history. Refresh visible incident/safety datasets every 30 seconds, on focus and on manual refresh; discard superseded responses. Retain last-success timestamps and never convert failed reads to healthy empty state.
- Show per-source discovery outcomes and await data reload; label old interface/BGP metrics with age and availability. Describe SSH reachability, operating mode and preview context separately; a dry run is not evidence of observe mode.
- **Acceptance:** Blocked/failed/uncertain/succeeded/mixed outcomes, independent endpoint failure, remote administrator changes, clear→firing, aging data and all/partial discovery failure. Cover these with focused component tests and one bounded real-browser desktop/mobile pass.

### 14.09 — Protection workflow

- Use the existing protection API with an object body; show persisted protection on interface list/detail and in disruptive-action selection. Only `manage_devices` users can change it. Keep server-side authorization and actuation-time protection enforcement authoritative.
- **Acceptance:** Correct wire JSON, protect/unprotect and reload, viewer read-only state, mutation failure, and shutdown/MSS-add refusal on a protected interface. Do not confuse corrective inverse exemptions with a missing guard.

### 14.10 — Accurate rule edits and atomic action definitions

- Implement an internal `Patch<T>` with Missing/Null/Value states and explicit Serde decoding: omitted leaves unchanged, explicit null clears, provided value replaces. Apply it to all nullable rule fields, then validate the full resulting condition. Preserve an existing egress direction during unrelated GUI edits. Include group member IDs in interface rule coverage/counts.
- Add `POST /api/rules/{id}/actions/batch` for an ordered array with a client-generated request ID. Validate the entire array and persist actions, idempotency identity and audit in one transaction. An identical retry returns the persisted result; reuse with changed content refuses. Existing single-action POST remains compatible. Reconcile the saved rule after ambiguous responses.
- **Acceptance:** Clear protocol/port together, clear each recovery override and edit/reload egress rules. Invalid second bundle action or failed audit writes zero actions; response loss/retry does not duplicate actions. Single/summed/mixed/cross-device rule coverage remains accurate.

### 14.11 — Flow evidence integrity

- Persist actual packet-receipt time, not flush time; silence must remain silent through empty flushes and permit retention. Separate health bookkeeping from activity evidence.
- Decode transport ports only for initial IPv4 fragments with valid headers. Reject outer FlowSet/XDR length/count/padding violations as structured errors; do not reject intentionally short sampled packet payloads solely for being samples. Forward malformed/degraded accounting to health and metric availability.
- Give NetFlow templates a refresh timestamp and bounded lifetime; default to 30 minutes with a documented configuration knob. Detect a restart from exporter boot-time evidence corroborated with sequence reset, distinguishing uptime/sequence wrap and bounded reordering. Clear generation-specific template/sampling state before decoding a new generation. Unknown/expired templates cannot drive detection.
- **Acceptance:** Silent/resumed exporters, initial/non-initial fragments, valid/truncated framing, structured mutations of valid packets, reused IDs after restart, lost refreshes, normal wraps and harmless out-of-order delivery. Preserve documented uniform-sampling assumptions; per-record mixed sampling is separate scope.

### 14.12 — Preview response identity and SSH editor honesty

- Increment a request generation when any preview-affecting input changes; ignore older preview and device-inventory responses. Invalidate local tokens appropriately after submission/rejection and require reconciliation after ambiguous execution.
- Remove `none` as an edit transition for a configured SSH device, retain persisted authentication labels and clear newly entered secrets after save. Do not add credential-removal API behavior in this fix; that is a separate feature with explicit revocation semantics.
- **Acceptance:** Delayed A→B router changes never restore A's token/pickers; template/params/reason changes behave likewise. A configured SSH device cannot appear disabled after a successful no-op save.

### 14.13 — Measurement labels

- Label existing error/discard data as counts per poll interval. Rename smoothing to Raw/3 samples/5 samples, matching the implementation. Preserve a NULL current optic point instead of filling it from older points.
- **Acceptance:** Known deltas at different intervals, irregular timestamps and NULL optics are labeled truthfully. No backend unit or detector threshold changes are needed for this bounded correction.

### 14.14 — Keyboard and contrast

- Replace mouse-only selector activation with a complete keyboard/native control path, add explicit links/buttons for row navigation and associate labels/help triggers. Preserve current visual identity and responsive layout.
- Separate error-text and destructive-fill tokens and measure representative small text against its actual surfaces in both themes.
- **Acceptance:** Keyboard-only completion of selector, interface/flow detail, help and form workflows; correct accessible names and focus behavior; at least 4.5:1 error-text contrast. Verify in an actual browser; the audit's source detector is not acceptance evidence.

### 14.15 — Dependency resolutions

- Update compatible locked resolutions to at least h2 0.4.16, rustls 0.23.45, event-listener 5.4.2, nanoid 3.3.18, PostCSS 8.5.23 and a compatible React Router pair with router at least 7.18.2. Recheck current primary advisories before implementing; these floors reflect the audit date.
- Preserve explicit RSA/derivative risk records while no suitable fix exists. Record applicability of build-only and SSR/RSC advisories rather than presenting registry counts as proven deployment exploits.
- **Acceptance:** Release gate, embedded UI build, routing smoke checks and refreshed scans. Report all remaining findings/accepted risks; do not use broad ignores or change execution policy to make scanners green.

### 14.16 — Deployment correctness

- Set explicit root-owned service-readable application/config/unit permissions for fresh installs; keep `.env` private to its intended owner. Preserve existing operator file contents and deliberate permissions unless a documented migration requires changing them.
- Separate root installation from service-user commands. Document upgrade backup/release checks, installation, intentional restart and verification of the running executable plus health/readiness. Use Ubuntu-compatible HTTP/2 syntax in the customer vhost.
- **Acceptance:** Prefixed installs under 0022/0077, idempotent reinstall, permissions verified as the service identity, isolated Nginx validation of both vhosts, unit validation and a disposable upgrade demonstration. A real deployed restart remains outside this audit/remediation implementation until authorized.

### 14.17 — Agents, skills, doctrine and review process

- Narrow the pre-existing blanket cleanup permission while preserving other local edits. Put all seven flat domain skills in `<name>/SKILL.md`, repair YAML and relative references, and verify discovery in the target harness.
- Capture review base/result revisions and cover committed, staged, unstaged and untracked implementation correctly. Keep imported setup optional; correct stale invocation names and glossary semantics. Harden optional hook input handling/matching and document its enforcement limits instead of implicitly installing it.
- Align MariaDB-primary/MySQL-8.4-compatible policy, gate applicability, retention/recovery rules, SSH stability, preview/flow copy and actual repository tree. Preserve owner decisions and historical audit text, adding dated supersession pointers where needed.
- **Acceptance:** All 27 skills/5 agents parse; no broken operational references; harness discovery/invocation works. Disposable review scenarios expose all intended changes. Inert hook tests cover documented equivalent forms and malformed input. MySQL-specific validation is executed in an isolated MySQL environment or remains explicitly unverified; MariaDB success alone never closes that gap.

## Closing a work item

- Confirm the cited baseline still matches before editing; inspect later relevant changes if it moved. Preserve unrelated work.
- Record exact tests, engine/tool versions and any skipped scenarios. Run the local release gate for code/schema changes; run narrower link/frontmatter checks for guidance-only changes. Do not repeat unrelated expensive checks without a change or unresolved failure.
- Update each finding's status with its implementing commit and evidence; keep unresolved and accepted risks explicit. Coordinate new migration ordering and test fresh plus upgrade schemas.
- Rerun the targeted negative scenarios from this audit before any readiness verdict. Observe-mode and armed-mode conclusions must state their evidence and remaining live-device/browser/MySQL limits separately.
