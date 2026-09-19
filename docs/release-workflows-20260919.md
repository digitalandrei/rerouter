# Logical workflows release — 2026-09-19

Status: **software accepted; deployment pending**.

## Result

The release adds saved manual mitigations, complete action-set inspection,
direct IPv4 BGP export-policy changes, durable bundle ownership and recovery,
independent rule clear/revert controls, remembered sessions, resilient resource
states, and paginated audit review.

Observe remains the shipped mode and the automatic master remains off. Observe
permits an authorized operator to run or revert only after reviewing an exact
server plan and explicitly confirming its short-lived one-use authority.
Autonomous starts require Enforce, the master switch, an automatic-capable
template, and every narrower gate. Condition and timed recovery separately
require Enforce, the master, recorded recovery authority, eligible owned changes,
and recovery gates. Remember me has a seven-day absolute maximum and retains the
one-hour idle timeout.

## EMDD conversion

The reviewed definition is preset 1, `e-manuel-apply`, revision 3. Conversion
creates revision 4 without deleting or renumbering any of its 16 steps:

- 14 legacy BGP prefix-list entry mutations become direct outbound IPv4
  `bgp_export_policy_set` attachments;
- both Port-channel1 MSS 1436 steps remain unchanged;
- eMA1's six Akamai peers select `pfx-to-viva`, and COLT selects `no-export`;
- eMA2's six Akamai peers select `rr-194105142-only`, and COLT selects
  `rr-colt-without-194105142`.

The two eMA2 prefix lists do not exist yet. Their seven dependent steps and the
whole definition remain **Needs setup**. The lists are reference-only in
[Operator workflows](operator-workflows.md); release tooling never provisions
router configuration. The conversion preserves all 13 rules, all 18 existing
templates, adds one policy template, preserves unrelated records and history,
and deletes nothing. Fixture conversion produced zero reroutes and zero locks.

## Acceptance evidence

- Frozen software gate so far: 274 Rust tests, 36 frontend tests in 13 files,
  TypeScript typecheck, strict Clippy, the frontend production build, and the
  development embed-UI Rust build. The optimized release build is still running.
- Browser confirmation: nine desktop and four mobile routes; no page errors or
  horizontal overflow, with explicit outage and stale-data behavior.
- MariaDB: fresh 69 migrations and 67→69 upgrade passed.
- MySQL 8.4.7: uninterrupted fresh 69 migrations and 67→69 upgrade passed.
- MySQL 8.4.7 all-target Rust suite: 274 passed, zero failed; log
  `mysql-full-rust-tests.log`.
- Upgrade fixtures preserved rule conditions, flags and current states; the 18
  original template behaviors; session expiry; device credential state; preset
  description; all action IDs, positions and enabled flags.
- Conversion changed exactly 14 BGP actions, retained two MSS string parameters,
  resolved the new template by unique name, and refused reapplication atomically.

Evidence and logs are under
`/tmp/rerouter-workflow-review-20260919/`, including
`platform-gate-summary.json`, the before/migrated/final snapshots, conversion
report and SQL hash, and `mysql-fresh-single-pass.log`.

## Pending deployment acceptance

The parent release session must fill this section after the authorized release:

- [ ] stopped-window restorable database/application backup recorded;
- [ ] artifact, frontend, and reviewed conversion SQL hashes recorded;
- [ ] schema 69, service readiness, running executable, and release version verified;
- [ ] Observe and automatic-off state verified;
- [ ] 13 rules, 19 templates, revision-4 definition and seven Needs setup steps verified;
- [ ] reroute count unchanged and no action/test/notification endpoint invoked;
- [ ] session-owned test schemas, grants, and tunnel cleaned up by their owner.

Live route activation is not certified by source, fixture, browser, or read-only
configuration inspection. eMA3 peers were Idle during the authorized read, and
the user owns any post-deployment router test.
