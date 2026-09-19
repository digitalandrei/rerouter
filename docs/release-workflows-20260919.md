# Logical workflows release — 2026-09-19

Status: **deployed and read-only verified**.

Deployed source: `77a3f73daa7461ebc67112dab2020e64dca61020`.

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

- Frozen software gate: 274 Rust tests, 36 frontend tests in 13 files,
  TypeScript typecheck, strict Clippy, frontend production build, development
  embed-UI build, and optimized Rust release build.
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

## Deployment acceptance

- [x] Restorable stopped-window backup:
  `/root/rerouter-backups/20260919-77a3f73`, 39,824,379 compressed bytes,
  SHA-256 `7016528e8fec64ddf01f8c99f764f11852c8a029d4dc9270c8b017b5e11894a1`.
- [x] Controller SHA-256
  `0dce921c44c5260720a74e89af30603cd12d3aab1c7033e47e584bfdd1b50595`.
- [x] Frontend SHA-256
  `da29bbf96c26d9edda9a45fb69bd76a11a2d6dd2dd95f0f8ad2482af77e788d2`;
  the public frontend plus five delivered JavaScript/CSS assets fetched from the
  workspace matched the release byte-for-byte.
- [x] Reviewed conversion SQL SHA-256
  `1223cd16a7f9cb184468fb608166d922ffad46b949c44970427606c25d06d6fb`.
- [x] Release archive SHA-256
  `608926070f3d67d03e26aad62edb002737f028fc0297aa0643ff68d8b438f8c6`.
- [x] Schema 69, service readiness, running executable and release version verified.
- [x] Observe and automatic-off state verified; `.env` and config unchanged.
- [x] 13 rules unchanged, 19 templates, revision-4 definition, same 16 action
  IDs/positions, and seven converted actions reference the two documented missing
  policies. Live readiness awaits the normal cache refresh.
- [x] Zero reroutes, bundles and locks; zero deletions. No action, revert, router
  test, notification test, or router prerequisite provisioning was performed.
- [x] Three owned MySQL schemas and account grants, two owned MariaDB schemas and
  added grants, and the owned tunnel were removed. The existing MariaDB account
  and both database services were preserved.

Live route activation is not certified by deployment, source, fixture, browser,
or read-only configuration inspection. eMA3 peers were Idle during the authorized
read, and the user owns any future router test. The cached routing-policy table
was still empty shortly after startup, within the normal delayed discovery window;
no discovery was triggered. It must refresh through the normal schedule before
the seven known prerequisite-dependent steps can be evaluated live, and the
complete preset remains blocked until both missing eMA2 lists exist.
