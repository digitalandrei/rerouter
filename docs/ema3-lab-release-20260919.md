# eMA3 configuration-only lab release — 2026-09-19

Status: deployed and read-only verified. Source release `4129744de24ee346dfc9ae34e7238d1bd1ee356c`.

The saved definition [e-manuel-apply-ema3-test](https://emdd.vivanet.ro/manual-mitigations/2)
is preset 2, revision 1. Its eight enabled steps target only eMA3: six Akamai
outbound attachments select `pfx-to-viva`, Po1 MSS becomes 1436, and COLT selects
`no-export`. The existing lists scope this configuration to 194.105.142.0/24.
Original preset 1, revision 4, and all 16 of its actions are unchanged.

For a lab run, select **Run → Configuration-only lab test — eMA3 → Preview exact
plan**, inspect the complete change, and explicitly confirm. This changes router
configuration; it does not certify BGP advertisement. Idle peers can be used.
Only the enrolled eMA3 device ID, address, port and pinned host key qualify.
Normal routing verification remains the default. Revert inherits the recorded
scope and restores owned changes in reverse order. Timed and traffic-triggered
recovery are disabled for lab runs; immediate failure compensation remains in
place when the failure is proven safe to compensate. Uncertainty or drift blocks
further changes.

Production retains its limit of three actions per 600 seconds. Lab runs have an
independent per-device allowance of 32 actions per 600 seconds, with atomic
whole-set admission. Lab actions and their inverses do not consume the production
allowance. Observe mode and the automatic master switch remain unchanged/off.

The UI now separates prefix-list and route-map attachments, shows the preserved
policy, presents before/after/revert attachment states, and displays readable
prefix-list entries and route-map clauses. Cached assessments are distinguished
from exact previews and operational verification.

Verification passed: 279 Rust tests on MariaDB and 279 on MySQL 8.4, 51 frontend
tests, typecheck, strict Clippy, production builds, and mocked desktop/mobile
workflows. Stateful fake tests prove BGP/MSS apply, explicit revert, compensation,
authority/identity refusal and isolated rate reservations. Public delivery of
46 frontend files matches the release.

Live checks: schema 69, 13 rules, 19 templates, only lab device 3, zero reroutes,
zero bundles, zero active locks, unchanged environment/session secret, and both
saved definitions preserved through deployment. No mitigation, revert, router
write, notification test or live execution preview was performed by the assistant.
Live IOS execution testing remains the user's task.

Backup: `/root/rerouter-backups/ema3-lab-4129744de24e`. Database evidence is 40,118,369
compressed bytes; SHA-256 `b6d3645505a2b15047d23979d46eedd580aa630277d3d8bd9367c030bbc1f90c`. The prior controller, frontend,
config and environment are retained there. Owned MySQL test resources were
removed without stopping database services.

Detailed evidence: `/tmp/rerouter-workflow-review-20260919/ema3-preset/`.
