# EMDD hardening deployment — 20 September 2026

Deployed the verified hardening candidate to `https://emdd.vivanet.ro` after
explicit owner authorization. Release marker:
`hardening-20260920-11e55e8c0198`.

- Controller SHA-256: `cc47c4ec0149db17d64da0a561baff05bc47adb0e184c16e1a0d0e8fb92cdff6`.
- Applied six pending migrations: schema 69 → 75. All migration checksums match
  the reviewed manifest.
- The running service executable matches the installed artifact. Public UI
  entrypoint and referenced assets match the reviewed frontend; public health
  and readiness return `ok` / `ready`.
- Observe mode and automatic actions off were preserved. Device credentials,
  enabled flags, polling intervals, configuration, environment, systemd unit,
  saved mitigation definitions, and rules were preserved.
- Before/after captures preserve all 16 reroute records, both completed bundles,
  their immutable ledgers/plans, and notification history. The expected repair
  added the restored association from recovery bundle 2 to source bundle 1.
  No active execution, open safety lock, or device window was discarded.
- The eMA3 preset `e-manuel-apply-ema3-test` reports `ready`. The main preset
  `e-manuel-apply` still reports missing/stale routing inventory for device 2
  (eMA1), consistent with the owner's deliberately restricted router account.
  eMA1/eMA2 permissions were not changed; their later validation follows the
  owner's eMA3 retest and access restoration.
- Removed 77 obsolete application/staging paths (1,244,317,459 bytes), including
  older controller binaries, frontend trees, and release archives. Retained
  database recovery snapshots and configuration/audit evidence.

Only `rerouter-controller.service` was stopped and started. No MySQL/MariaDB or
Nginx service was installed, stopped, restarted, or reconfigured. Database
queries/migrations targeted Rerouter only. No router configuration action or
notification test send was executed.

Private stopped-window data and deployment evidence remain on EMDD under
`/root/rerouter-deployment-evidence/hardening-20260920`. The application account
was used for deployment capture, fencing, data snapshot, and migration access.
The data snapshot is not an older application version and was not restored.

## Later 20 September releases

The controller and frontend were subsequently advanced through `4fcb7cc` and
schema 76. Durable direct runs now publish server state before router reads, and
direct recovery inherits the source verification scope. Recovery bundle 9
successfully restored eMA3 run 7; both are inactive, with no remaining mutation,
device window, source membership, or open lock.

The policy inventories were refreshed after the operator installed the reviewed
single-prefix policies. `e-manuel-apply` is revision 6 and
`e-manuel-apply-ema3-test` is revision 3; both validate Ready. Every Akamai action
selects `rr-194105142-only`. eMA1 and eMA3 withdraw the attacked prefix from COLT
with `no-export`; eMA2 uses `rr-colt-without-194105142` so
`194.102.117.0/24` remains eligible there. Every Po1 action sets MSS 1436. These
definition updates created no execution plan or router run.

## Recovery ownership and page-workflow follow-up

Release `recovery-ownership-ui-20260920-ebf70485eb2e` advanced EMDD from
schema 76 to 77. The controller PID changed from 1090698 to 1092920; controller
SHA-256 is `97cd3874014af24beee86f35d2cdee0fd9d928a098f35c97ad13af9d0fed6ec3`.
The installed and public frontend entrypoint both have SHA-256
`2c68eb23896dc882f524c406e5df04245492c5b7d42a87f42e2f8ce19f0aff76`.

The migration adds recovery-attempt membership provenance. Proven no-write
recovery now releases only memberships created by that attempt, removes an empty
child quarantine window, and cannot remove later ownership when startup repair
is repeated. Active Run/revert is now a URL-owned page instead of a modal.
Redundant Rules and operational Mitigations shortcuts were removed, as was the
unsaved Run once entry point.

The stopped-window preflight and final verification both recorded Observe mode,
automatic actions off, zero in-flight or active bundles, zero device windows,
zero source memberships, and zero open locks. Both saved mitigations remained
Ready at revisions 6 and 3. The release performed no router command, mitigation,
notification send, or rule arming. It controlled only
`rerouter-controller.service`; no database or web service was restarted or
reconfigured. No transient or previous application copy remains on EMDD.
