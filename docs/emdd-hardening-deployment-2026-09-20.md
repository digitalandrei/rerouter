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
