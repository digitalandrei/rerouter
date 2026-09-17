# Operations Runbook

Day-2 operations for Rerouter. Assumes the deployment in
[deployment.md](deployment.md).

## Paths

Everything the controller needs lives in `/srv/rerouter/`:

- `/srv/rerouter/rerouter-controller` — the binary (upgraded by re-running
  `--install`);
- `/srv/rerouter/.env` — environment (mode `0600`): `DATABASE_URL`, `SMTP_*`,
  auto-generated `SESSION_SECRET`/`SECRETS_KEY`, `TWO_FACTOR_ISSUER`;
- `/srv/rerouter/config.toml` — controller config (missing file = built-in
  defaults + warning);
- `/etc/systemd/system/rerouter-controller.service` — the unit (owned by the
  installer; overwritten on `--install`).

Installer-managed ownership is `root:rerouter` mode `0750` for
`/srv/rerouter`, `root:root` mode `0755` for the controller binary,
`root:rerouter` mode `0640` for a newly created `config.toml`, and
`rerouter:rerouter` mode `0600` for a newly created `.env`. Reinstall preserves
an existing operator-managed `.env` or `config.toml`, including its ownership
and mode.

## Services

```bash
systemctl status rerouter-controller     # Rust controller (API, engines, alert dispatcher)
systemctl status nginx mariadb
journalctl -u rerouter-controller -f     # structured controller logs
```

Controller health (localhost only):

```bash
curl -s http://127.0.0.1:9277/api/health
curl -s http://127.0.0.1:9277/api/ready
# /api/status is authenticated; inspect it from the SPA or with a valid session.
```

## Ops toolbox (CLI)

Run as the service user with the service's config/env:

```bash
sudo -u rerouter /srv/rerouter/rerouter-controller \
  --config /srv/rerouter/config.toml --env-file /srv/rerouter/.env <flag>
```

- `--check` — config check, then exit.
- `--check-db` — DB connectivity/credential check, then exit (the same
  preflight the controller runs at startup; clear error, never the password).
- `--migrate` — apply pending sqlx migrations, then exit (startup also
  migrates/seeds a fresh database automatically).
- `--seed-templates` — applies pending migrations containing template seeds; it
  does not restore template rows deleted after their migration ran.
- `--create-admin` — create/rotate a superadmin (`ADMIN_EMAIL`/`ADMIN_NAME`/
  `ADMIN_PASSWORD` via flags or interactive prompt; idempotent on email). It
  prints the separate one-time code required for first-login 2FA enrollment.

Run `--install` as root, as shown below, to replace the binary and unit. It
preserves an existing `.env`/`config.toml` and does not restart the controller.

## Controller upgrade

An atomic binary replacement does not change the executable already mapped by
the running process. Always restart and prove both readiness and running-binary
identity:

```bash
sudo /tmp/rerouter-controller --install
sudo systemctl restart rerouter-controller
sudo systemctl is-active --quiet rerouter-controller
curl -fsS http://127.0.0.1:9277/api/health
curl -fsS http://127.0.0.1:9277/api/ready
PID=$(systemctl show --property MainPID --value rerouter-controller)
sudo cmp --silent "/proc/$PID/exe" /srv/rerouter/rerouter-controller
journalctl -u rerouter-controller --since '-5 minutes' --no-pager
```

Do not treat the copied file as the running version. If `cmp` differs or
`/proc/$PID/exe` resolves to a deleted inode, the old process is still serving.
Readiness must be healthy after startup migrations before the upgrade is
accepted.

## Global safety switches

- **Operating mode (read-only / alert-only):** `operating_mode = observe` in
  `system_settings` (UI: `/settings`, admin-only, audited) is the shipped
  default. In observe mode **no reroute executes — automatic or manual**;
  fired rules alert with the rendered plan of the actions that *would* have
  run. Flip to `enforce` only when you are ready for Rerouter to act.
- **Disable all automatic reroutes:** set `automatic_actions_enabled = false` in
  `system_settings` (UI: `/settings`) — takes effect on next evaluation
  (applies in enforce mode; observe mode already blocks everything).
- **Global maintenance lock:** `POST /api/locks/global` (UI button). Blocks every
  reroute until cleared. Use during planned upstream maintenance.
- **Rate budget vs bundle size:** `global_action_rate_limit_count` (default **3**
  per `global_action_rate_limit_window_seconds`, default 600) is counted **per
  action**, and an ordered mitigation bundle reserves its whole size up front. A
  14-action scrubber diversion therefore needs a budget of at least 14 in the
  window, plus headroom for anything else you expect to run and for the
  compensating rollbacks' own attempts. If the budget is smaller, the bundle is
  refused **whole** and nothing executes. Size this deliberately before the first
  enforce-mode run — the default is intentionally not raised for you, because a
  larger budget is a larger blast radius per window.

Use the authenticated Settings UI for lock changes; API calls require a signed,
fully authenticated session and `manage_locks`.

### Router platform gate for enforce mode

Every router used by an enforced action must be certified for the native IOS
exclusive-lock sequence (`show configuration lock` → `configure terminal lock`
→ locked reads/write/readback/soft clear → `end`). The controller refuses an
unsupported, busy, or denied lock; never work around that refusal by loosening
the router account or using an unlocked CLI session. Real IOS/IOS-XE platform
certification is still outstanding, so production remains in `observe` until
the exact hardware/image/account combination passes the staging matrix in
[deployment.md](deployment.md#ios-exclusive-write-platform-certification),
including the 25-second command, 30-second BGP convergence, and 12-minute whole
lock-window bounds.

## Common incidents

### An attack is detected but no reroute happened

Expected if the operating mode is `observe` (the shipped default — the alert
shows what *would* have run), automatic reroutes are off, the rule's
`automatic_reroute_enabled` is false, a cooldown is active, or a safety gate
failed. Check the rule event, the device's locks/cooldowns, and the controller log
line for the abort reason. In enforce mode, trigger a **manual** reroute from
`/manual-mitigations` if appropriate.

### A reroute is stuck `uncertain`

The controller could not prove the outcome (often after a crash). The device is
locked and the whole set is frozen. Use **Reconcile** in the authenticated UI
to compare the router with the action's persisted before/after state. This is a
read-only operation requiring `acknowledge_uncertain_reroute`, also granted to
the seeded operator role. A note alone cannot clear the lock. Conflicting or
incomplete evidence leaves quarantine intact; missing legacy snapshots require
investigation outside automatic recovery.

### A mitigation bundle ended `compensation_blocked`

**Known-applied actions and ambiguous actions require recovery.** Any uncertain
sibling stops all further writes across the set, including compensation on
other routers. A proven failure may permit compensation; if an inverse becomes
uncertain, that also freezes the entire set. Ownership remains held.

What you see: a critical `reroute_bundle_partial` alert and an audit row naming
the bundle and the reroute ids still in force, the bundle in state
`compensation_blocked` on `GET /api/reroute-bundles/{id}` with
`still_applied_reroute_ids`, and the affected device locked.

Resolve in this order:

```text
1. Read GET /api/reroute-bundles/{id}: note failure_reason, the sibling that
   failed, and every id in still_applied_reroute_ids.
2. On each affected router, confirm the REAL state of each listed action
   (e.g. show ip route <prefix> for a Null0, show ip bgp neighbors <ip>,
   show running-config | include <network>). Do not trust the UI here.
3. Reconcile each uncertain reroute from the UI. Only exact recorded state
   resolves uncertainty; conflicting evidence retains quarantine.
4. Roll back each still-applied reroute individually from /mitigations
   (POST /api/reroutes/{id}/rollback), in reverse order of bundle_position:
   undo the most recent change first.
5. Re-check the bundle and the device: no uncertain rows, no open locks.
6. Only then consider re-running the mitigation, after fixing what made the
   original action fail.
```

The bundle row is terminal — it is a record, not a job to resume. There is no
"retry compensation" button by design: the controller does not push config to a
device whose state it could not read.

### A mitigation bundle was refused whole (`bundle_not_admitted`)

The apply returned `409 {"error":"bundle_not_admitted"}` and **nothing ran** —
the bundle did not fit the remaining global action-rate budget (its own size,
plus actions already executed in the window, plus capacity other in-flight
bundles have reserved). The bundle row is closed as `failed`; `detail` names the
observed count, window, and limit.

Either wait for the window to roll over, or raise
`global_action_rate_limit_count` deliberately to fit the bundle (see
[Global safety switches](#global-safety-switches)). Do not work around it by
applying the actions one at a time: that reintroduces exactly the half-applied
mitigation the all-or-nothing admission prevents.

### A mitigation needs to be lifted

Run the original action's **rollback** from `/mitigations`. Recovery uses the
persisted inverse of its owned change, including exact pre-existing values.
Rollbacks are themselves audited and verified. In enforce mode the UI first obtains a server-rendered rollback plan,
then consumes its five-minute one-time preview token. There is no auto-expiry: a
mitigation stays in effect until you explicitly run its rollback.

### Telemetry went stale

The device shows `telemetry_stale`. Traffic-threshold rules are suppressed (by
design). Check device reachability and the SNMP community with `POST
/api/devices/{id}/test`. Do not force reroutes off stale data.

### Email alerts not arriving

Check `alert_delivery_intents` first: each alert/channel/target has durable
`pending`, `retry`, or `settled` work with its next-attempt time and last error.
Use `alert_deliveries` for the append-only attempt history (`failed`/`bounced` /
`sent`), then inspect the controller's alert-dispatcher log
(`journalctl -u rerouter-controller`) and `SMTP_*` values in
`/srv/rerouter/.env`. Rate-limited deliveries retry after backoff; transport
failures retry up to five times and then settle with a permanent-delivery
meta-alert. Unresolved intents prevent retention from deleting the source alert.
Uncertain/failed reroutes, arming changes, degradation, and security events bypass
deduplication and rate limits.

### Origin reachable directly (bypassing Cloudflare)

The origin must accept 443 only from Cloudflare IP ranges. If direct hits appear
in logs (non-Cloudflare source), re-apply the firewall allowlist — see
[deployment.md](deployment.md).

## Backups

Back up: the MariaDB database, `/srv/rerouter/.env` (`DATABASE_URL`,
`SESSION_SECRET`, `SECRETS_KEY`, `SMTP_*`), `/srv/rerouter/config.toml`, and
exported reroute templates. Losing `SECRETS_KEY` makes encrypted device secrets
(SNMP communities, SSH passwords/keys) unrecoverable. Never commit secrets to
Git. Test restore into a staging DB periodically.

## Routine checks

- Before deploying any new build: run the full local release gate — see
  [Release gate (local)](deployment.md#release-gate-local). There is no hosted
  CI; nothing passes unless you run it.
- Confirm `operating_mode` (observe/enforce) and `automatic_actions_enabled`
  match the intended posture.
- Review open locks and stale cooldowns weekly.
- Review `uncertain`/`failed` reroutes and audit logs after any incident, and any
  bundle left `aborted` / `compensation_blocked`.
- Verify retention jobs are pruning `interface_samples` and keeping audit logs.
- Rotate device SNMP communities and SSH credentials on schedule.
