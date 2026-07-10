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
- `--install` — re-run to upgrade the binary and systemd unit; never touches
  an existing `.env`/`config.toml`.

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

Use the authenticated Settings UI for lock changes; API calls require a signed,
fully authenticated session and `manage_locks`.

## Common incidents

### An attack is detected but no reroute happened

Expected if the operating mode is `observe` (the shipped default — the alert
shows what *would* have run), automatic reroutes are off, the rule's
`automatic_reroute_enabled` is false, a cooldown is active, or a safety gate
failed. Check the rule event, the device's locks/cooldowns, and the controller log
line for the abort reason. In enforce mode, trigger a **manual** reroute from
`/mitigations/manual` if appropriate.

### A reroute is stuck `uncertain`

The controller could not prove the outcome (often after a crash). The device is
locked and automatic reroutes are disabled for it. Verify the real routing state
on the router (e.g. `show ip route <prefix>` for a Null0, or the neighbor's
session state), then **acknowledge** from the authenticated UI.

Only acknowledge after you have confirmed the real routing state.

### A mitigation needs to be lifted

Run the template's **rollback** (`null_route_withdraw`, `blackhole_withdraw`, or
`bgp_session_disable`) from `/mitigations`. Rollbacks are themselves audited and
verified. In enforce mode the UI first obtains a server-rendered rollback plan,
then consumes its five-minute one-time preview token. There is no auto-expiry: a
mitigation stays in effect until you explicitly run its rollback.

### Telemetry went stale

The device shows `telemetry_stale`. Traffic-threshold rules are suppressed (by
design). Check device reachability and the SNMP community with `POST
/api/devices/{id}/test`. Do not force reroutes off stale data.

### Email alerts not arriving

Check `alert_deliveries` for `failed`/`bounced`, the controller's alert-dispatcher
log lines (`journalctl -u rerouter-controller`), and the `SMTP_*` values in
`/srv/rerouter/.env`. Rate-limited deliveries retry after backoff; transport
failures retry up to five times and then raise a permanent-delivery meta-alert.
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

- Confirm `operating_mode` (observe/enforce) and `automatic_actions_enabled`
  match the intended posture.
- Review open locks and stale cooldowns weekly.
- Review `uncertain`/`failed` reroutes and audit logs after any incident.
- Verify retention jobs are pruning `interface_samples` and keeping audit logs.
- Rotate device SNMP communities and SSH credentials on schedule.
