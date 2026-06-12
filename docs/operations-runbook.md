# Operations Runbook

Day-2 operations for Rerouter. Assumes the deployment in
[deployment.md](deployment.md).

## Services

```bash
systemctl status rerouter-controller     # Rust controller (API, engines, alert dispatcher)
systemctl status nginx mariadb
journalctl -u rerouter-controller -f     # structured controller logs
```

Controller health (localhost only):

```bash
curl -s http://127.0.0.1:9277/api/health
curl -s http://127.0.0.1:9277/api/status | jq .
```

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

```bash
curl -X POST http://127.0.0.1:9277/api/locks/global
curl -X DELETE http://127.0.0.1:9277/api/locks/global
```

## Common incidents

### An attack is detected but no reroute happened

Expected if the operating mode is `observe` (the shipped default — the alert
shows what *would* have run), automatic reroutes are off, the rule's
`automatic_reroute_enabled` is false, a cooldown is active, or a safety gate
failed. Check the rule event, the asset's locks/cooldowns, and the controller log
line for the abort reason. In enforce mode, trigger a **manual** reroute from
`/reroutes/manual` if appropriate.

### A reroute is stuck `uncertain`

The controller could not prove the outcome (often after a crash). The asset is
locked and automatic reroutes are disabled for it. Verify the real state
(BGP feed / Cloudflare zone / upstream FlowSpec), then **acknowledge** from the UI
or:

```bash
curl -X POST http://127.0.0.1:9277/api/reroutes/<id>/acknowledge-uncertain
```

Only acknowledge after you have confirmed the real routing state.

### A mitigation needs to be lifted

Run the template's **rollback** (e.g. `withdraw_blackhole_prefix`,
`cloudflare_restore_security_level`) from `/reroutes`. Rollbacks are themselves
audited and verified. Blackholes with `auto_expiry_seconds` lift automatically
unless renewed.

### Telemetry went stale

The asset shows `telemetry_stale`. Traffic-threshold rules are suppressed (by
design). Check the flow exporter, the collector, and `POST
/api/assets/{id}/test/telemetry`. Do not force reroutes off stale data.

### Email alerts not arriving

Check `alert_deliveries` for `failed`/`bounced`, the controller's alert-dispatcher
log lines (`journalctl -u rerouter-controller`), and the `SMTP_*` environment
variables on the service. Remember dedup/rate-limit collapses repeats —
`uncertain`, `failed`, and security events are never collapsed.

### Origin reachable directly (bypassing Cloudflare)

The origin must accept 443 only from Cloudflare IP ranges. If direct hits appear
in logs (non-Cloudflare source), re-apply the firewall allowlist — see
[deployment.md](deployment.md).

## Backups

Back up: the MariaDB database, `/etc/rerouter/` (config + keys), the controller's
environment file (`DATABASE_URL`, `SESSION_SECRET`, `SECRETS_KEY`, `SMTP_*`),
and exported reroute templates. Never commit secrets to Git. Test restore into a
staging DB periodically.

## Routine checks

- Confirm `operating_mode` (observe/enforce) and `automatic_actions_enabled`
  match the intended posture.
- Review open locks and stale cooldowns weekly.
- Review `uncertain`/`failed` reroutes and audit logs after any incident.
- Verify retention jobs are pruning `traffic_samples` (7d) and keeping audit logs.
- Rotate provider API tokens and BGP keys on schedule.
