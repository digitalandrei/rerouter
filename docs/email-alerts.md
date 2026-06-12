# Email Alerts

Rerouter sends email alerts so operators learn about attacks and reroutes even
when they aren't watching the dashboard. Email is sent by the **controller**
itself via SMTP (lettre, rustls), processed by an internal async alert-dispatcher
task so alerting never blocks API requests, detection, or reroutes.

## Triggers

An alert is generated on:

- `attack_detected` — a detection rule fired (threshold crossed above/below for
  the configured duration); in observe mode the payload carries the would-run
  action plan;
- `operating_mode_changed` — observe/enforce flipped (admin-only, audited);
- `reroute_planned` / `reroute_started` / `reroute_succeeded` / `reroute_failed`;
- `reroute_uncertain` — action left ambiguous (see [state-recovery.md](state-recovery.md));
- `asset_unreachable` / `telemetry_stale`;
- `lock_created` / `lock_cleared`;
- security events: `2fa_recovery_used`, `account_locked`, `reauth_for_action`.

Each alert type has a default severity and can be enabled/disabled per recipient
and per asset.

## Pipeline

```text
controller writes an `alerts` row (event_type, severity, asset, rule, action, payload)
        |
        v
alert-dispatcher task (async, in-process) picks up new alerts
        |
        v
resolve recipients (by role + per-asset subscriptions)
        |
        v
de-duplicate + rate-limit (see below)
        |
        v
render email -> send via SMTP (lettre) -> record outcome in `alert_deliveries`
```

The dispatcher is a dedicated tokio task inside `rerouter-controller`, decoupled
from the detection and reroute engines: the engines only write `alerts` rows, so
a slow or failing SMTP server never blocks telemetry ingestion or a reroute. The
intent is durably recorded in the database first — a crash or restart never loses
an alert; the dispatcher resumes from unsent rows.

## De-duplication & rate limiting

Attacks are bursty; detection rules can fire repeatedly. To avoid mailstorms:

- collapse repeats of the same `(event_type, asset, rule)` within a window
  (default 10 min) into one email, with an occurrence count;
- per-recipient rate cap (default max 20 emails / hour) with a digest fallback;
- always send `reroute_uncertain`, `reroute_failed`, and security events
  immediately (these are never collapsed away).

## Recipients & subscriptions

- Recipients are users (or external addresses) with verified email.
- Subscriptions: by role (e.g. all `operator`s) and/or per-asset opt-in.
- Critical alerts (`uncertain`, `failed`) always go to `admin`s.

## Configuration

- SMTP settings are env vars consumed by the controller
  (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`) — see
  [../deploy/env/rerouter.example.env](../deploy/env/rerouter.example.env).
- Alert routing, thresholds, and per-recipient toggles are stored in the DB and
  managed from `/alerts` in the UI.

## Tables

`alerts`, `alert_recipients`, `alert_subscriptions`, `alert_deliveries` — see
[database.md](database.md). Delivery records (sent/failed/bounced) are retained for
audit and troubleshooting.

## Content

Every alert email includes: event type + severity, asset and prefix, the rule and
metric value that fired (and whether it crossed above or below the threshold),
the reroute (if any) and its state, a timestamp, and a deep link to the relevant
UI page. In **observe** mode (read-only / alert-only — see
[reroute-engine.md](reroute-engine.md) "Operating mode"), `attack_detected`
alerts additionally include the rendered **would-run action plan**: the exact
template, provider, prefix, and parameters that `enforce` mode would have
executed. Never include secrets or raw credentials.
