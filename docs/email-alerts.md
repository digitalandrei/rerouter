# Alerts (Email + Microsoft Teams)

Rerouter sends alerts so operators learn about attacks and reroutes even when
they aren't watching the dashboard. Alerts are delivered by the **controller**
itself over two channels — **email** (SMTP via lettre, rustls) and **Microsoft
Teams** (incoming webhook, HTTP POST of a MessageCard via reqwest) — processed by
one internal async alert-dispatcher task so alerting never blocks API requests,
detection, or reroutes. Each `alerts` row is fanned out to whichever channels are
subscribed to its event type; deliveries are recorded per channel in
`alert_deliveries` (`channel` ∈ {`email`, `teams`}).

## Triggers

An alert (an `alerts` row) is generated on:

- `rule_fired` — a detection rule on a monitored **interface** (or device)
  crossed its threshold above/below for the configured settle window; the payload
  carries the device, interface, rule, metric/observed value, and — in observe
  mode — the rendered would-run action plan;
- reroute lifecycle: `reroute_planned` / `reroute_started` / `reroute_succeeded`
  / `reroute_failed`; the payload carries the **actor** (who — for manual and
  rollback triggers), the exact **commands run**, and the **rollback** commands to
  undo the action by hand. `rollback` runs are reroute events with
  `trigger_type = rollback`;
- `reroute_uncertain` — action left ambiguous (see [state-recovery.md](state-recovery.md));
- **arming / mode flips** — `operating_mode_changed`, `automatic_actions_changed`,
  `global_lock_changed`: the highest-consequence state changes (they can allow
  traffic-moving actions), so they are emitted as alerts with the **actor** and the
  before → after values, and are in `ALWAYS_IMMEDIATE` (page right away). They are
  still audited too;
- security events: `2fa_recovery_used`, `account_locked`.

> Device-unreachable / telemetry-stale show up via `GET /api/status`
> (`telemetry_stale_count`) and stale UI state rather than a dedicated alert email.
> Safety-lock create/clear and uncertain-acknowledge remain audit-log only.

Each alert type has a default severity and can be enabled/disabled per recipient
via subscriptions (by **role** and/or **event type**).

## Pipeline

```text
controller writes an `alerts` row
   (event_type, severity, device_id, interface_id, rule_id, payload_json, dedup_key)
        |
        v
alert-dispatcher task (async, in-process) picks up new alerts
        |
        v
resolve recipients (by role + event-type subscriptions)
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

- collapse repeats with the same `alerts.dedup_key` (per event type + the firing
  device/rule, or user for security events) within a window (default 10 min) into
  one email, with an occurrence count;
- per-recipient rate cap (default max 20 emails / hour) with a digest fallback;
- always send `reroute_uncertain`, `reroute_failed`, and security events
  immediately (these are never collapsed away).

## Recipients & subscriptions

- Recipients are users (or external addresses) with verified email
  (`alert_recipients`).
- Subscriptions (`alert_subscriptions`): by role (e.g. all `operator`s) and/or by
  event type (a NULL event type matches all).
- Critical alerts (`uncertain`, `failed`, security events) always fan out to the
  admin tier (`admin` / `superadmin`).

## Teams webhook channel

- A Teams endpoint is an **incoming-webhook URL** stored **encrypted at rest**
  (AES-256-GCM, `crypto::seal`) in `webhook_endpoints` — only ciphertext is
  persisted, and the URL is never returned to the client or logged.
- Per-event routing lives in `webhook_subscriptions` (NULL `event_type` = all
  events), mirroring `alert_subscriptions`. The same 10-minute de-dup and 20/hr
  rate limit apply, keyed on the endpoint; `ALWAYS_IMMEDIATE` events bypass both.
- The dispatcher drains when **either** SMTP is configured **or** at least one
  enabled webhook exists. If SMTP is down but a webhook is configured, Teams still
  delivers; an alert with no audience on either channel stays queued (so email
  retries once SMTP comes up) unless SMTP was up and simply had no recipients.
- No alert payload (email or Teams) ever contains a secret.

## Configuration

- SMTP settings are env vars consumed by the controller
  (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`) — see
  [../deploy/env/rerouter.example.env](../deploy/env/rerouter.example.env).
- Email recipients and Teams webhooks (with per-event routing and a test-send)
  are managed from the **Notifications** section of `/settings`
  (`manage_alerts`), backed by `/api/notifications/*`. Webhook URLs are
  write-only (encrypted, never shown again).

## Tables

`alerts`, `alert_recipients`, `alert_subscriptions`, `alert_deliveries` (now
channel-aware, with a nullable `recipient_id` + an `endpoint_id`),
`webhook_endpoints`, `webhook_subscriptions` — see [database.md](database.md).
Delivery records (sent/failed/bounced/queued) are retained for audit and
troubleshooting.

## Content

Every alert email includes: event type + severity, the **device** and (for
interface rules) the **interface**, the rule and metric value that fired (and
whether it crossed above or below the threshold), the reroute (if any) and its
state, a timestamp, and a deep link to the relevant UI page. In **observe** mode
(read-only / alert-only — see [reroute-engine.md](reroute-engine.md) "Operating
mode"), `rule_fired` alerts additionally include the rendered **would-run action
plan** (and its **rollback** commands): the exact template, target device, prefix,
and parameters that `enforce` mode would have executed. `reroute_*` emails include
the **trigger** (manual / automatic / rollback), the **actor** who decided (for
manual), the **commands run**, and the **rollback** commands to undo the action by
hand. Arming / mode-flip emails state the before → after change and the actor.
Never include secrets or raw credentials (no SNMP community, SSH password/key, or
full command output beyond the rendered plan).
