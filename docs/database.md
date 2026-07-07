# Database (MariaDB)

Single **MariaDB** database owned by the Rust controller (sqlx). The schema is
managed by sqlx SQL migrations in `backend-rust/migrations/` (plain SQL files,
e.g. `20260612000100_users_and_auth.sql`) — the Rust repo is the single source
of schema truth.

> Engine: InnoDB, `utf8mb4`. Use `BIGINT UNSIGNED` PKs, UTC timestamps, and
> foreign keys with sensible `ON DELETE` behaviour. High-volume sample tables are
> partition/retention candidates.

## Table groups

```text
auth        users, roles, permissions, role_user, permission_role, sessions
devices     devices, device_interfaces, interface_metrics_current, interface_samples,
            device_bgp_peers, device_bgp_networks
routing     rtbh_communities
detection   rules, rule_states, rule_events, rule_actions
reroute     reroute_templates, reroutes, reroute_steps, reroute_outputs,
            reroute_verifications
safety      locks, cooldowns
alerts      alerts, alert_recipients, alert_subscriptions, alert_deliveries
core        audit_logs, system_settings
```

> **Asset/provider model dropped.** The original abstract `protected_assets` /
> `reroute_providers` layer (and `asset_provider`, `asset_statuses`,
> `provider_credentials`, `asset_metrics_current`, `traffic_samples`) was removed
> by migration `20260614000100_drop_asset_provider_model.sql`, along with the
> orphaned `asset_id`/`provider_id` columns it left on the live tables. The
> shipped telemetry + mitigation model is **devices / interfaces** (SNMP polling)
> with `device_cli` reroutes over SSH; per-interface telemetry lives in
> `interface_metrics_current` (latest) + `interface_samples` (history).

## auth / users

Created by our own migration; passwords are Argon2id hashes and the 2FA columns
are described in [authentication.md](authentication.md):

```text
id, name, email, password,
two_factor_secret, two_factor_recovery_codes, two_factor_confirmed_at,
two_factor_enforced, failed_login_attempts, locked_until,
last_login_at, last_login_ip, created_at, updated_at
```

## sessions

Server-side store backing the session cookie (see
[authentication.md](authentication.md)):

```text
id, user_id, token_hash, totp_verified, ip_address, user_agent,
created_at, last_activity_at, expires_at
```

`totp_verified` gates the 2FA-complete state of a session. (The `reauth_at`
column was dropped: the re-auth gate it backed — for "high safety" reroutes —
was removed along with the `safety_level` classification.)

## roles / permissions

Explicit RBAC tables, enforced by the controller's axum middleware/extractors.
Roles: admin, operator, viewer, auditor.

```text
roles:            id, name, created_at, updated_at
permissions:      id, name, created_at, updated_at
role_user:        role_id, user_id
permission_role:  permission_id, role_id
```

## devices (SNMP)

The v1 telemetry source: polled SNMP v2c devices (routers). See
[device-enrollment.md](device-enrollment.md). The community / v3 key material is
AES-256-GCM ciphertext (key from `SECRETS_KEY`); only ciphertext is stored and it
is never returned by the API.

```text
id, name (unique), hostname, snmp_version(v2c|v3), snmp_port,
community_encrypted (VARBINARY, nullable), v3_* (reserved, nullable),
poll_interval_seconds, enabled,
vendor, model, os_version, sys_name, sys_uptime,   -- learned from sysDescr
reachable (default 0), last_poll_at, last_error,
-- SSH access — actively used by the device_cli reroute engine (backend-rust/src/ssh/)
-- to push config and run verification `show`s. Password XOR key; all secrets
-- AES-256-GCM, never returned. ssh_public_key is NOT secret (plaintext, returned
-- by the API) so the UI can show it for `ip ssh pubkey-chain` enrollment.
ssh_username, ssh_port (default 22), ssh_auth_method(password|key, nullable),
ssh_password_encrypted, ssh_private_key_encrypted, ssh_key_passphrase_encrypted,
ssh_host_fingerprint (reserved), ssh_public_key (TEXT, nullable, plaintext),
created_at, updated_at
```

## device_interfaces

Interfaces discovered on a device (ifXTable + ifTable), reconciled by
`(device_id, if_index)`. **Every** discovered interface is polled, chartable, and
rule-evaluable (the old `enabled_for_monitoring` toggle was dropped — it no longer
gated anything).

```text
id, device_id, if_index, if_name, if_descr, if_alias, if_speed_bps,
admin_status, oper_status, is_physical,
display_order, first_seen_at, last_seen_at
UNIQUE (device_id, if_index)
```

## interface_metrics_current

Exactly one row per interface. The raw `*_octets` / `*_pkts` columns are the
counters from the last valid poll and form the baseline for the next delta —
raw and derived are kept strictly separate. `valid_sample = 0` marks a
wrapped/reset/failed read whose rates detection must not trust.

```text
interface_id (PK), device_id, sampled_at, valid_sample,
in_octets, out_octets, in_ucast_pkts, out_ucast_pkts,   -- raw (next baseline)
rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent,  -- derived
in_errors, out_errors, in_discards, out_discards,
admin_status, oper_status, updated_at
```

## interface_samples

Retained per-interface rate history — the raw per-interface sample history that
backs the detail-page charts (the scheduler prunes it to
`[retention].traffic_samples_days`, default 7 days; see
[Retention defaults](#retention-defaults)). Only derived rates; raw counters stay
in `interface_metrics_current`.

```text
id, interface_id, device_id, sampled_at, valid_sample,
rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent, created_at
```

## device_bgp_peers

BGP neighbors discovered over SNMP (BGP4-MIB `bgpPeerTable`), reconciled by
`(device_id, peer_remote_addr)` and refreshed every poll. Read-only telemetry that
backs the neighbor picker for the `bgp_session_*` templates (operators pick a real
neighbor — e.g. a GRE scrubber session). IPv4 only in v1.

```text
id, device_id, peer_remote_addr, peer_remote_as, local_as,
peer_state, peer_admin_status, label,
first_seen_at, last_seen_at, last_polled_at, created_at, updated_at
UNIQUE (device_id, peer_remote_addr)
```

## device_bgp_networks

Per-device announced prefixes (BGP `network` statements), discovered from config
over SSH and revalidated daily/manually. Backs the "announced prefix" picker for
the `blackhole_*` / `null_route_*` templates.

```text
id, device_id, prefix (CIDR), first_seen_at, last_seen_at,
last_discovered_at, created_at, updated_at
UNIQUE (device_id, prefix)
```

## rtbh_communities

Global list of blackhole communities (standard `X:Y` or large `X:Y:Z`) plus the
route **tag** the routers' RTBH redistribute route-map matches to set that
community. Backs the "RTBH community" picker for `blackhole_*` (the chosen row's
`tag` flows into `ip route … Null0 tag {tag}`).

```text
id, label, kind(standard|large), community, tag (unique),
created_by, created_at, updated_at
```

## rules

The live rule targets a monitored **interface** (`interface_id` + a denormalized
`device_id`); the evaluator only selects `interface_id IS NOT NULL` rows. (The old
`asset_id` column was dropped with the asset model.) A rule's mitigation is **not**
the `reroute_template_id` column (now legacy / unused) — its actions live in
`rule_actions` (below).

```text
id, interface_id (nullable), device_id (nullable),
name, metric, operator, threshold_value, threshold_unit,
duration_seconds, consecutive_samples, severity, schedule_json,
enabled, automatic_reroute_enabled (default 0), reroute_template_id (legacy/unused),
alert_enabled (default 1), cooldown_seconds,
created_by, updated_by, created_at, updated_at
```

## rule_states

```text
rule_id, current_state, first_matched_at, last_matched_at, last_cleared_at,
consecutive_match_count, last_metric_value, last_evaluated_at,
last_triggered_reroute_id, updated_at
```

## rule_events

Keyed on `rule_id` only (the `asset_id` column was dropped with the asset model).

```text
id, rule_id, event(matched|fired|cleared), metric_value,
sampled_at, created_at
```

## rule_actions

A fired rule's mitigation: one or more actions, each `(template, target device,
params)`. Lets a rule fan the same mitigation out to several routers, each with
its own params (e.g. a different scrubber neighbor IP per router). The detection
engine renders these as the would-run plan (observe / manual-only) or hands them
to the executor (enforce + the rule's auto switch on).

```text
id, rule_id, reroute_template_id, device_id, params_json,
position (default 0), enabled (default 1), created_at, updated_at
KEY (rule_id)
```

## reroute_templates

`provider_type` enum is `cloudflare|bgp_rtbh|flowspec|scrubber|device_cli`, but
only **`device_cli`** (mode `ios_ssh`) has a backing executor — the others were
de-scoped. The `safety_level`, `manual_confirmation_required`, and
`auto_expiry_seconds` columns were **dropped** (the safety-level classification,
its re-auth/typed-confirmation gate, and template auto-expiry were all removed).

```text
id, name, description, provider_type, mode,
automatic_allowed,
parameter_schema_json, plan_json, verification_json,
rollback_template_id, enabled, created_at, updated_at
```

## reroutes (actions)

The target is `device_id` (the router the action ran against). The `asset_id` and
`provider_id` columns were **dropped** with the asset/provider model (the
`device_cli` executor never set either). The `safety_level`, `expires_at`, and
`cooldown_until` columns were also **dropped** (safety levels and auto-expiry
removed; cooldowns live in the `cooldowns` table keyed on the `device` scope).

```text
id, device_id (nullable),
rule_id, reroute_template_id,
trigger_type(automatic|manual|rollback), triggered_by_user_id,
state(planned|pending|running|verifying|succeeded|failed|uncertain),
reason, parameters_json, planned_steps_json,
started_at, finished_at, success, failure_reason, verification_status,
created_at, updated_at
```

## reroute_steps / reroute_outputs

```text
reroute_steps:   id, reroute_id, step_number, description, mode, state
reroute_outputs: id, reroute_id, step_number, request, response, status,
                 started_at, finished_at, created_at
```

## reroute_verifications

```text
id, reroute_id, method, expected, observed, result(pass|fail|uncertain),
checked_at, created_at
```

## locks / cooldowns

In practice only **`device`** and **`global`** locks and **`device`**, **`rule`**,
and **`global`** cooldowns are written — the device-CLI engine works at the device
scope. (The ENUMs still list the older asset/provider/prefix scope values from the
asset era, but no live path sets them.) A `device` lock is what an
`uncertain`/failed action or crash recovery sets; the per-device cooldown row is
what the 5-min post-action window writes.

```text
locks:     id, scope(global|asset|provider|prefix|template|device), scope_ref,
           reason, kind(manual|auto_failed|auto_crash|auto_uncertain),
           created_by, created_at, cleared_by, cleared_at
cooldowns: id, scope(rule|asset|prefix_provider|global|device), scope_ref,
           until, reason, created_at
```

## alerts / delivery

`alerts` key on `device_id` / `interface_id` / `rule_id`; `alert_subscriptions`
match by `event_type` only (NULL = all events). The `asset_id` columns on both were
**dropped** with the asset model.

```text
alerts:              id, event_type, severity, device_id, interface_id,
                     rule_id, reroute_id,
                     payload_json, dedup_key, occurrence_count, created_at
alert_recipients:    id, user_id, email, verified_at, created_at
alert_subscriptions: id, recipient_id, event_type(null=all),
                     enabled, created_at
alert_deliveries:    id, alert_id, recipient_id, channel(email|teams),
                     status(queued|sent|failed|bounced), error, sent_at, created_at
webhook_endpoints:   id, kind, url (AES-256-GCM sealed at rest), enabled, created_at
webhook_subscriptions: id, endpoint_id, event_type(null=all), enabled, created_at
```

## audit_logs

Append-only. Audit everything.

```text
id, actor_type(user|controller|system), actor_user_id, event_type,
entity_type, entity_id, reroute_id, message,
before_json, after_json, ip_address, user_agent, created_at
```

## system_settings

Key/value for global toggles. The DB value is authoritative at runtime (the
matching `[safety]` entries in `config.toml` are only startup fallbacks):

```text
operating_mode             observe | enforce   (seeded 'observe' — read-only /
                           alert-only: NO reroute executes, automatic or manual;
                           alerts carry the would-run action plan)
automatic_actions_enabled  seeded 'false' (gates automatic reroutes in enforce mode)
global_maintenance_lock    seeded 'false'
```

## Retention defaults

All windows below are enforced by `scheduler::retention_cleanup`, a single task
that runs every 10 minutes and honours the `[retention]` config block.

```text
interface_samples:   7 days   ([retention].traffic_samples_days)
flow_*_buckets:      7 days   ([retention].flow_buckets_days)
alerts:              7 days   ([retention].alerts_days)
rule_events:         7 days   ([retention].rule_events_days)
reroutes/outputs:    365 days ([retention].reroute_logs_days — advisory, see below)
alert_deliveries:    follows alerts (ON DELETE CASCADE from the alerts prune)
audit_logs:          permanent (never auto-deleted without an explicit decision)
```

> **Status (2026-07):** the short-term telemetry + protection history —
> `interface_samples`, the four `flow_*_buckets`, `alerts`, and `rule_events` —
> are actively pruned by `retention_cleanup` (unified: the flow collector no
> longer prunes its own buckets, and the old hardcoded ~70-minute
> `interface_samples` window is gone). The `reroutes` action log
> (`reroute_logs_days`) is **advisory and deliberately NOT auto-pruned**: it is a
> low-volume safety trail and its rows are live state-machine state (an
> `uncertain` reroute holds a device lock), so bounding it needs state-aware
> pruning, not a blanket time delete. `audit_logs` (security/admin trail) is
> likewise never auto-deleted.
