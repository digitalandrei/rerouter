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
assets      protected_assets, asset_statuses, asset_provider
providers   reroute_providers, provider_credentials
devices     devices, device_interfaces, interface_metrics_current, interface_samples
telemetry   asset_metrics_current, traffic_samples
detection   rules, rule_states, rule_events
reroute     reroute_templates, reroutes, reroute_steps, reroute_outputs,
            reroute_verifications
safety      locks, cooldowns
alerts      alerts, alert_recipients, alert_subscriptions, alert_deliveries
core        audit_logs, system_settings
```

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
id, user_id, token_hash, totp_verified, reauth_at, ip_address, user_agent,
created_at, last_activity_at, expires_at
```

`totp_verified` gates the 2FA-complete state of a session; `reauth_at` records
the last fresh password+TOTP re-auth backing a high-safety reroute.

## roles / permissions

Explicit RBAC tables, enforced by the controller's axum middleware/extractors.
Roles: admin, operator, viewer, auditor.

```text
roles:            id, name, created_at, updated_at
permissions:      id, name, created_at, updated_at
role_user:        role_id, user_id
permission_role:  permission_id, role_id
```

## protected_assets

```text
id, name, kind(prefix|ip|service), cidr, address_family(v4|v6),
description, owner, site, criticality,
enabled, flow_enabled, bgp_enabled, cloudflare_zone_id,
auto_reroute_eligible (default 0),
created_at, updated_at
```

## asset_provider

Link table: which providers are eligible to reroute which assets (see the
enrollment flow in [asset-enrollment.md](asset-enrollment.md)).

```text
asset_id, provider_id   (composite PK; FKs cascade on delete)
```

## asset_statuses

```text
asset_id, overall_status, network_status, telemetry_status, provider_status,
last_successful_sample_at, last_failed_sample_at, last_failure_reason,
last_seen_at, telemetry_stale, updated_at
```

## reroute_providers

```text
id, name, type(cloudflare|bgp_rtbh|flowspec|scrubber), enabled, actions_enabled,
endpoint, peer_ip, local_asn, remote_asn, blackhole_community, permitted_prefixes_json,
credential_id, health_status, last_success_at, last_failure_reason,
created_at, updated_at
```

## provider_credentials

Only references/metadata in DB; secret material encrypted at rest by the
controller (AES-256-GCM, key from `SECRETS_KEY`) or file-based.

```text
id, provider_id, name, kind(api_token|bgp_key|ssh_key|password),
encrypted_value, key_path, created_at, updated_at
```

## asset_metrics_current

Latest normalized metrics per asset (one row per asset).

```text
asset_id, sampled_at, method, valid_sample, sampling_rate,
rx_bps, tx_bps, rx_pps, tx_pps,
new_conns_per_sec, syn_rate, syn_ack_ratio, unique_src_count,
top_src_asn, top_dst_port, telemetry_stale, updated_at
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
-- SSH access (captured at onboarding for future CLI reroute actions; unused in
-- observe mode). Password XOR key; all secrets AES-256-GCM, never returned.
ssh_username, ssh_port (default 22), ssh_auth_method(password|key, nullable),
ssh_password_encrypted, ssh_private_key_encrypted, ssh_key_passphrase_encrypted,
ssh_host_fingerprint (reserved),
created_at, updated_at
```

## device_interfaces

Interfaces discovered on a device (ifXTable + ifTable), reconciled by
`(device_id, if_index)`. Only `enabled_for_monitoring = 1` rows are polled and
rule-evaluated.

```text
id, device_id, if_index, if_name, if_descr, if_alias, if_speed_bps,
admin_status, oper_status, is_physical, enabled_for_monitoring (default 0),
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

Retained per-interface rate history (default 7-day retention, like
`traffic_samples`). Only derived rates; raw counters stay in
`interface_metrics_current`.

```text
id, interface_id, device_id, sampled_at, valid_sample,
rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent, created_at
```

## traffic_samples

High volume; retention-controlled (default 7 days).

```text
id, asset_id, sampled_at, method, valid_sample, sampling_rate,
rx_bps, tx_bps, rx_pps, tx_pps, new_conns_per_sec, syn_rate, syn_ack_ratio,
unique_src_count, raw_ref, created_at
```

## rules

A rule targets a protected **asset** XOR a monitored **interface** (the
interface path was added with the SNMP device tables; `asset_id` is now
nullable, and `interface_id`/`device_id` are the alternative target — enforced in
application code).

```text
id, asset_id (nullable), interface_id (nullable), device_id (nullable),
name, metric, operator, threshold_value, threshold_unit,
duration_seconds, consecutive_samples, severity, schedule_json,
enabled, automatic_reroute_enabled (default 0), reroute_template_id,
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

```text
id, rule_id, asset_id, event(matched|fired|cleared), metric_value,
sampled_at, created_at
```

## reroute_templates

```text
id, name, description, provider_type, mode, safety_level,
automatic_allowed, manual_confirmation_required,
parameter_schema_json, plan_json, verification_json,
rollback_template_id, auto_expiry_seconds, enabled, created_at, updated_at
```

## reroutes (actions)

```text
id, asset_id, provider_id, rule_id, reroute_template_id,
trigger_type(automatic|manual|rollback), triggered_by_user_id,
state(planned|pending|running|verifying|succeeded|failed|uncertain),
safety_level, reason, parameters_json, planned_steps_json,
started_at, finished_at, success, failure_reason, verification_status,
expires_at, cooldown_until, created_at, updated_at
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

```text
locks:     id, scope(global|asset|provider|prefix|template), scope_ref,
           reason, kind(manual|auto_failed|auto_crash|auto_uncertain),
           created_by, created_at, cleared_by, cleared_at
cooldowns: id, scope(rule|asset|prefix_provider|global), scope_ref,
           until, reason, created_at
```

## alerts / delivery

```text
alerts:              id, event_type, severity, asset_id, device_id, interface_id,
                     rule_id, reroute_id,
                     payload_json, dedup_key, occurrence_count, created_at
alert_recipients:    id, user_id, email, verified_at, created_at
alert_subscriptions: id, recipient_id, asset_id(null=all), event_type(null=all),
                     enabled, created_at
alert_deliveries:    id, alert_id, recipient_id, channel(email),
                     status(queued|sent|failed|bounced), error, sent_at, created_at
```

## audit_logs

Append-only. Audit everything.

```text
id, actor_type(user|controller|system), actor_user_id, event_type,
entity_type, entity_id, asset_id, reroute_id, message,
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

```text
traffic_samples:     7 days
rule_events:         90 days
reroutes/outputs:    365 days
alert_deliveries:    365 days
audit_logs:          permanent (or 365+ days)
```

The controller runs an internal cleanup task honouring these. Never delete
`audit_logs` automatically without an explicit retention decision.
