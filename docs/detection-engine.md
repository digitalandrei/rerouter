# Detection Engine

Detection rules decide *when* an asset is considered under attack (or anomalous).
A rule firing is a signal — it does **not** by itself reroute traffic. Whether a
fired rule triggers a reroute, an email alert, or both is configured per rule and
gated by the safety model in [reroute-engine.md](reroute-engine.md).

## Rule shape

A rule belongs to: an asset; a metric; an operator; a threshold; a duration /
consecutive-sample requirement; a severity; an optional schedule; an optional
reroute template; a cooldown policy; an enabled flag; an
`automatic_reroute_enabled` flag (default **false**).

Metrics: `rx_bps`, `tx_bps`, `rx_pps`, `tx_pps`, `new_conns_per_sec`, `syn_rate`,
`syn_ack_ratio`, `unique_src_count`, `pps_over_baseline`, `bps_over_baseline`,
`reachability`, `telemetry_stale`.

Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`, `between`, `outside`, `changed`,
`stale`.

## Example rules

```text
Asset 203.0.113.0/24  rx_bps   > 8Gbps              for 60s   -> blackhole or scrub
Asset 203.0.113.10    pps_in   > 1.5Mpps            for 30s   -> flowspec_drop
Asset web-edge        syn_rate > 200000/s and syn_ack_ratio < 0.1 for 30s -> cloudflare_under_attack
Asset 203.0.113.0/24  bps_over_baseline > 5x         for 60s   -> alert only
Asset api.example     unique_src_count > 50000       for 120s  -> rate_limit
```

## Stateful evaluation

Rule evaluation is **stateful**. A single bad sample must not trigger a reroute
unless explicitly configured. By default a rule requires a sustained match:

```text
minimum consecutive matching samples: 3
minimum trigger duration: 30s   (attack signals are faster than the original
                                 router-CLI domain; tune per metric)
```

Track per rule: `current_state`, `first_matched_at`, `last_matched_at`,
`last_cleared_at`, `consecutive_match_count`, `last_metric_value`,
`last_evaluated_at`, `last_triggered_reroute_id`.

Rule lifecycle: `clear -> matching -> firing -> (action / alert) -> cleared`.
A rule clears when the condition stops matching for the configured hysteresis
window (avoid flapping).

## Inputs the engine must respect

- Ignore **stale** or **invalid** telemetry samples (do not fire on them, except
  rules whose metric *is* `telemetry_stale`).
- Apply the correct flow **sampling rate** before comparing to absolute thresholds.
- Suppress traffic-threshold rules for an asset while a reroute is active on it
  (the post-reroute traffic profile is expected to change).

## Outputs

When a rule fires (its metric crossed above/below the threshold for the
configured duration), the engine emits a **rule event** and, per configuration:

- always: record the event, update dashboards;
- if alerting configured: record an `alerts` row for the controller's alert
  dispatcher to send (see [email-alerts.md](email-alerts.md));
- in **observe** mode (the shipped default — see
  [reroute-engine.md](reroute-engine.md) "Operating mode"): no execution ever;
  if a template is attached, its **would-run plan** is rendered in dry-run and
  included in the rule event and the alert;
- in **enforce** mode, if a reroute template is attached and execution is
  permitted: hand off to the reroute engine, which re-checks every safety gate
  before doing anything.

Rule events are retained (see [database.md](database.md)) and are the basis for
"why did this reroute happen?" forensics.
