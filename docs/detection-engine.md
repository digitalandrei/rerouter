# Detection Engine

Detection rules decide *when* a monitored **interface** is anomalous (under attack
or saturated). A rule firing is a signal — it does **not** by itself reroute
traffic. Whether a fired rule triggers a reroute, an email alert, or both is
configured per rule and gated by the safety model in
[reroute-engine.md](reroute-engine.md).

## Rule shape

A rule targets a **monitored interface** (`interface_id`, plus its `device_id`)
and carries: a metric; an operator; a threshold; a `duration_seconds` and a
`consecutive_samples` requirement; a severity; an optional schedule; a cooldown
policy; an `enabled` flag; and an `automatic_reroute_enabled` flag (default
**false**). A rule's mitigation is **not** a single template column — its actions
live in the `rule_actions` table (see "Actions" below). (The legacy
`rules.reroute_template_id` column is unused.)

Metrics come from SNMP interface polling (the v1 source), plus two flow-derived
metrics when the flow collector is enabled. There are no SYN, per-source, or
connection-rate metrics from SNMP:

```text
rx_bps  tx_bps  rx_pps  tx_pps  rx_util_percent  tx_util_percent
in_err_rate  out_err_rate  oper_status
flow_pps  flow_bps            (flow collector, off by default; sampling-estimated)
```

Flow rules select a direction and may select a source/destination port plus an
optional protocol. A protocol without a port is rejected because the stored
rollups have no protocol-only bucket; migration
`20260710000600_disable_ambiguous_flow_rules.sql` disables legacy ambiguous
rules rather than silently evaluating broader traffic.

`oper_status` resolves to `1` when the link is `up`, else `0`, so a rule like
`oper_status < 1` fires on link-down. `in_err_rate` / `out_err_rate` are
errors/sec derived from the cumulative `ifInErrors`/`ifOutErrors` deltas (0 on a
counter wrap), so a rule like `in_err_rate > 100` fires on an error storm.

### Aggregation (summed rules)

A rule's `metric_aggregation` is `single` (the default — one interface) or `sum`.
A `sum` rule has no single owning interface/device; it lists member interfaces in
`rule_interfaces` (which may span **multiple devices**) and thresholds the **sum**
of a rate metric (`rx_bps`/`tx_bps`/`rx_pps`/`tx_pps`/`in_err_rate`/`out_err_rate`
— summing a percentage or status is meaningless and rejected) across them. Summed
rules are evaluated in a single global pass (`evaluate_aggregate_rules`), not in
the per-device loop. **Conservative sampling:** if ANY member lacks a fresh, valid
sample, the whole observation is skipped — a summed rule never fires on partial
data (doctrine "low confidence blocks").

Operators: `>`, `>=`, `<`, `<=`, `==`, `!=`. (The two-argument forms `between` /
`outside` and the `changed` / `stale` operators are parsed but not evaluated — the
evaluator only compares a single value against a single threshold.)

## Example rules

```text
Interface Te0/0/0  rx_bps          > 8e9     for 60s   -> blackhole_prefix
Interface Te0/0/0  rx_pps          > 1.5e6   for 30s   -> null_route_prefix
Interface Gi0/1    rx_util_percent > 90      for 60s   -> alert only
Interface Te0/0/1  oper_status     < 1       for 0s    -> alert only (link down)
```

The mitigation column is illustrative: in practice the rule's `rule_actions`
choose the template(s), target router(s), and parameters.

## Stateful evaluation

Rule evaluation is **stateful** and runs after every device poll or closed flow
bucket. A single bad sample must not trigger anything. A rule **fires on the
rising edge** once its condition satisfies every enabled persistence gate:

```text
held for >= duration_seconds        AND
consecutive_samples valid matches
```

A zero disables that gate. The UI uses a duration window for flow rules and
consecutive samples for SNMP rules, so only one is normally enabled; API clients
may require both on SNMP rules, but the rules API now **rejects**
`consecutive_samples > 0` on flow rules (each tick re-reads the same latest
closed bucket, so it would count poll ticks against unchanged evidence) —
flow rules are window-only. While firing, the rule does not re-alert each tick.

Track per rule (`rule_states`): `current_state`, `first_matched_at`,
`last_matched_at`, `last_cleared_at`, `consecutive_match_count`,
`last_metric_value`, `last_evaluated_at`, `last_triggered_reroute_id`.

Rule lifecycle: `clear -> matching -> firing -> (alert / actions) -> cleared`.
Clearing is governed by the rule's **`recovery_mode`** (`auto` | `threshold` |
`manual`): `auto` returns to `clear` after the condition stops matching for a
settle window (`recovery_window_seconds` for flow / `recovery_consecutive_samples`
for SNMP, falling back to the global default); `threshold` requires a distinct
`recovery_threshold_value` to be crossed; `manual` holds `firing` until an operator
clears it. A rule still in `matching` that stops matching drops straight to `clear`.

## Inputs the engine must respect

- Ignore **stale** or **invalid** samples: only an `interface_metrics_current` row
  with `valid_sample = 1` and a `sampled_at` newer than `stale_after_seconds`
  advances a rule's state (a wrapped/reset/failed counter read is never trusted).
- SNMP rates are absolute (counter deltas over the poll interval) — no flow
  sampling-rate scaling applies.
- Flow observations must come from an enrolled exporter, a closed fresh bucket,
  and non-low sampling confidence. Port selectors are evaluated at the latest
  interface-bucket timestamp; no matching port row means a current zero with low
  confidence, never reuse of an older non-zero bucket. Flow-derived automatic
  actions additionally require the separate off-by-default flow automation gate
  and contemporaneous same-interface SNMP volume within the configured ratio
  band. Failed corroboration may still produce a visible rule observation, but
  it cannot move traffic automatically.

## Outputs

When a rule fires, the engine records the event and inserts one `alerts` row with
`event_type = 'rule_fired'` (the alert dispatcher sends it — see
[email-alerts.md](email-alerts.md)). The alert payload carries the metric, the
observed vs. threshold values, the interface, and — depending on mode and the
rule's switch — the rule's actions:

- **"The rule decides."** A rule's mitigation is its `rule_actions` set (each row
  = template + target router + parameters), so one fired rule can fan the same
  mitigation out to several routers.
- in **observe** mode (the shipped default — see
  [reroute-engine.md](reroute-engine.md) "Operating mode"), **or** for any rule
  whose `automatic_reroute_enabled` is off: nothing executes; each action is
  rendered to its exact would-run commands and attached to the alert
  (`would_run_actions`);
- in **enforce** mode, and only when the rule's `automatic_reroute_enabled` is on:
  the firing edge hands each action to the reroute executor, which re-checks its
  own device-scoped gates (a locked or cooling-down device is skipped safely); the
  outcomes are attached to the alert (`executed_actions`).

Rule events / alert rows are retained (see [database.md](database.md)) and are the
basis for "why did this reroute happen?" forensics.
