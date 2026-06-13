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

Metrics come from SNMP interface polling, so the set is exactly the seven
derived/raw interface signals — there are no SYN, per-source, or connection-rate
metrics (SNMP cannot produce them):

```text
rx_bps  tx_bps  rx_pps  tx_pps  rx_util_percent  tx_util_percent  oper_status
```

`oper_status` resolves to `1` when the link is `up`, else `0`, so a rule like
`oper_status < 1` fires on link-down.

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

Rule evaluation is **stateful** and runs after every device poll. A single bad
sample must not trigger anything. A rule **fires on the rising edge** once its
condition has held long enough, where "long enough" is satisfied by **either**
gate (logical OR):

```text
held for >= duration_seconds        OR
consecutive_samples valid matches
```

So a rule can require a sustained duration, a sample count, or (with one of them
zeroed) just the other. While firing, the rule does not re-alert each tick.

Track per rule (`rule_states`): `current_state`, `first_matched_at`,
`last_matched_at`, `last_cleared_at`, `consecutive_match_count`,
`last_metric_value`, `last_evaluated_at`, `last_triggered_reroute_id`.

Rule lifecycle: `clear -> matching -> firing -> (alert / actions) -> cleared`.
Clearing uses **hysteresis**: once firing, a rule only returns to `clear` after
the condition has stopped matching for `hysteresis_seconds` (a settle window that
prevents flapping). A rule still in the `matching` state that stops matching drops
straight back to `clear`.

## Inputs the engine must respect

- Ignore **stale** or **invalid** samples: only an `interface_metrics_current` row
  with `valid_sample = 1` and a `sampled_at` newer than `stale_after_seconds`
  advances a rule's state (a wrapped/reset/failed counter read is never trusted).
- SNMP rates are absolute (counter deltas over the poll interval) — no flow
  sampling-rate scaling applies.

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
