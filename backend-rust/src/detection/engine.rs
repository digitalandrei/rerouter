//! Interface-rule evaluation, run after every device poll or closed flow bucket.
//!
//! Stateful per rule via `rule_states` (clear -> matching -> firing) with
//! hysteresis. A rule FIRES on the rising edge once its condition has held for
//! every enabled persistence gate (`duration_seconds`, `consecutive_samples`);
//! a zero disables that gate. On the
//! edge we write a `rule_events` (fired) row and INSERT an `alerts` row. While
//! firing we do not re-alert each tick. Recovery uses the rule's configured
//! automatic, threshold, or manual policy.
//!
//! SAFETY (GATE 0): this engine NEVER executes a reroute directly. In observe
//! mode — or for a manual-only rule — a firing rule renders its attached actions
//! (`rule_actions`) as the would-run plan in the alert payload instead of acting.
//! Only in enforce mode, and only when the rule's auto switch is on, does it hand
//! the actions to the reroute executor (which re-checks its own safety gates).
//!
//! Stale/invalid samples are ignored: only `interface_metrics_current` rows with
//! `valid_sample = 1` and a recent `sampled_at` advance a rule's state.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::MySqlPool;

// TIMESTAMP columns decode as DateTime<Utc> (sqlx-mysql maps NaiveDateTime only
// to DATETIME); the pool pins the session tz to UTC.
type Ts = DateTime<Utc>;

use super::condition::Op;
use crate::config::Config;
use crate::reroute::flow_target::{self, FlowSelector, PreparedAction};

/// Flow-derived rule metrics (evaluated against the latest closed flow bucket
/// rather than interface_metrics_current). See docs/flow-telemetry.md.
const FLOW_METRICS: &[&str] = &["flow_pps", "flow_bps"];

fn is_flow_metric(metric: &str) -> bool {
    FLOW_METRICS.contains(&metric)
}

/// One metric reading feeding the rule state machine, from either telemetry
/// source. `low_confidence` (flow sampling not verified) blocks automatic
/// actions but never blocks alerting.
struct Observation {
    value: f64,
    sampled_at: Option<Ts>,
    low_confidence: bool,
    source_corroborated: bool,
}

/// One enabled interface rule with the bits the evaluator needs.
#[derive(Debug, Clone, sqlx::FromRow)]
struct InterfaceRule {
    id: u64,
    name: String,
    /// The target interface for a `single` rule; NULL for a `sum` rule (whose
    /// members live in `rule_interfaces`).
    interface_id: Option<u64>,
    device_id: Option<u64>,
    metric: String,
    /// 'single' (per-interface) | 'sum' (summed across rule_interfaces members).
    metric_aggregation: String,
    /// Flow-metric selector (NULL for SNMP interface metrics).
    flow_direction: Option<String>,
    flow_protocol: Option<u16>,
    flow_port: Option<u16>,
    flow_port_kind: Option<String>,
    operator: String,
    threshold_value: f64,
    duration_seconds: u32,
    consecutive_samples: u32,
    /// How a firing rule clears: auto | threshold | manual.
    recovery_mode: String,
    /// Recovery threshold for `threshold` mode (defaults to threshold_value).
    recovery_threshold_value: Option<f64>,
    /// Threshold-mode recovery overrides (NULL = mirror the firing persistence):
    /// flow recovery window (seconds) and SNMP recovery sample count.
    recovery_window_seconds: Option<u32>,
    recovery_consecutive_samples: Option<u32>,
    severity: String,
    /// Per-rule switch: in enforce mode, run the rule's actions automatically on
    /// the firing edge. "The rule decides" — this is the only auto gate besides
    /// enforce mode + the executor's locks/cooldowns.
    automatic_reroute_enabled: bool,
}

/// The latest derived metrics for an interface (only the columns rules read).
#[derive(Debug, Clone, sqlx::FromRow)]
struct CurrentMetrics {
    sampled_at: Option<Ts>,
    valid_sample: bool,
    rx_bps: f64,
    tx_bps: f64,
    rx_pps: f64,
    tx_pps: f64,
    rx_util_percent: f64,
    tx_util_percent: f64,
    in_err_rate: f64,
    out_err_rate: f64,
    oper_status: Option<String>,
}

impl CurrentMetrics {
    /// Resolve a metric name to its numeric value. oper_status maps up=1, else 0
    /// so threshold rules like `oper_status < 1` (link down) work.
    fn value(&self, metric: &str) -> Option<f64> {
        Some(match metric {
            "rx_bps" => self.rx_bps,
            "tx_bps" => self.tx_bps,
            "rx_pps" => self.rx_pps,
            "tx_pps" => self.tx_pps,
            "rx_util_percent" => self.rx_util_percent,
            "tx_util_percent" => self.tx_util_percent,
            "in_err_rate" => self.in_err_rate,
            "out_err_rate" => self.out_err_rate,
            "oper_status" => {
                if self.oper_status.as_deref() == Some("up") {
                    1.0
                } else {
                    0.0
                }
            }
            _ => return None,
        })
    }
}

/// Metrics that can be SUMMED across interfaces for a `sum` rule (rates only —
/// summing a percentage or a status would be meaningless).
const SUMMABLE_METRICS: &[&str] = &[
    "rx_bps",
    "tx_bps",
    "rx_pps",
    "tx_pps",
    "in_err_rate",
    "out_err_rate",
];

/// The prior `rule_states` row (absent => treated as clear/zero).
#[derive(Debug, Clone, Default, sqlx::FromRow)]
struct RuleStateRow {
    current_state: Option<String>,
    first_matched_at: Option<Ts>,
    recovery_first_at: Option<Ts>,
    recovery_consecutive: u32,
    consecutive_match_count: u32,
}

/// Evaluate every enabled interface rule on `device_id` against the latest
/// metrics. Called by the scheduler right after a poll stores fresh samples.
/// Per-rule failures are logged and skipped; one bad rule never stops the rest.
///
/// Rules are evaluated in PRIORITY order (severity: critical > warning > info,
/// then oldest rule first), so when two rules fire on the same device the
/// higher-priority one acts first. Auto-execution is mutually exclusive per
/// device: while a reroute is in flight the executor's per-device reserve guard
/// blocks any other action on that device; once it finalizes the device frees up
/// and the next still-firing rule can act on a later pass.
pub async fn evaluate_device(pool: &MySqlPool, cfg: &Config, device_id: u64) -> Result<usize> {
    let rules = sqlx::query_as::<_, InterfaceRule>(
        "SELECT id, name, interface_id, device_id, metric, metric_aggregation, \
                flow_direction, flow_protocol, flow_port, flow_port_kind, \
                operator, threshold_value, \
                duration_seconds, consecutive_samples, \
                recovery_mode, recovery_threshold_value, recovery_window_seconds, \
                recovery_consecutive_samples, severity, \
                automatic_reroute_enabled \
         FROM rules \
         WHERE enabled = 1 AND metric_aggregation = 'single' \
               AND interface_id IS NOT NULL AND device_id = ? \
         ORDER BY CASE severity \
             WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END, \
             id",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await?;

    let mut fired = 0usize;
    for rule in rules {
        match evaluate_rule(pool, cfg, &rule).await {
            Ok(true) => fired += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(event_type = "rule_eval_failed", rule_id = rule.id, error = %e, "rule evaluation failed");
            }
        }
    }
    Ok(fired)
}

/// Evaluate every `sum` (cross-interface / cross-device) rule once per poll
/// cycle. These rules have no single owning device, so they run in a global pass
/// rather than inside `evaluate_device`. Returns the number that fired this cycle.
pub async fn evaluate_aggregate_rules(pool: &MySqlPool, cfg: &Config) -> Result<usize> {
    let rules = sqlx::query_as::<_, InterfaceRule>(
        "SELECT id, name, interface_id, device_id, metric, metric_aggregation, \
                flow_direction, flow_protocol, flow_port, flow_port_kind, \
                operator, threshold_value, \
                duration_seconds, consecutive_samples, \
                recovery_mode, recovery_threshold_value, recovery_window_seconds, \
                recovery_consecutive_samples, severity, \
                automatic_reroute_enabled \
         FROM rules \
         WHERE enabled = 1 AND metric_aggregation = 'sum' \
         ORDER BY CASE severity \
             WHEN 'critical' THEN 0 WHEN 'warning' THEN 1 WHEN 'info' THEN 2 ELSE 3 END, \
             id",
    )
    .fetch_all(pool)
    .await?;

    let mut fired = 0usize;
    for rule in rules {
        match evaluate_rule(pool, cfg, &rule).await {
            Ok(true) => fired += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(event_type = "rule_eval_failed", rule_id = rule.id, error = %e, "aggregate rule evaluation failed");
            }
        }
    }
    Ok(fired)
}

/// Evaluate a single rule and advance its state. Returns Ok(true) iff the rule
/// transitioned INTO `firing` on this evaluation (the alert edge).
async fn evaluate_rule(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Result<bool> {
    let Some(op) = Op::parse(&rule.operator) else {
        return Ok(false); // unknown operator: never matches.
    };

    // Source the reading from the summed member set, a flow bucket, or a single
    // interface. Every path returns None for no/stale/invalid data (which must
    // not advance state) — for `sum`, ANY stale/invalid member blocks the rule.
    let obs = if rule.metric_aggregation == "sum" {
        aggregate_observation(pool, cfg, rule).await?
    } else if is_flow_metric(&rule.metric) {
        flow_observation(pool, cfg, rule).await?
    } else {
        interface_observation(pool, cfg, rule).await?
    };
    let Some(obs) = obs else { return Ok(false) };
    let value = obs.value;
    let sampled_at = obs.sampled_at;
    let matched = op.compare(value, rule.threshold_value);

    // Load prior state.
    let prev = sqlx::query_as::<_, RuleStateRow>(
        "SELECT current_state, first_matched_at, recovery_first_at, \
                recovery_consecutive, consecutive_match_count \
         FROM rule_states WHERE rule_id = ?",
    )
    .bind(rule.id)
    .fetch_optional(pool)
    .await?
    .unwrap_or_default();

    let prev_state = prev.current_state.as_deref().unwrap_or("clear");
    let now = Utc::now();

    if matched {
        let consecutive = prev.consecutive_match_count.saturating_add(1);
        // first_matched_at is the start of the current matching streak.
        let first_matched = prev.first_matched_at.unwrap_or(now);
        let held_secs = (now - first_matched).num_seconds();

        // Persistence: each control is OPT-IN (0 = disabled). The rule fires only
        // when EVERY enabled control is satisfied; with none set it fires on the
        // first match. Flow rules use the time window; SNMP rules use consecutive
        // samples (each poll is a fresh sample) — see docs/detection-engine.md.
        let should_fire = persistence_satisfied(
            rule.duration_seconds,
            held_secs,
            rule.consecutive_samples,
            consecutive,
        );

        if should_fire && prev_state != "firing" {
            // Rising edge: fire. Reset any prior recovery progress.
            upsert_state(
                pool,
                rule.id,
                "firing",
                Some(first_matched),
                sampled_at,
                consecutive,
                value,
            )
            .await?;
            set_recovery_progress(pool, rule.id, None, 0).await?;
            if let Err(e) = on_fire(
                pool,
                cfg,
                rule,
                value,
                sampled_at,
                obs.low_confidence,
                obs.source_corroborated,
            )
            .await
            {
                // No action is attempted until the durable fired event exists. Put
                // the rule back into matching so the next evaluation retries the
                // firing edge instead of silently losing it forever.
                upsert_state(
                    pool,
                    rule.id,
                    "matching",
                    Some(first_matched),
                    sampled_at,
                    consecutive,
                    value,
                )
                .await?;
                return Err(e);
            }
            return Ok(true);
        } else if should_fire {
            // Already firing and the firing condition still holds: keep firing,
            // refresh activity (no new alert), and cancel any recovery progress.
            upsert_state(
                pool,
                rule.id,
                "firing",
                Some(first_matched),
                sampled_at,
                consecutive,
                value,
            )
            .await?;
            set_recovery_progress(pool, rule.id, None, 0).await?;
            return Ok(false);
        } else {
            // Matching but persistence not yet met.
            if prev_state == "clear" {
                if let Err(e) = record_event(pool, rule, "matched", value, sampled_at).await {
                    tracing::warn!(event_type = "rule_match_event_write_failed", rule_id = rule.id, error = %e, "could not persist the start of a matching streak");
                }
            }
            upsert_state(
                pool,
                rule.id,
                "matching",
                Some(first_matched),
                sampled_at,
                consecutive,
                value,
            )
            .await?;
            return Ok(false);
        }
    }

    // Firing condition not matched this tick. Recovery clears the rule per its
    // recovery_mode (docs/detection-engine.md):
    //   manual    — never auto-clears.
    //   auto      — recover after the SAME persistence used to fire (consecutive
    //               samples for SNMP, time window for flow), staying on the
    //               recovered side of the FIRE threshold. No extra config.
    //   threshold — recover when the metric crosses a recovery_threshold_value
    //               (hysteresis band) and holds for an optional recovery
    //               persistence override (else the firing persistence).
    if prev_state == "firing" {
        if rule.recovery_mode == "manual" {
            return Ok(false);
        }

        let is_threshold = rule.recovery_mode == "threshold";
        // Is the metric on the recovered side this tick? For auto we are already
        // in the not-matched branch (fire condition false ⇒ recovered). For
        // threshold the recovered side is past the (possibly lower) recovery band.
        let recovered_now = if is_threshold {
            let rec_threshold = rule
                .recovery_threshold_value
                .unwrap_or(rule.threshold_value);
            op.recovered(value, rec_threshold)
        } else {
            true
        };
        if !recovered_now {
            // Threshold band: below fire threshold but not yet recovered. Hold
            // firing and reset recovery progress.
            set_recovery_progress(pool, rule.id, None, 0).await?;
            return Ok(false);
        }

        let is_flow = is_flow_metric(&rule.metric);
        if is_flow {
            // Time-window recovery (mirrors the firing window).
            let target_secs = if is_threshold {
                rule.recovery_window_seconds
            } else {
                None
            }
            .map(|s| s as i64)
            .unwrap_or(rule.duration_seconds as i64);
            let rec_first = prev.recovery_first_at.unwrap_or(now);
            if target_secs == 0 || (now - rec_first).num_seconds() >= target_secs {
                recover_and_clear(pool, cfg, rule, value, sampled_at).await?;
            } else {
                set_recovery_progress(pool, rule.id, Some(rec_first), prev.recovery_consecutive)
                    .await?;
            }
            return Ok(false);
        } else {
            // Consecutive-sample recovery (mirrors the firing sample count).
            let target_samples = if is_threshold {
                rule.recovery_consecutive_samples
            } else {
                None
            }
            .unwrap_or(rule.consecutive_samples)
            .max(1);
            let rec_consec = prev.recovery_consecutive.saturating_add(1);
            if rec_consec >= target_samples {
                recover_and_clear(pool, cfg, rule, value, sampled_at).await?;
            } else {
                set_recovery_progress(pool, rule.id, None, rec_consec).await?;
            }
            return Ok(false);
        }
    }

    // Was matching but the condition dropped before firing, or already clear.
    if prev_state == "matching" {
        clear_state(pool, rule.id, value).await?;
    } else {
        // Keep last_evaluated_at fresh.
        upsert_state(pool, rule.id, "clear", None, sampled_at, 0, value).await?;
    }
    Ok(false)
}

/// Read an SNMP interface metric from `interface_metrics_current`. None for a
/// missing / invalid / stale sample, or an unknown metric name.
async fn interface_observation(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
) -> Result<Option<Observation>> {
    let Some(interface_id) = rule.interface_id else {
        return Ok(None); // single-interface observation needs a target interface.
    };
    let metrics = sqlx::query_as::<_, CurrentMetrics>(
        "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
                rx_util_percent, tx_util_percent, in_err_rate, out_err_rate, oper_status \
         FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(interface_id)
    .fetch_optional(pool)
    .await?;

    let Some(metrics) = metrics else {
        return Ok(None);
    };
    if !metrics.valid_sample {
        return Ok(None);
    }
    let stale_after = cfg.telemetry.stale_after_seconds as i64;
    match metrics.sampled_at {
        Some(ts) if (Utc::now() - ts).num_seconds() <= stale_after => {}
        _ => return Ok(None),
    }
    let Some(value) = metrics.value(&rule.metric) else {
        return Ok(None);
    };
    Ok(Some(Observation {
        value,
        sampled_at: metrics.sampled_at,
        low_confidence: false,
        source_corroborated: true,
    }))
}

/// Sum an interface metric across a `sum` rule's member interfaces (possibly on
/// different devices). Conservative: EVERY member must have a valid, fresh sample
/// — if any is missing / invalid / stale, the whole observation is None (the rule
/// neither fires nor advances on partial data; doctrine "low confidence blocks").
/// Only `SUMMABLE_METRICS` are summed; anything else yields None.
async fn aggregate_observation(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
) -> Result<Option<Observation>> {
    if !SUMMABLE_METRICS.contains(&rule.metric.as_str()) {
        return Ok(None);
    }
    let members =
        sqlx::query_scalar::<_, u64>("SELECT interface_id FROM rule_interfaces WHERE rule_id = ?")
            .bind(rule.id)
            .fetch_all(pool)
            .await?;
    if members.is_empty() {
        return Ok(None);
    }

    let stale_after = cfg.telemetry.stale_after_seconds as i64;
    let mut total = 0f64;
    let mut newest: Option<Ts> = None;
    for interface_id in members {
        let m = sqlx::query_as::<_, CurrentMetrics>(
            "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
                    rx_util_percent, tx_util_percent, in_err_rate, out_err_rate, oper_status \
             FROM interface_metrics_current WHERE interface_id = ?",
        )
        .bind(interface_id)
        .fetch_optional(pool)
        .await?;
        // Any missing / invalid / stale member blocks the whole sum.
        let Some(m) = m else { return Ok(None) };
        if !m.valid_sample {
            return Ok(None);
        }
        match m.sampled_at {
            Some(ts) if (Utc::now() - ts).num_seconds() <= stale_after => {
                if newest.map(|n| ts > n).unwrap_or(true) {
                    newest = Some(ts);
                }
            }
            _ => return Ok(None),
        }
        let Some(v) = m.value(&rule.metric) else {
            return Ok(None);
        };
        total += v;
    }

    Ok(Some(Observation {
        value: total,
        sampled_at: newest,
        low_confidence: false,
        source_corroborated: true,
    }))
}

/// Read a flow-derived metric (flow_pps / flow_bps) from the latest CLOSED
/// interface bucket, optionally narrowed by the rule's protocol/port selector.
/// Counts are sampling-scaled (estimated). None when there is no fresh interface
/// flow data. A selector absent from the latest bucket is a current zero, not a
/// stale value from the last bucket in which that selector happened to appear.
/// `low_confidence` is set when the sampling rate behind the estimate is
/// unverified.
async fn flow_observation(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
) -> Result<Option<Observation>> {
    // The current schema has no protocol-only bucket. Silently ignoring this
    // selector would evaluate a broader condition than the operator configured.
    if rule.flow_protocol.is_some() && rule.flow_port.is_none() {
        tracing::warn!(
            event_type = "flow_rule_selector_unsupported",
            rule_id = rule.id,
            "protocol-only flow selector cannot be evaluated without a port bucket"
        );
        return Ok(None);
    }
    let bucket_secs = cfg.flow.bucket_seconds.max(1) as f64;
    let direction = rule.flow_direction.as_deref().unwrap_or("ingress");

    // Match flow buckets by (device_id, if_index), NOT by the bucket's
    // interface_id FK. if_index/device_id are always populated on a bucket;
    // interface_id can be NULL when the exporter's ifIndex wasn't mapped to an
    // enrolled row, which would make a flow condition silently never match. We
    // resolve the rule's interface to its (device_id, if_index) and scope on that.
    let resolved: Option<(u64, u32)> =
        sqlx::query_as("SELECT device_id, if_index FROM device_interfaces WHERE id = ?")
            .bind(rule.interface_id)
            .fetch_optional(pool)
            .await?;
    let Some((dev_id, if_index)) = resolved else {
        return Ok(None); // interface no longer exists
    };

    // Anchor every selector to the latest complete interface bucket. Looking up
    // MAX() in the selector table itself would preserve an old non-zero value
    // after that port disappears, and historically forced a multi-million-row
    // scan when no matching composite index existed.
    let bucket_ts: Option<Ts> = sqlx::query_scalar(
        "SELECT MAX(bucket_ts) FROM flow_iface_buckets \
         WHERE device_id = ? AND if_index = ? AND direction = ?",
    )
    .bind(dev_id)
    .bind(if_index)
    .bind(direction)
    .fetch_one(pool)
    .await?;
    let Some(bucket_ts) = bucket_ts else {
        return Ok(None);
    };

    // Flow buckets lag (bucket close + flush), so allow a wider staleness window
    // than the SNMP path — a few bucket widths.
    let flow_stale =
        (cfg.flow.bucket_seconds as i64 * 3).max(cfg.telemetry.stale_after_seconds as i64);
    if (Utc::now() - bucket_ts).num_seconds() > flow_stale {
        return Ok(None);
    }

    // (est_pkts, est_bytes, low-confidence flag). Aggregates return NULL when a
    // selector has no row in this bucket; its current value is then zero and its
    // confidence remains low, so absence can clear stale state but never act.
    type Agg = (Option<u64>, Option<u64>, Option<u64>);
    let agg = "CAST(SUM(pkts * effective_sampling_rate) AS UNSIGNED), \
               CAST(SUM(bytes * effective_sampling_rate) AS UNSIGNED), \
               CAST(MAX(sampling_confidence = 'low') AS UNSIGNED)";

    let row: Agg = if let Some(port) = rule.flow_port {
        let port_kind = rule.flow_port_kind.as_deref().unwrap_or("dst");
        if let Some(protocol) = rule.flow_protocol {
            sqlx::query_as(&format!(
                "SELECT {agg} FROM flow_port_buckets \
                 WHERE device_id = ? AND if_index = ? AND direction = ? AND bucket_ts = ? \
                   AND port_kind = ? AND port = ? AND protocol = ?"
            ))
            .bind(dev_id)
            .bind(if_index)
            .bind(direction)
            .bind(bucket_ts)
            .bind(port_kind)
            .bind(port)
            .bind(protocol)
            .fetch_one(pool)
            .await?
        } else {
            sqlx::query_as(&format!(
                "SELECT {agg} FROM flow_port_buckets \
                 WHERE device_id = ? AND if_index = ? AND direction = ? AND bucket_ts = ? \
                   AND port_kind = ? AND port = ?"
            ))
            .bind(dev_id)
            .bind(if_index)
            .bind(direction)
            .bind(bucket_ts)
            .bind(port_kind)
            .bind(port)
            .fetch_one(pool)
            .await?
        }
    } else {
        sqlx::query_as(&format!(
            "SELECT {agg} FROM flow_iface_buckets \
             WHERE device_id = ? AND if_index = ? AND direction = ? AND bucket_ts = ?"
        ))
        .bind(dev_id)
        .bind(if_index)
        .bind(direction)
        .bind(bucket_ts)
        .fetch_one(pool)
        .await?
    };

    let (est_pkts, est_bytes, low_conf) = row;

    let value = match rule.metric.as_str() {
        "flow_pps" => est_pkts.unwrap_or(0) as f64 / bucket_secs,
        "flow_bps" => est_bytes.unwrap_or(0) as f64 * 8.0 / bucket_secs,
        _ => return Ok(None),
    };
    let source_corroborated = flow_matches_snmp(pool, cfg, rule, value, bucket_ts).await?;
    // Unknown sampling confidence or absent/divergent SNMP corroboration is
    // treated as low: alerts still fire, but unauthenticated UDP cannot act alone.
    Ok(Some(Observation {
        value,
        sampled_at: Some(bucket_ts),
        low_confidence: low_conf.unwrap_or(1) != 0 || !source_corroborated,
        source_corroborated,
    }))
}

async fn flow_matches_snmp(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    flow_value: f64,
    bucket_ts: Ts,
) -> Result<bool> {
    let Some(interface_id) = rule.interface_id else {
        return Ok(false);
    };
    let row = sqlx::query_as::<_, (Option<Ts>, bool, f64, f64, f64, f64)>(
        "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps \
         FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(interface_id)
    .fetch_optional(pool)
    .await?;
    let Some((sampled_at, valid, rx_bps, tx_bps, rx_pps, tx_pps)) = row else {
        return Ok(false);
    };
    let Some(sampled_at) = sampled_at else {
        return Ok(false);
    };
    if !valid || (Utc::now() - sampled_at).num_seconds() > cfg.telemetry.stale_after_seconds as i64
    {
        return Ok(false);
    }
    let max_skew =
        (cfg.flow.bucket_seconds as i64 * 2).max(cfg.telemetry.stale_after_seconds as i64);
    if (sampled_at - bucket_ts).num_seconds().unsigned_abs() > max_skew as u64 {
        return Ok(false);
    }
    let ingress = rule.flow_direction.as_deref().unwrap_or("ingress") == "ingress";
    let snmp_value = match (rule.metric.as_str(), ingress) {
        ("flow_pps", true) => rx_pps,
        ("flow_pps", false) => tx_pps,
        ("flow_bps", true) => rx_bps,
        ("flow_bps", false) => tx_bps,
        _ => return Ok(false),
    };
    if !flow_value.is_finite() || !snmp_value.is_finite() || flow_value < 0.0 || snmp_value <= 0.0 {
        return Ok(false);
    }
    let ratio = flow_value / snmp_value;
    let under_ceiling = ratio <= cfg.flow.snmp_corroboration_max_ratio;
    let whole_interface = rule.flow_port.is_none() && rule.flow_protocol.is_none();
    let above_floor = !whole_interface || ratio >= cfg.flow.snmp_corroboration_min_ratio;
    Ok(under_ceiling && above_floor)
}

/// Pure decision: should a fired rule's actions auto-execute? Requires enforce
/// mode AND the global automatic master switch AND the rule's own auto switch,
/// and NEVER on a low-confidence (unverified-sampling) reading. This is the
/// doctrine "global and per-rule" gate; the executor re-checks it as defence in
/// depth. Unit-tested below.
fn should_auto_execute(
    mode_is_enforce: bool,
    global_automatic_enabled: bool,
    rule_automatic_enabled: bool,
    low_confidence: bool,
) -> bool {
    mode_is_enforce && global_automatic_enabled && rule_automatic_enabled && !low_confidence
}

fn persistence_satisfied(
    duration_seconds: u32,
    held_seconds: i64,
    consecutive_samples: u32,
    consecutive_matches: u32,
) -> bool {
    (duration_seconds == 0 || held_seconds >= duration_seconds as i64)
        && (consecutive_samples == 0 || consecutive_matches >= consecutive_samples)
}

/// On the firing edge: record the rule_event and enqueue the alert. In observe
/// mode (and always, since execution is gated elsewhere) the alert carries the
/// would-run plan instead of any reroute.
async fn on_fire(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
    low_confidence: bool,
    source_corroborated: bool,
) -> Result<()> {
    let mode = crate::api::settings::operating_mode(pool, cfg).await;

    // Direction phrasing for the alert body.
    let direction = match Op::parse(&rule.operator) {
        Some(Op::Lt) | Some(Op::Le) => "below",
        _ => "above",
    };

    let interface_label = match rule.interface_id {
        Some(id) => interface_label(pool, id).await,
        None => aggregate_label(pool, rule.id).await,
    };

    let mut payload = json!({
        "rule_id": rule.id,
        "rule_name": rule.name,
        "metric": rule.metric,
        "operator": rule.operator,
        "threshold_value": rule.threshold_value,
        "observed_value": value,
        "direction": direction,
        "interface_id": rule.interface_id,
        "interface": interface_label,
        "device_id": rule.device_id,
        "operating_mode": mode,
        "severity": rule.severity,
    });

    // For a flow rule, surface the selector + that the value is a sampled estimate.
    if is_flow_metric(&rule.metric) {
        payload["flow_selector"] = json!({
            "flow_direction": rule.flow_direction,
            "flow_protocol": rule.flow_protocol,
            "flow_port": rule.flow_port,
            "flow_port_kind": rule.flow_port_kind,
        });
        payload["flow_estimated"] = json!(true);
        payload["automatic_confidence_low"] = json!(low_confidence);
        payload["snmp_source_corroborated"] = json!(source_corroborated);
    }

    // "The rule decides", but only within the GLOBAL gates. Automatic execution
    // requires enforce mode AND the global master switch (automatic_actions_enabled)
    // AND the rule's own auto switch, and never on a low-confidence (unverified
    // sampling) reading. Otherwise — observe mode, global switch off, a manual-only
    // rule, or low confidence — we only RENDER the would-run plan. The runtime
    // global value lives in system_settings; config is the startup fallback.
    let global_auto = crate::api::settings::bool_setting(
        pool,
        "automatic_actions_enabled",
        cfg.safety.automatic_actions_enabled,
    )
    .await;
    // Surface low-confidence suppression only when it is the deciding blocker
    // (everything else that would permit auto-execution is satisfied).
    if low_confidence && mode == "enforce" && global_auto && rule.automatic_reroute_enabled {
        payload["auto_suppressed_low_confidence"] = json!(true);
        tracing::warn!(
            event_type = "rule_auto_suppressed",
            rule_id = rule.id,
            "flow rule fired but auto-action suppressed: sampling/source confidence is low"
        );
    }
    let flow_auto_gate = !is_flow_metric(&rule.metric)
        || (cfg.flow.automatic_actions_enabled && cfg.flow.allowlist_enrolled_only);
    if is_flow_metric(&rule.metric) && !flow_auto_gate {
        payload["auto_suppressed_flow_source_policy"] = json!(true);
    }
    let auto = flow_auto_gate
        && should_auto_execute(
            mode == "enforce",
            global_auto,
            rule.automatic_reroute_enabled,
            low_confidence,
        );
    let would_run_actions = render_would_run_actions(pool, rule).await?;
    if !would_run_actions.is_empty() {
        payload["would_run_actions"] = json!(would_run_actions);
    }
    if auto {
        payload["automatic_execution_planned"] = json!(true);
    }

    let dedup_key = match rule.interface_id {
        Some(id) => format!("rule_fired:rule:{}:iface:{}", rule.id, id),
        None => format!("rule_fired:rule:{}:agg", rule.id),
    };
    // Persist the firing edge and its alert atomically BEFORE any SSH side
    // effect. If this transaction fails, evaluate_rule returns to `matching` and
    // retries later. Once it commits, a crash can at worst omit the automatic
    // action; it can never leave an unalerted action that is retried blindly.
    let mut tx = pool.begin().await?;
    let event = sqlx::query(
        "INSERT INTO rule_events (rule_id, event, metric_value, sampled_at) \
         VALUES (?, 'fired', ?, ?)",
    )
    .bind(rule.id)
    .bind(value)
    .bind(sampled_at)
    .execute(&mut *tx)
    .await?;
    let rule_event_id = event.last_insert_id();
    let alert = sqlx::query(
        "INSERT INTO alerts (event_type, severity, device_id, interface_id, rule_id, payload_json, dedup_key) \
         VALUES ('rule_fired', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rule.severity)
    .bind(rule.device_id)
    .bind(rule.interface_id)
    .bind(rule.id)
    .bind(sqlx::types::Json(&payload))
    .bind(&dedup_key)
    .execute(&mut *tx)
    .await?;
    let alert_id = alert.last_insert_id();
    tx.commit().await?;

    if auto {
        match auto_execute_actions(pool, cfg, rule, rule_event_id).await {
            Ok(executed) => {
                if !executed.is_empty() {
                    payload["executed_actions"] = json!(executed);
                }
                payload["automatic_execution_completed"] = json!(true);
            }
            Err(e) => {
                payload["automatic_execution_completed"] = json!(false);
                payload["automatic_execution_error"] = json!(e.to_string());
                tracing::error!(event_type = "automatic_action_failed", rule_id = rule.id, rule_event_id, error = %e, "automatic action preparation failed after the firing alert was committed; no untracked retry will be attempted");
                let failure_payload = json!({
                    "rule_id": rule.id,
                    "rule_event_id": rule_event_id,
                    "rule_name": rule.name,
                    "reason": e.to_string(),
                    "side_effect_attempted": false,
                });
                if let Err(alert_err) = sqlx::query(
                    "INSERT INTO alerts (event_type, severity, rule_id, payload_json, dedup_key) \
                     VALUES ('automatic_action_failed', 'critical', ?, ?, ?)",
                )
                .bind(rule.id)
                .bind(sqlx::types::Json(&failure_payload))
                .bind(format!(
                    "automatic_action_failed:rule_event:{rule_event_id}"
                ))
                .execute(pool)
                .await
                {
                    tracing::error!(event_type = "automatic_action_failure_alert_write_failed", rule_id = rule.id, rule_event_id, error = %alert_err, "could not enqueue the automatic-action failure alert");
                }
            }
        }
        if let Err(e) = sqlx::query("UPDATE alerts SET payload_json = ? WHERE id = ?")
            .bind(sqlx::types::Json(&payload))
            .bind(alert_id)
            .execute(pool)
            .await
        {
            tracing::error!(event_type = "rule_alert_outcome_update_failed", rule_id = rule.id, rule_event_id, alert_id, error = %e, "automatic action finished but the firing alert could not be enriched; reroute lifecycle alerts remain durable");
        }
    }

    tracing::info!(
        event_type = "rule_fired",
        rule_id = rule.id,
        interface_id = ?rule.interface_id,
        metric = %rule.metric,
        observed = value,
        threshold = rule.threshold_value,
        mode = %mode,
        "detection rule fired (observe-safe: no reroute executed)"
    );
    Ok(())
}

/// The flow selector for auto-target resolution, taken from the rule.
fn flow_selector(rule: &InterfaceRule) -> FlowSelector {
    FlowSelector {
        interface_id: rule.interface_id,
        direction: rule.flow_direction.clone(),
        protocol: rule.flow_protocol,
        port: rule.flow_port,
        port_kind: rule.flow_port_kind.clone(),
    }
}

/// Render every attached action of a rule (template + target router + params) to
/// its exact would-run commands, for the alert payload. Best-effort and
/// observe-safe: it resolves auto-target hosts, loads templates, and renders
/// strings; it executes nothing. An auto-target action that resolves shows the
/// concrete /32 or /128 in `auto_target.resolved_cidr`; one that cannot resolve
/// (no in-prefix victim, no flows, …) shows `skipped` instead of commands.
async fn render_would_run_actions(pool: &MySqlPool, rule: &InterfaceRule) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<
        _,
        (u64, u64, u64, String, Option<sqlx::types::Json<Value>>, Option<String>),
    >(
        "SELECT ra.id, ra.reroute_template_id, ra.device_id, d.name, ra.params_json, ra.auto_target \
         FROM rule_actions ra \
         JOIN devices d ON d.id = ra.device_id \
         WHERE ra.rule_id = ? AND ra.enabled = 1 \
         ORDER BY ra.position, ra.id",
    )
    .bind(rule.id)
    .fetch_all(pool)
    .await?;

    let sel = flow_selector(rule);
    let mut out = Vec::with_capacity(rows.len());
    for (action_id, template_id, device_id, device_name, params_json, auto_target) in rows {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        match flow_target::prepare_action(
            pool,
            &sel,
            template_id,
            device_id,
            params.clone(),
            auto_target.as_deref(),
        )
        .await
        {
            PreparedAction::Ready {
                template,
                params: rparams,
                auto_target: at,
            } => {
                let rendered = match crate::reroute::templates::render(&template, &rparams) {
                    Ok(plan) => json!({ "commands": plan.commands, "verify": plan.verify }),
                    Err(e) => json!({ "error": e.to_string() }),
                };
                // The undo command set (if the template has a paired rollback), so
                // the alert shows how to reverse this mitigation by hand. `null`
                // when there is no rollback template.
                let rollback =
                    crate::reroute::rollback::render_rollback_plan(pool, template.id, &rparams)
                        .await
                        .map(|p| json!({ "commands": p.commands }));
                let mut v = json!({
                    "action_id": action_id,
                    "template_id": template.id,
                    "template_name": template.name,
                    "template_display_name": template.display_name,
                    "device_id": device_id,
                    "device_name": device_name,
                    "params": rparams,
                    "rendered": rendered,
                    "rollback": rollback,
                });
                if let Some(at) = at {
                    v["auto_target"] = json!({
                        "kind": flow_target::FLOW_DST_HOST,
                        "resolved_cidr": at.cidr,
                        "low_confidence": at.low_confidence,
                        "note": at.note,
                    });
                }
                out.push(v);
            }
            PreparedAction::Skip { reason } => {
                let mut v = json!({
                    "action_id": action_id,
                    "template_id": template_id,
                    "device_id": device_id,
                    "device_name": device_name,
                    "params": params,
                    "skipped": reason,
                });
                if auto_target.is_some() {
                    v["auto_target"] =
                        json!({ "kind": flow_target::FLOW_DST_HOST, "unresolved": true });
                }
                out.push(v);
            }
        }
    }
    Ok(out)
}

/// Execute every attached action of a rule via the reroute executor. Called only
/// on the firing edge, only in enforce mode, only when the rule's auto switch is
/// on. The executor re-checks Gate 0 + device locks/cooldowns/uncertain, so a
/// device that's locked or recently acted on is safely skipped. Auto-target
/// actions resolve their host from current flows first; a LOW-confidence
/// resolution is SUPPRESSED for automatic execution (doctrine) — the alert still
/// shows the would-run target. Returns each action's outcome for the alert payload.
async fn auto_execute_actions(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    rule_event_id: u64,
) -> Result<Vec<Value>> {
    let specs = sqlx::query_as::<_, (u64, u64, Option<sqlx::types::Json<Value>>, Option<String>)>(
        "SELECT reroute_template_id, device_id, params_json, auto_target FROM rule_actions \
         WHERE rule_id = ? AND enabled = 1 ORDER BY position, id",
    )
    .bind(rule.id)
    .fetch_all(pool)
    .await?;

    let sel = flow_selector(rule);
    let mut out = Vec::with_capacity(specs.len());
    let mut acted_devices = Vec::new();
    for (template_id, device_id, params_json, auto_target) in specs {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        match flow_target::prepare_action(
            pool,
            &sel,
            template_id,
            device_id,
            params,
            auto_target.as_deref(),
        )
        .await
        {
            PreparedAction::Ready {
                template,
                params,
                auto_target: at,
            } => {
                // Doctrine: LOW flow-sampling confidence blocks AUTOMATIC execution.
                if at.as_ref().is_some_and(|a| a.low_confidence) {
                    tracing::warn!(
                        event_type = "auto_target_suppressed",
                        rule_id = rule.id,
                        device_id,
                        "auto-target suppressed: low flow sampling confidence"
                    );
                    out.push(json!({
                        "device_id": device_id,
                        "executed": false,
                        "skipped": "auto-target suppressed: LOW flow sampling confidence",
                        "auto_target": at.map(|a| a.cidr),
                    }));
                    continue;
                }
                let reason = match &at {
                    Some(a) => format!("automatic: rule '{}' fired; {}", rule.name, a.note),
                    None => format!("automatic: rule '{}' fired", rule.name),
                };
                let req = crate::reroute::executor::ActionRequest {
                    device_id,
                    template,
                    params,
                    trigger_type: "automatic",
                    rule_id: Some(rule.id),
                    rule_event_id: Some(rule_event_id),
                    rollback_of_reroute_id: None,
                    user_id: None,
                    actor_context: None,
                    reason: Some(reason),
                    defer_cooldown: true,
                };
                let outcome = crate::reroute::executor::execute(pool, cfg, req, false).await;
                if outcome.executed {
                    acted_devices.push(outcome.device_id);
                }
                let mut v = serde_json::to_value(&outcome).unwrap_or(Value::Null);
                if let (Value::Object(m), Some(a)) = (&mut v, at) {
                    m.insert("auto_target".into(), json!(a.cidr));
                }
                out.push(v);
            }
            PreparedAction::Skip { reason } => {
                tracing::warn!(
                    event_type = "auto_target_skipped",
                    rule_id = rule.id,
                    device_id,
                    reason = %reason,
                    "auto action skipped (auto-target unresolved)"
                );
                out.push(json!({ "device_id": device_id, "executed": false, "skipped": reason }));
            }
        }
    }
    if let Err(e) =
        crate::reroute::executor::record_cooldowns(pool, cfg, Some(rule.id), &acted_devices).await
    {
        tracing::error!(event_type = "rule_cooldown_persist_failed", rule_id = rule.id, error = %e, "could not persist rule action cooldowns; reroute history remains the fallback gate");
    }
    Ok(out)
}

/// A short human label for an interface ("ifName on device").
async fn interface_label(pool: &MySqlPool, interface_id: u64) -> String {
    let row = sqlx::query_as::<_, (Option<String>, Option<String>, String)>(
        "SELECT di.if_name, di.if_descr, d.name FROM device_interfaces di \
         JOIN devices d ON d.id = di.device_id WHERE di.id = ?",
    )
    .bind(interface_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    match row {
        Some((if_name, if_descr, device)) => {
            let iface = if_name
                .or(if_descr)
                .unwrap_or_else(|| format!("if#{interface_id}"));
            format!("{iface} on {device}")
        }
        None => format!("interface #{interface_id}"),
    }
}

/// A short label for a `sum` rule's member set, e.g. "3 interfaces across 2 devices".
async fn aggregate_label(pool: &MySqlPool, rule_id: u64) -> String {
    let row = sqlx::query_as::<_, (i64, i64)>(
        "SELECT COUNT(*), COUNT(DISTINCT device_id) FROM rule_interfaces WHERE rule_id = ?",
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    match row {
        Some((ifaces, devices)) if ifaces > 0 => {
            format!(
                "{ifaces} interface{} across {devices} device{}",
                if ifaces == 1 { "" } else { "s" },
                if devices == 1 { "" } else { "s" }
            )
        }
        _ => "interface group".to_string(),
    }
}

/// Insert a rule_events row for the rule's timeline (matched / fired / cleared).
async fn record_event(
    pool: &MySqlPool,
    rule: &InterfaceRule,
    event: &str,
    value: f64,
    sampled_at: Option<Ts>,
) -> Result<u64> {
    let res = sqlx::query(
        "INSERT INTO rule_events (rule_id, event, metric_value, sampled_at) VALUES (?, ?, ?, ?)",
    )
    .bind(rule.id)
    .bind(event)
    .bind(value)
    .bind(sampled_at)
    .execute(pool)
    .await?;
    Ok(res.last_insert_id())
}

/// Upsert rule_states to a given state, advancing the streak counters.
async fn upsert_state(
    pool: &MySqlPool,
    rule_id: u64,
    state: &str,
    first_matched_at: Option<Ts>,
    sampled_at: Option<Ts>,
    consecutive: u32,
    value: f64,
) -> Result<()> {
    let _ = sampled_at;
    sqlx::query(
        "INSERT INTO rule_states \
            (rule_id, current_state, first_matched_at, last_matched_at, consecutive_match_count, \
             last_metric_value, last_evaluated_at) \
         VALUES (?, ?, ?, UTC_TIMESTAMP(), ?, ?, UTC_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE \
            current_state = VALUES(current_state), \
            first_matched_at = VALUES(first_matched_at), \
            last_matched_at = VALUES(last_matched_at), \
            consecutive_match_count = VALUES(consecutive_match_count), \
            last_metric_value = VALUES(last_metric_value), \
            last_evaluated_at = VALUES(last_evaluated_at)",
    )
    .bind(rule_id)
    .bind(state)
    .bind(first_matched_at)
    .bind(consecutive)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Reset a rule's state to clear, stamping last_cleared_at and zeroing the streak.
async fn clear_state(pool: &MySqlPool, rule_id: u64, value: f64) -> Result<()> {
    sqlx::query(
        "INSERT INTO rule_states \
            (rule_id, current_state, consecutive_match_count, last_metric_value, \
             last_cleared_at, last_evaluated_at) \
         VALUES (?, 'clear', 0, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE \
            current_state = 'clear', first_matched_at = NULL, recovery_first_at = NULL, \
            recovery_consecutive = 0, consecutive_match_count = 0, \
            last_metric_value = VALUES(last_metric_value), last_cleared_at = UTC_TIMESTAMP(), \
            last_evaluated_at = UTC_TIMESTAMP()",
    )
    .bind(rule_id)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update recovery progress: the hold start (flow window) and the recovered-side
/// streak (SNMP samples). Assumes a rule_states row exists (true once firing).
async fn set_recovery_progress(
    pool: &MySqlPool,
    rule_id: u64,
    first_at: Option<Ts>,
    consecutive: u32,
) -> Result<()> {
    sqlx::query(
        "UPDATE rule_states SET recovery_first_at = ?, recovery_consecutive = ?, \
                last_evaluated_at = UTC_TIMESTAMP() WHERE rule_id = ?",
    )
    .bind(first_at)
    .bind(consecutive)
    .bind(rule_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Recovery edge. A rule stays firing until every automatic reroute created by
/// this exact firing edge has either no rollback or a verified successful one.
async fn recover_and_clear(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
) -> Result<()> {
    if !run_recovery_rollback(pool, cfg, rule.id, &rule.name, None, None).await? {
        tracing::warn!(
            event_type = "rule_recovery_pending",
            rule_id = rule.id,
            "rule remains firing until its automatic mitigations are verified rolled back"
        );
        return Ok(());
    }
    clear_state(pool, rule.id, value).await?;
    record_event(pool, rule, "cleared", value, sampled_at).await?;
    Ok(())
}

/// Roll back successful automatic reroutes from the latest firing event, in
/// reverse execution order. Uses each reroute's persisted resolved parameters,
/// never the rule's mutable action definition. Returns false while any corrective
/// action is blocked, failed, or uncertain; the next evaluation retries it.
async fn run_recovery_rollback(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
    rule_name: &str,
    actor_user_id: Option<u64>,
    actor_context: Option<crate::reroute::executor::ActorContext>,
) -> Result<bool> {
    let firing: Option<(u64, Ts)> = sqlx::query_as(
        "SELECT id, created_at FROM rule_events \
         WHERE rule_id = ? AND event = 'fired' ORDER BY id DESC LIMIT 1",
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await?;
    let Some((rule_event_id, fired_at)) = firing else {
        return Ok(true);
    };

    type RecoveryRow = (u64, u64, u64, Option<sqlx::types::Json<Value>>);
    let specs = sqlx::query_as::<_, RecoveryRow>(
        "SELECT r.id, r.reroute_template_id, r.device_id, r.parameters_json \
         FROM reroutes r \
         WHERE r.rule_id = ? AND r.trigger_type = 'automatic' AND r.state = 'succeeded' \
           AND (r.rule_event_id = ? OR (r.rule_event_id IS NULL AND r.created_at >= ?)) \
           AND NOT EXISTS ( \
             SELECT 1 FROM reroutes rb \
             WHERE rb.rollback_of_reroute_id = r.id AND rb.state = 'succeeded' \
           ) \
         ORDER BY r.id DESC",
    )
    .bind(rule_id)
    .bind(rule_event_id)
    .bind(fired_at)
    .fetch_all(pool)
    .await?;

    if specs.is_empty() {
        return Ok(true);
    }
    if crate::api::settings::operating_mode(pool, cfg).await != "enforce" {
        return Ok(false);
    }

    let mut complete = true;
    let mut acted_devices = Vec::new();
    for (original_id, template_id, device_id, params_json) in specs {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        let reason =
            format!("recovery rollback of reroute #{original_id}: rule '{rule_name}' recovered");
        match crate::reroute::rollback::rollback_of(
            pool,
            cfg,
            crate::reroute::rollback::RollbackRequest {
                device_id,
                template_id,
                params: &params,
                original_reroute_id: Some(original_id),
                rule_event_id: Some(rule_event_id),
                user_id: actor_user_id,
                actor_context: actor_context.clone(),
                reason,
                defer_cooldown: true,
                dry_run: false,
            },
        )
        .await
        {
            Ok(Some(outcome)) => {
                if outcome.executed {
                    acted_devices.push(device_id);
                }
                if outcome.state.as_deref() == Some("succeeded") {
                    tracing::info!(
                        event_type = "rule_recovery_rollback_succeeded",
                        rule_id,
                        original_reroute_id = original_id,
                        rollback_reroute_id = ?outcome.reroute_id,
                        device_id,
                        template_id,
                        "verified rollback on recovery"
                    );
                } else {
                    complete = false;
                    tracing::warn!(
                        event_type = "rule_recovery_rollback_pending",
                        rule_id,
                        original_reroute_id = original_id,
                        device_id,
                        state = ?outcome.state,
                        blocked_reason = ?outcome.blocked_reason,
                        "rollback did not reach verified success; recovery will retry"
                    );
                }
            }
            Ok(None) => tracing::debug!(
                event_type = "rule_recovery_no_rollback",
                rule_id,
                original_reroute_id = original_id,
                template_id,
                "action template has no rollback; nothing to undo"
            ),
            Err(e) => {
                complete = false;
                tracing::error!(event_type = "rule_recovery_rollback_error", rule_id, original_reroute_id = original_id, error = %e, "could not prepare the recovery rollback; recovery remains pending");
            }
        }
    }
    if let Err(e) =
        crate::reroute::executor::record_cooldowns(pool, cfg, None, &acted_devices).await
    {
        tracing::error!(event_type = "recovery_cooldown_persist_failed", rule_id, error = %e, "could not persist recovery cooldown rows");
    }
    Ok(complete)
}

/// Reset a rule's evaluation state to clear (zeroing streaks + recovery), without
/// recording an event. Called when a rule is edited so its old match/firing
/// progress doesn't carry over against the new condition.
pub async fn reset_rule_state(pool: &MySqlPool, rule_id: u64) -> Result<()> {
    clear_state(pool, rule_id, 0.0).await
}

/// Operator-initiated clear of a firing rule (recovery_mode = manual, or any rule
/// an admin wants to reset). Returns true if a firing rule was cleared. Records a
/// `cleared` rule_event and — if the rule auto-executed mitigations — runs their
/// rollback (same gating as automatic recovery).
pub async fn clear_rule_manual(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
    actor_user_id: u64,
    actor_context: crate::reroute::executor::ActorContext,
) -> Result<bool> {
    let cur: Option<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT current_state FROM rule_states WHERE rule_id = ?",
    )
    .bind(rule_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    if cur.as_deref() != Some("firing") {
        return Ok(false);
    }
    let meta: Option<String> = sqlx::query_scalar("SELECT name FROM rules WHERE id = ?")
        .bind(rule_id)
        .fetch_optional(pool)
        .await?;
    let name = meta.unwrap_or_else(|| format!("#{rule_id}"));

    if !run_recovery_rollback(
        pool,
        cfg,
        rule_id,
        &name,
        Some(actor_user_id),
        Some(actor_context.clone()),
    )
    .await?
    {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO rule_states \
         (rule_id, current_state, consecutive_match_count, last_metric_value, \
          last_cleared_at, last_evaluated_at) \
         VALUES (?, 'clear', 0, 0, UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE current_state = 'clear', first_matched_at = NULL, \
          recovery_first_at = NULL, recovery_consecutive = 0, consecutive_match_count = 0, \
          last_metric_value = 0, last_cleared_at = UTC_TIMESTAMP(), \
          last_evaluated_at = UTC_TIMESTAMP()",
    )
    .bind(rule_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO rule_events (rule_id, event, metric_value, sampled_at) VALUES (?, 'cleared', NULL, NULL)")
        .bind(rule_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, entity_type, entity_id, message, \
          ip_address, user_agent) \
         VALUES ('user', ?, 'rule_cleared_manual', 'rule', ?, ?, ?, ?)",
    )
    .bind(actor_user_id)
    .bind(rule_id)
    .bind(format!(
        "manually cleared rule '{name}' after required rollback"
    ))
    .bind(&actor_context.ip_address)
    .bind(&actor_context.user_agent)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(
        event_type = "rule_cleared_manual",
        rule_id,
        "rule manually cleared by operator"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Timelike, Utc};

    use super::{flow_observation, persistence_satisfied, should_auto_execute, InterfaceRule};
    use crate::config::Config;

    // Args: (enforce_mode, global_switch, rule_switch, low_confidence) -> auto?
    // These mirror the doctrine acceptance gates for the auto-execution decision.

    #[test]
    fn observe_mode_never_auto_executes() {
        assert!(!should_auto_execute(false, true, true, false));
    }

    #[test]
    fn enforce_with_global_switch_off_never_auto_executes() {
        assert!(!should_auto_execute(true, false, true, false));
    }

    #[test]
    fn enforce_global_on_but_rule_off_does_not_auto_execute() {
        assert!(!should_auto_execute(true, true, false, false));
    }

    #[test]
    fn low_confidence_suppresses_even_when_all_switches_on() {
        assert!(!should_auto_execute(true, true, true, true));
    }

    #[test]
    fn all_gates_satisfied_auto_executes() {
        assert!(should_auto_execute(true, true, true, false));
    }

    #[test]
    fn persistence_requires_every_enabled_gate() {
        assert!(!persistence_satisfied(60, 59, 3, 3));
        assert!(!persistence_satisfied(60, 60, 3, 2));
        assert!(persistence_satisfied(60, 60, 3, 3));
    }

    #[test]
    fn zero_disables_each_persistence_gate() {
        assert!(persistence_satisfied(0, 0, 3, 3));
        assert!(persistence_satisfied(60, 60, 0, 0));
        assert!(persistence_satisfied(0, 0, 0, 0));
    }

    #[tokio::test]
    async fn port_selector_uses_latest_interface_bucket() {
        let Ok(url) = std::env::var("DATABASE_URL") else {
            return;
        };
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .expect("connect to DATABASE_URL");
        crate::db::migrate_test_schema(&pool)
            .await
            .expect("run migrations");

        let suffix = uuid::Uuid::new_v4();
        let name = format!("flow-{suffix}");
        let device_id =
            sqlx::query("INSERT INTO devices (name, hostname, enabled) VALUES (?, ?, 0)")
                .bind(&name)
                .bind(&name)
                .execute(&pool)
                .await
                .expect("insert test device")
                .last_insert_id();
        let interface_id =
            sqlx::query("INSERT INTO device_interfaces (device_id, if_index) VALUES (?, 42)")
                .bind(device_id)
                .execute(&pool)
                .await
                .expect("insert test interface")
                .last_insert_id();
        let exporter_id = sqlx::query(
            "INSERT INTO flow_exporters \
             (device_id, source_addr, observation_domain, version) VALUES (?, ?, 0, 9)",
        )
        .bind(device_id)
        .bind(&name)
        .execute(&pool)
        .await
        .expect("insert test exporter")
        .last_insert_id();

        let latest =
            Utc::now().with_nanosecond(0).expect("valid timestamp") - Duration::seconds(60);
        let older = latest - Duration::seconds(60);
        for bucket_ts in [older, latest] {
            sqlx::query(
                "INSERT INTO flow_iface_buckets \
                 (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, \
                  pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence) \
                 VALUES (?, ?, ?, 42, 'ingress', ?, 100, 10000, 1, 1, 'high')",
            )
            .bind(exporter_id)
            .bind(device_id)
            .bind(interface_id)
            .bind(bucket_ts)
            .execute(&pool)
            .await
            .expect("insert interface bucket");
        }
        sqlx::query(
            "INSERT INTO flow_port_buckets \
             (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, protocol, \
              port_kind, port, pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, 42, 'ingress', ?, 6, 'src', 443, 100, 10000, 1, 1, 'high')",
        )
        .bind(exporter_id)
        .bind(device_id)
        .bind(interface_id)
        .bind(older)
        .execute(&pool)
        .await
        .expect("insert old port bucket");

        let rule = InterfaceRule {
            id: 0,
            name: "latest port bucket test".into(),
            interface_id: Some(interface_id),
            device_id: Some(device_id),
            metric: "flow_pps".into(),
            metric_aggregation: "single".into(),
            flow_direction: Some("ingress".into()),
            flow_protocol: Some(6),
            flow_port: Some(443),
            flow_port_kind: Some("src".into()),
            operator: ">".into(),
            threshold_value: 1.0,
            duration_seconds: 0,
            consecutive_samples: 0,
            recovery_mode: "auto".into(),
            recovery_threshold_value: None,
            recovery_window_seconds: None,
            recovery_consecutive_samples: None,
            severity: "warning".into(),
            automatic_reroute_enabled: false,
        };
        let cfg = Config::load(concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml"))
            .expect("load test config");
        let observation = flow_observation(&pool, &cfg, &rule)
            .await
            .expect("read flow observation")
            .expect("latest interface bucket exists");

        assert_eq!(observation.value, 0.0);
        assert_eq!(observation.sampled_at, Some(latest));
        assert!(observation.low_confidence);

        sqlx::query("DELETE FROM flow_exporters WHERE id = ?")
            .bind(exporter_id)
            .execute(&pool)
            .await
            .expect("remove test exporter");
        sqlx::query("DELETE FROM devices WHERE id = ?")
            .bind(device_id)
            .execute(&pool)
            .await
            .expect("remove test device");
    }
}
