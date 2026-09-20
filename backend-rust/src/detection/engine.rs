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
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};

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
    evidence: std::collections::BTreeMap<u64, Ts>,
}

/// One enabled interface rule with the bits the evaluator needs.
#[derive(Debug, Clone, sqlx::FromRow)]
struct InterfaceRule {
    id: u64,
    actions_revision: u64,
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
    /// Recovery condition is independent from permission to mutate routers.
    automatic_revert_enabled: bool,
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
    in_err_rate_valid: bool,
    out_err_rate_valid: bool,
    oper_status_valid: bool,
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
            "in_err_rate" if self.in_err_rate_valid => self.in_err_rate,
            "out_err_rate" if self.out_err_rate_valid => self.out_err_rate,
            "oper_status" => {
                if !self.oper_status_valid {
                    return None;
                }
                match self.oper_status.as_deref() {
                    Some("up") => 1.0,
                    Some(
                        "down" | "testing" | "dormant" | "notPresent" | "lowerLayerDown"
                        | "not_present" | "lower_layer_down",
                    ) => 0.0,
                    _ => return None,
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
    last_observation_json: Option<sqlx::types::Json<Value>>,
    last_observation_at: Option<Ts>,
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
        "SELECT id, actions_revision, name, interface_id, device_id, metric, metric_aggregation, \
                flow_direction, flow_protocol, flow_port, flow_port_kind, \
                operator, threshold_value, \
                duration_seconds, consecutive_samples, \
                recovery_mode, recovery_threshold_value, recovery_window_seconds, \
                recovery_consecutive_samples, severity, \
                automatic_reroute_enabled, automatic_revert_enabled \
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
        "SELECT id, actions_revision, name, interface_id, device_id, metric, metric_aggregation, \
                flow_direction, flow_protocol, flow_port, flow_port_kind, \
                operator, threshold_value, \
                duration_seconds, consecutive_samples, \
                recovery_mode, recovery_threshold_value, recovery_window_seconds, \
                recovery_consecutive_samples, severity, \
                automatic_reroute_enabled, automatic_revert_enabled \
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

/// Evaluate flow rules whose enrolled interface was present in a completed
/// flush. E3 coalesces interface ids; every rule still uses the same cursor and
/// publication path as ordinary evaluation.
pub async fn evaluate_flow_interfaces(
    pool: &MySqlPool,
    cfg: &Config,
    interface_ids: &[u64],
) -> Result<usize> {
    if interface_ids.is_empty() {
        return Ok(0);
    }
    let mut ids = interface_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let mut query=sqlx::QueryBuilder::<sqlx::MySql>::new(
        "SELECT id,actions_revision,name,interface_id,device_id,metric,metric_aggregation,flow_direction,flow_protocol,flow_port,flow_port_kind,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_window_seconds,recovery_consecutive_samples,severity,automatic_reroute_enabled,automatic_revert_enabled FROM rules WHERE enabled=1 AND metric IN ('flow_pps','flow_bps') AND interface_id IN ("
    );
    let mut separated = query.separated(",");
    for id in ids {
        separated.push_bind(id);
    }
    query.push(") ORDER BY id");
    evaluate_rules(
        pool,
        cfg,
        query
            .build_query_as::<InterfaceRule>()
            .fetch_all(pool)
            .await?,
    )
    .await
}

pub async fn evaluate_all_flow_rules(pool: &MySqlPool, cfg: &Config) -> Result<usize> {
    let rules=sqlx::query_as::<_,InterfaceRule>(
        "SELECT id,actions_revision,name,interface_id,device_id,metric,metric_aggregation,flow_direction,flow_protocol,flow_port,flow_port_kind,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_window_seconds,recovery_consecutive_samples,severity,automatic_reroute_enabled,automatic_revert_enabled FROM rules WHERE enabled=1 AND metric IN ('flow_pps','flow_bps') ORDER BY id"
    ).fetch_all(pool).await?;
    evaluate_rules(pool, cfg, rules).await
}

#[doc(hidden)]
pub async fn automatic_flow_evidence_qualified(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
) -> Result<bool> {
    let rule=sqlx::query_as::<_,InterfaceRule>(
        "SELECT id,actions_revision,name,interface_id,device_id,metric,metric_aggregation,flow_direction,flow_protocol,flow_port,flow_port_kind,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_window_seconds,recovery_consecutive_samples,severity,automatic_reroute_enabled,automatic_revert_enabled FROM rules WHERE id=? AND enabled=1"
    ).bind(rule_id).fetch_optional(pool).await?;
    let Some(rule) = rule else { return Ok(false) };
    if !is_flow_metric(&rule.metric) {
        return Ok(true);
    }
    Ok(flow_observation(pool, cfg, &rule)
        .await?
        .is_some_and(|obs| !obs.low_confidence && obs.source_corroborated))
}

/// Revalidate a rule-owned automatic recovery against current evidence. A
/// queued recovery may wait long enough for the incident to relapse; in that
/// case the published recovery decision is stale and no inverse may be written.
#[doc(hidden)]
pub async fn automatic_condition_recovery_qualified(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
) -> Result<bool> {
    let rule=sqlx::query_as::<_,InterfaceRule>(
        "SELECT id,actions_revision,name,interface_id,device_id,metric,metric_aggregation,flow_direction,flow_protocol,flow_port,flow_port_kind,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_window_seconds,recovery_consecutive_samples,severity,automatic_reroute_enabled,automatic_revert_enabled FROM rules WHERE id=? AND enabled=1 AND automatic_revert_enabled=1"
    ).bind(rule_id).fetch_optional(pool).await?;
    let Some(rule) = rule else { return Ok(false) };
    let state: Option<String> =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule_id)
            .fetch_optional(pool)
            .await?;
    if state.as_deref() != Some("recovered_awaiting_revert") {
        return Ok(false);
    }
    let observation = if rule.metric_aggregation == "sum" {
        aggregate_observation(pool, cfg, &rule).await?
    } else if is_flow_metric(&rule.metric) {
        flow_observation(pool, cfg, &rule).await?
    } else {
        interface_observation(pool, cfg, &rule).await?
    };
    let Some(observation) = observation else {
        return Ok(false);
    };
    if is_flow_metric(&rule.metric)
        && (observation.low_confidence || !observation.source_corroborated)
    {
        return Ok(false);
    }
    let Some(operator) = Op::parse(&rule.operator) else {
        return Ok(false);
    };
    if operator.compare(observation.value, rule.threshold_value) {
        return Ok(false);
    }
    Ok(rule.recovery_mode != "threshold"
        || operator.recovered(
            observation.value,
            rule.recovery_threshold_value
                .unwrap_or(rule.threshold_value),
        ))
}

async fn evaluate_rules(
    pool: &MySqlPool,
    cfg: &Config,
    rules: Vec<InterfaceRule>,
) -> Result<usize> {
    let mut fired = 0;
    let mut failures = Vec::new();
    for rule in rules {
        match evaluate_rule(pool, cfg, &rule).await {
            Ok(true) => fired += 1,
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(event_type="flow_rule_eval_failed",rule_id=rule.id,error=%error);
                failures.push(format!("rule {}: {error:#}", rule.id));
            }
        }
    }
    if !failures.is_empty() {
        anyhow::bail!(
            "one or more flow rules remain retryable: {}",
            failures.join("; ")
        )
    }
    Ok(fired)
}

/// All required members must have advanced. A scheduler tick or a fast member
/// cannot count the same slow member twice.
fn evidence_advanced(
    previous: Option<&Value>,
    current: &std::collections::BTreeMap<u64, Ts>,
) -> bool {
    !current.is_empty()
        && current.iter().all(
            |(id, ts)| match previous.and_then(|p| p.get(id.to_string())) {
                None => true,
                Some(value) => value
                    .as_str()
                    .and_then(|s| s.parse::<Ts>().ok())
                    .is_some_and(|prior| *ts > prior),
            },
        )
}

async fn reset_unproven_streak(pool: &MySqlPool, rule_id: u64) -> Result<()> {
    sqlx::query("UPDATE rule_states SET current_state=IF(current_state='matching','clear',current_state), \
        first_matched_at=NULL,consecutive_match_count=0,recovery_first_at=NULL,recovery_consecutive=0 WHERE rule_id=?")
        .bind(rule_id).execute(pool).await?;
    Ok(())
}

/// Evaluate a single rule and advance its state. Returns Ok(true) iff the rule
/// transitioned INTO `firing` on this evaluation (the alert edge).
async fn evaluate_rule(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Result<bool> {
    let runtime = cfg.advisory_runtime(pool).await?;
    crate::db::advisory::background_scope(runtime, async {
        let guard =
            crate::db::advisory::acquire(&format!("00:detection:observation:{}", rule.id)).await?;
        let result = evaluate_rule_inner(pool, cfg, rule).await;
        guard.release().await?;
        result
    })
    .await?
}

async fn evaluate_rule_inner(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Result<bool> {
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
    let Some(obs) = obs else {
        reset_unproven_streak(pool, rule.id).await?;
        return Ok(false);
    };
    let value = obs.value;
    let sampled_at = obs.sampled_at;
    let matched = op.compare(value, rule.threshold_value);

    // Load prior state.
    let mut prev = sqlx::query_as::<_, RuleStateRow>(
        "SELECT current_state, first_matched_at, recovery_first_at, \
                recovery_consecutive, consecutive_match_count, last_observation_json, last_observation_at \
         FROM rule_states WHERE rule_id = ?",
    )
    .bind(rule.id)
    .fetch_optional(pool)
    .await?
    .unwrap_or_default();

    if !evidence_advanced(
        prev.last_observation_json.as_ref().map(|j| &j.0),
        &obs.evidence,
    ) {
        return Ok(false);
    }
    let now = sampled_at.ok_or_else(|| anyhow::anyhow!("observation has no timestamp"))?;
    let gap_limit = if is_flow_metric(&rule.metric) {
        cfg.telemetry
            .stale_after_seconds
            .max(cfg.flow.bucket_seconds.saturating_mul(3))
    } else {
        cfg.telemetry.stale_after_seconds
    } as i64;
    if prev
        .last_observation_at
        .is_some_and(|last| (now - last).num_seconds() > gap_limit)
    {
        reset_unproven_streak(pool, rule.id).await?;
        prev.first_matched_at = None;
        prev.consecutive_match_count = 0;
        prev.recovery_first_at = None;
        prev.recovery_consecutive = 0;
        if prev.current_state.as_deref() == Some("matching") {
            prev.current_state = Some("clear".into());
        }
    }
    let mut prev_state = prev.current_state.clone().unwrap_or_else(|| "clear".into());
    if prev_state == "recovered_awaiting_revert"
        && rule_owned_changes(pool, rule.id, false).await? == 0
    {
        prev_state = "clear".into();
        prev.first_matched_at = None;
        prev.consecutive_match_count = 0;
    }

    if matched {
        let consecutive = prev.consecutive_match_count.saturating_add(1);
        // first_matched_at is the start of the current matching streak.
        let first_matched = prev.first_matched_at.unwrap_or(now);
        let held_secs = (now - first_matched).num_seconds();
        if prev_state == "recovered_awaiting_revert" {
            publish_simple_observation(
                pool,
                rule,
                "firing",
                Some(first_matched),
                consecutive,
                value,
                &obs,
                None,
                0,
                None,
            )
            .await?;
            return Ok(false);
        }

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
            on_fire(
                pool,
                cfg,
                rule,
                value,
                sampled_at,
                obs.low_confidence,
                obs.source_corroborated,
                &obs.evidence,
                first_matched,
                consecutive,
            )
            .await?;
            return Ok(true);
        } else if prev_state == "firing" {
            // Already firing and the firing condition still holds: keep firing,
            // refresh activity (no new alert), and cancel any recovery progress.
            publish_simple_observation(
                pool,
                rule,
                "firing",
                Some(first_matched),
                consecutive,
                value,
                &obs,
                None,
                0,
                None,
            )
            .await?;
            return Ok(false);
        } else {
            // Matching but persistence not yet met.
            publish_simple_observation(
                pool,
                rule,
                "matching",
                Some(first_matched),
                consecutive,
                value,
                &obs,
                None,
                0,
                (prev_state == "clear").then_some("matched"),
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
            publish_simple_observation(
                pool,
                rule,
                "firing",
                prev.first_matched_at,
                prev.consecutive_match_count,
                value,
                &obs,
                None,
                0,
                None,
            )
            .await?;
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
            publish_simple_observation(
                pool,
                rule,
                "firing",
                prev.first_matched_at,
                prev.consecutive_match_count,
                value,
                &obs,
                None,
                0,
                None,
            )
            .await?;
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
                recover_and_clear(
                    pool,
                    cfg,
                    rule,
                    value,
                    sampled_at,
                    obs.low_confidence,
                    obs.source_corroborated,
                    &obs.evidence,
                )
                .await?;
            } else {
                publish_simple_observation(
                    pool,
                    rule,
                    "firing",
                    prev.first_matched_at,
                    prev.consecutive_match_count,
                    value,
                    &obs,
                    Some(rec_first),
                    prev.recovery_consecutive,
                    None,
                )
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
                recover_and_clear(
                    pool,
                    cfg,
                    rule,
                    value,
                    sampled_at,
                    obs.low_confidence,
                    obs.source_corroborated,
                    &obs.evidence,
                )
                .await?;
            } else {
                publish_simple_observation(
                    pool,
                    rule,
                    "firing",
                    prev.first_matched_at,
                    prev.consecutive_match_count,
                    value,
                    &obs,
                    None,
                    rec_consec,
                    None,
                )
                .await?;
            }
            return Ok(false);
        }
    }

    if prev_state == "recovered_awaiting_revert" {
        // Router ownership outlives the recovered condition. Quiet samples must
        // never clear that ownership marker; only a verified inverse may do so.
        publish_simple_observation(
            pool,
            rule,
            "recovered_awaiting_revert",
            None,
            0,
            value,
            &obs,
            None,
            0,
            None,
        )
        .await?;
        if let Some(bundle_id)=sqlx::query_scalar::<_,u64>("SELECT id FROM reroute_bundles WHERE rule_id=? AND state='planned' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.kind'))='recovery' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.preparation_phase'))='published' ORDER BY id LIMIT 1")
            .bind(rule.id).fetch_optional(pool).await? {
            submit_recovery_worker(pool,cfg,rule.clone(),bundle_id).await?;
        }
        return Ok(false);
    }

    // Was matching but the condition dropped before firing, or already clear.
    if prev_state == "matching" {
        publish_simple_observation(pool, rule, "clear", None, 0, value, &obs, None, 0, None)
            .await?;
    } else {
        // Keep last_evaluated_at fresh.
        publish_simple_observation(pool, rule, "clear", None, 0, value, &obs, None, 0, None)
            .await?;
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
                rx_util_percent, tx_util_percent, in_err_rate, out_err_rate, oper_status, in_err_rate_valid, out_err_rate_valid, oper_status_valid \
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
        Some(ts) if (0..=stale_after).contains(&(Utc::now() - ts).num_seconds()) => {}
        _ => return Ok(None),
    }
    let Some(value) = metrics.value(&rule.metric) else {
        return Ok(None);
    };
    Ok(Some(Observation {
        value,
        sampled_at: metrics.sampled_at,
        evidence: metrics
            .sampled_at
            .map(|ts| (interface_id, ts))
            .into_iter()
            .collect(),
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
    let mut evidence = std::collections::BTreeMap::new();
    for interface_id in members {
        let m = sqlx::query_as::<_, CurrentMetrics>(
            "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
                    rx_util_percent, tx_util_percent, in_err_rate, out_err_rate, oper_status, in_err_rate_valid, out_err_rate_valid, oper_status_valid \
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
            Some(ts) if (0..=stale_after).contains(&(Utc::now() - ts).num_seconds()) => {
                evidence.insert(interface_id, ts);
                if newest.map(|n| ts < n).unwrap_or(true) {
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
        evidence,
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
    if !(0..=flow_stale).contains(&(Utc::now() - bucket_ts).num_seconds()) {
        return Ok(None);
    }
    let quality_dimension = if rule.flow_port.is_some() {
        crate::telemetry::flow::quality::QualityDimension::Port
    } else {
        crate::telemetry::flow::quality::QualityDimension::Interface
    };
    let quality_direction = if direction == "egress" {
        crate::telemetry::flow::Direction::Egress
    } else {
        crate::telemetry::flow::Direction::Ingress
    };
    let quality = crate::telemetry::flow::quality::bucket_evidence(
        pool,
        dev_id,
        if_index,
        quality_direction,
        bucket_ts,
        quality_dimension,
    )
    .await?;
    if quality.availability == crate::telemetry::flow::quality::EvidenceAvailability::Unavailable {
        return Ok(None);
    }

    // (est_pkts, est_bytes, low-confidence flag). Aggregates return NULL when a
    // selector has no row in this bucket; its current value is then zero and its
    // confidence remains low, so absence can clear stale state but never act.
    type Agg = (
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
    );
    let agg = "CAST(SUM(pkts * effective_sampling_rate) AS UNSIGNED), \
               CAST(SUM(bytes * effective_sampling_rate) AS UNSIGNED), \
               CAST(MAX(sampling_confidence = 'low') AS UNSIGNED), CAST(MIN(pkts_available) AS UNSIGNED), CAST(MIN(bytes_available) AS UNSIGNED)";

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

    let (est_pkts, est_bytes, _low_conf, _pkts_available, _bytes_available) = row;
    let available = match rule.metric.as_str() {
        "flow_pps" => quality.pkts_available,
        "flow_bps" => quality.bytes_available,
        _ => false,
    };
    if !available {
        return Ok(None);
    }

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
        evidence: [(rule.interface_id.unwrap_or(0), bucket_ts)]
            .into_iter()
            .collect(),
        low_confidence: !quality.sampling_high_confidence || !source_corroborated,
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
    let sample_age = (Utc::now() - sampled_at).num_seconds();
    if !valid || !(0..=cfg.telemetry.stale_after_seconds as i64).contains(&sample_age) {
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
    if !flow_value.is_finite() || !snmp_value.is_finite() || flow_value < 0.0 || snmp_value < 0.0 {
        return Ok(false);
    }
    if snmp_value == 0.0 {
        return Ok(flow_value == 0.0);
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
#[allow(clippy::too_many_arguments)]
async fn on_fire(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
    low_confidence: bool,
    source_corroborated: bool,
    evidence: &std::collections::BTreeMap<u64, Ts>,
    first_matched: Ts,
    consecutive: u32,
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
    let automatic_inputs: Vec<Value> = if auto {
        sqlx::query_as::<_,(u64,u64,Option<sqlx::types::Json<Value>>,Option<String>,u32)>(
            "SELECT reroute_template_id,device_id,params_json,auto_target,position FROM rule_actions WHERE rule_id=? AND enabled=1 ORDER BY position,id"
        ).bind(rule.id).fetch_all(pool).await?.into_iter().map(|(template_id,device_id,params,auto_target,position)|json!({
            "template_id":template_id,"device_id":device_id,"params":params.map(|v|v.0).unwrap_or(Value::Null),"auto_target":auto_target,"position":position
        })).collect()
    } else {
        Vec::new()
    };

    let dedup_key = match rule.interface_id {
        Some(id) => format!("rule_fired:rule:{}:iface:{}", rule.id, id),
        None => format!("rule_fired:rule:{}:agg", rule.id),
    };
    // Persist the firing edge and its alert atomically BEFORE any SSH side
    // effect. If this transaction fails, the previous state and cursor remain
    // unchanged so the same observation can retry later. Once it commits, a crash can at worst omit the automatic
    // action; it can never leave an unalerted action that is retried blindly.
    let persist_started = std::time::Instant::now();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO rule_states(rule_id,current_state,first_matched_at,recovery_first_at,recovery_consecutive,consecutive_match_count,last_metric_value,last_observation_json,last_observation_at,last_matched_at,last_evaluated_at) VALUES(?,'firing',?,NULL,0,?,?,?,?,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE current_state='firing',first_matched_at=VALUES(first_matched_at),recovery_first_at=NULL,recovery_consecutive=0,consecutive_match_count=VALUES(consecutive_match_count),last_metric_value=VALUES(last_metric_value),last_observation_json=VALUES(last_observation_json),last_observation_at=VALUES(last_observation_at),last_matched_at=VALUES(last_observation_at),last_evaluated_at=UTC_TIMESTAMP()")
        .bind(rule.id).bind(first_matched).bind(consecutive).bind(value).bind(sqlx::types::Json(evidence)).bind(sampled_at).bind(sampled_at).execute(&mut *tx).await?;
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
    let planned_bundle_id = if auto && !automatic_inputs.is_empty() {
        let row=sqlx::query("INSERT INTO reroute_bundles(rule_id,rule_event_id,trigger_type,reason,state,failure_policy,total_actions,source_json) VALUES(?,?,'automatic',?,'planned','abort_and_compensate',?,?)")
            .bind(rule.id).bind(rule_event_id).bind(format!("automatic: rule '{}' fired",rule.name)).bind(automatic_inputs.len() as u32)
            .bind(sqlx::types::Json(json!({"kind":"rule","rule_id":rule.id,"name":rule.name,"actions_revision":rule.actions_revision,"input_actions":automatic_inputs,"admission_state":"published"})))
            .execute(&mut *tx).await?;
        Some(row.last_insert_id())
    } else {
        None
    };
    if cfg.fail_automatic_decision_before_commit {
        anyhow::bail!("injected decision publication failure")
    }
    tx.commit().await?;
    tracing::info!(event_type="hardening_timing",stage="decision_persist",subject_id=rule.id,elapsed_us=persist_started.elapsed().as_micros() as u64,outcome="committed",observation_at=?sampled_at);

    if let Some(bundle_id) = planned_bundle_id {
        if let Err(error) =
            submit_automatic_worker(pool, cfg, rule.clone(), rule_event_id, alert_id, bundle_id)
                .await
        {
            tracing::error!(event_type="automatic_worker_submit_failed",rule_id=rule.id,bundle_id,error=%error,"durable firing decision remains committed for startup repair");
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

type JobFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[derive(Clone, Copy)]
enum JobKind {
    Activation,
    Recovery,
}
struct SupervisedJob {
    future: JobFuture,
    pool: Option<MySqlPool>,
    bundle_id: u64,
    kind: JobKind,
}

#[derive(Default)]
pub struct AutomaticWorkQueue {
    sender: OnceLock<tokio::sync::mpsc::Sender<SupervisedJob>>,
}

/// External router I/O used by the durable automatic-work pipeline. Database
/// publication/admission is intentionally outside this seam.
#[doc(hidden)]
pub trait AutomaticWorkPort: Send + Sync + std::fmt::Debug {
    fn prepare_manual_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
        mode: crate::reroute::device_plan::VerificationMode,
    ) -> crate::ssh::BoxFuture<'a, Result<()>>;
    fn prepare_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
    ) -> crate::ssh::BoxFuture<'a, Result<()>>;
    fn prepare_recovery<'a>(
        &'a self,
        pool: &'a MySqlPool,
        originals: &'a [u64],
        reason: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<crate::reroute::bundle::BundleAction>>>;
    fn transport_identities<'a>(
        &'a self,
        device_ids: &'a [u64],
    ) -> crate::ssh::BoxFuture<
        'a,
        Result<
            std::collections::BTreeMap<u64, crate::reroute::device_plan::DeviceTransportIdentity>,
        >,
    >;
    fn run_bundle<'a>(
        &'a self,
        pool: &'a MySqlPool,
        cfg: &'a Config,
        run: crate::reroute::bundle::BundleRun,
        actions: Vec<crate::reroute::bundle::BundleAction>,
    ) -> crate::ssh::BoxFuture<'a, crate::reroute::bundle::BundleOutcome>;
}

struct ProductionAutomaticWorkPort {
    ssh: crate::ssh::RusshExecutor,
}
impl std::fmt::Debug for ProductionAutomaticWorkPort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProductionAutomaticWorkPort")
            .finish_non_exhaustive()
    }
}
impl ProductionAutomaticWorkPort {
    fn new(pool: &MySqlPool) -> Self {
        Self {
            ssh: crate::ssh::RusshExecutor::new(pool.clone()),
        }
    }
}

pub(crate) fn production_work_port(pool: &MySqlPool) -> Arc<dyn AutomaticWorkPort> {
    Arc::new(ProductionAutomaticWorkPort::new(pool))
}
impl AutomaticWorkPort for ProductionAutomaticWorkPort {
    fn prepare_manual_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
        mode: crate::reroute::device_plan::VerificationMode,
    ) -> crate::ssh::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::reroute::preparation::inspect_actions_for_mode(pool, actions, mode).await
        })
    }
    fn prepare_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
    ) -> crate::ssh::BoxFuture<'a, Result<()>> {
        Box::pin(
            async move { crate::reroute::preparation::inspect_actions(pool, actions, true).await },
        )
    }
    fn prepare_recovery<'a>(
        &'a self,
        pool: &'a MySqlPool,
        originals: &'a [u64],
        reason: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<crate::reroute::bundle::BundleAction>>> {
        Box::pin(async move {
            crate::reroute::preparation::prepare_rollbacks(pool, originals, reason, true).await
        })
    }
    fn transport_identities<'a>(
        &'a self,
        device_ids: &'a [u64],
    ) -> crate::ssh::BoxFuture<
        'a,
        Result<
            std::collections::BTreeMap<u64, crate::reroute::device_plan::DeviceTransportIdentity>,
        >,
    > {
        Box::pin(self.ssh.transport_identities(device_ids))
    }
    fn run_bundle<'a>(
        &'a self,
        pool: &'a MySqlPool,
        cfg: &'a Config,
        run: crate::reroute::bundle::BundleRun,
        actions: Vec<crate::reroute::bundle::BundleAction>,
    ) -> crate::ssh::BoxFuture<'a, crate::reroute::bundle::BundleOutcome> {
        Box::pin(async move {
            crate::reroute::bundle::run_with_ssh(pool, cfg, run, actions, &self.ssh).await
        })
    }
}

#[doc(hidden)]
pub struct InjectedAutomaticWorkPort<R, S> {
    reader: Arc<R>,
    ssh: Arc<S>,
}
impl<R, S> std::fmt::Debug for InjectedAutomaticWorkPort<R, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InjectedAutomaticWorkPort")
            .finish_non_exhaustive()
    }
}
impl<R, S> InjectedAutomaticWorkPort<R, S> {
    pub fn new(reader: Arc<R>, ssh: Arc<S>) -> Self {
        Self { reader, ssh }
    }
}
impl<R, S> AutomaticWorkPort for InjectedAutomaticWorkPort<R, S>
where
    R: crate::reroute::device_plan::PreparationReader + 'static,
    S: crate::ssh::SshExecutor + 'static,
{
    fn prepare_manual_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
        mode: crate::reroute::device_plan::VerificationMode,
    ) -> crate::ssh::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::reroute::preparation::inspect_actions_with_reader_for_mode(
                pool,
                actions,
                false,
                &*self.reader,
                mode,
            )
            .await
        })
    }
    fn prepare_activation<'a>(
        &'a self,
        pool: &'a MySqlPool,
        actions: &'a mut [crate::reroute::bundle::BundleAction],
    ) -> crate::ssh::BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            crate::reroute::preparation::inspect_actions_with_reader(
                pool,
                actions,
                true,
                &*self.reader,
            )
            .await
        })
    }
    fn prepare_recovery<'a>(
        &'a self,
        pool: &'a MySqlPool,
        originals: &'a [u64],
        reason: &'a str,
    ) -> crate::ssh::BoxFuture<'a, Result<Vec<crate::reroute::bundle::BundleAction>>> {
        Box::pin(async move {
            let mut actions =
                crate::reroute::preparation::prepare_rollbacks(pool, originals, reason, false)
                    .await?;
            let mut plans = actions
                .iter()
                .filter_map(|action| action.prepared.clone())
                .collect::<Vec<_>>();
            crate::reroute::device_plan::prepare_inverse_sequence_read_only_with_reader(
                &*self.reader,
                &mut plans,
            )
            .await?;
            for (action, plan) in actions.iter_mut().zip(plans) {
                action.prepared = Some(plan)
            }
            Ok(actions)
        })
    }
    fn transport_identities<'a>(
        &'a self,
        device_ids: &'a [u64],
    ) -> crate::ssh::BoxFuture<
        'a,
        Result<
            std::collections::BTreeMap<u64, crate::reroute::device_plan::DeviceTransportIdentity>,
        >,
    > {
        Box::pin(async move {
            let locks = self.ssh.lock_devices(device_ids).await?;
            let mut identities = std::collections::BTreeMap::new();
            for device_id in locks.device_ids() {
                identities.insert(device_id, locks.transport_identity(device_id)?);
            }
            locks.unlock_all().await?;
            Ok(identities)
        })
    }
    fn run_bundle<'a>(
        &'a self,
        pool: &'a MySqlPool,
        cfg: &'a Config,
        run: crate::reroute::bundle::BundleRun,
        actions: Vec<crate::reroute::bundle::BundleAction>,
    ) -> crate::ssh::BoxFuture<'a, crate::reroute::bundle::BundleOutcome> {
        Box::pin(async move {
            crate::reroute::bundle::run_with_ssh(pool, cfg, run, actions, &*self.ssh).await
        })
    }
}
impl std::fmt::Debug for AutomaticWorkQueue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutomaticWorkQueue").finish_non_exhaustive()
    }
}
impl AutomaticWorkQueue {
    fn sender(&self) -> tokio::sync::mpsc::Sender<SupervisedJob> {
        self.sender
            .get_or_init(|| {
                let (tx, rx) = tokio::sync::mpsc::channel::<SupervisedJob>(4096);
                let rx = Arc::new(tokio::sync::Mutex::new(rx));
                for _ in 0..2 {
                    let rx = rx.clone();
                    tokio::spawn(async move {
                        loop {
                            let job = { rx.lock().await.recv().await };
                            let Some(job) = job else { return };
                            let metadata=(job.pool.clone(),job.bundle_id,job.kind);
                            if tokio::spawn(job.future).await.is_err(){
                                tracing::error!(event_type="automatic_worker_panicked","supervised automatic worker job panicked; consumer remains available");
                                if let Some(pool)=metadata.0.as_ref(){settle_worker_failure(pool,metadata.1,metadata.2,"automatic worker panicked").await;}
                            }
                        }
                    });
                }
                tx
            })
            .clone()
    }
    async fn submit(&self, job: SupervisedJob) -> Result<()> {
        self.sender()
            .try_send(job)
            .map_err(|error| anyhow::anyhow!("automatic worker queue unavailable: {error}"))
    }
}

async fn settle_worker_failure(pool: &MySqlPool, bundle_id: u64, kind: JobKind, reason: &str) {
    let unstarted = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reroute_bundles WHERE id=? AND state='planned' AND NOT EXISTS(SELECT 1 FROM reroutes WHERE bundle_id=?)",
    ).bind(bundle_id).bind(bundle_id).fetch_one(pool).await.is_ok_and(|count| count == 1);
    if unstarted {
        let owner_token = match kind {
            JobKind::Activation => format!("bundle:{bundle_id}"),
            JobKind::Recovery => format!("recovery:bundle:{bundle_id}"),
        };
        if let Err(error) = crate::reroute::bundle::finish_and_release(
            pool,
            bundle_id,
            "failed",
            Some(reason),
            &owner_token,
        )
        .await
        {
            tracing::error!(event_type="automatic_worker_settlement_failed",bundle_id,error=%error);
        }
        return;
    }
    let _ = quarantine_interrupted_worker_bundle(pool, bundle_id, reason).await;
    match kind {
        JobKind::Activation => {}
        JobKind::Recovery => {
            let _ = crate::reroute::recovery::finalize_recovery_child(
                pool,
                bundle_id,
                "failed",
                Some(reason),
                &format!("recovery:bundle:{bundle_id}"),
            )
            .await;
        }
    }
}

pub(crate) async fn settle_supervised_manual_failure(
    pool: &MySqlPool,
    bundle_id: u64,
    recovery: bool,
    reason: &str,
) {
    settle_worker_failure(
        pool,
        bundle_id,
        if recovery {
            JobKind::Recovery
        } else {
            JobKind::Activation
        },
        reason,
    )
    .await;
}

async fn quarantine_interrupted_worker_bundle(
    pool: &MySqlPool,
    bundle_id: u64,
    reason: &str,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    let rows:Vec<(u64,u64)>=sqlx::query_as("SELECT id,device_id FROM reroutes WHERE bundle_id=? AND state IN ('planned','pending','running','verifying') FOR UPDATE")
        .bind(bundle_id).fetch_all(&mut *tx).await?;
    for (reroute_id, device_id) in rows {
        sqlx::query("UPDATE reroutes SET state='uncertain',success=NULL,mutation_effect='unknown',verification_status='uncertain',finished_at=UTC_TIMESTAMP(),failure_reason=? WHERE id=? AND state IN ('planned','pending','running','verifying')")
            .bind(reason).bind(reroute_id).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO locks(scope,scope_ref,reroute_id,reason,kind) SELECT 'device',?,?,?,'auto_uncertain' WHERE NOT EXISTS(SELECT 1 FROM locks WHERE reroute_id=? AND cleared_at IS NULL)")
            .bind(device_id.to_string()).bind(reroute_id).bind(reason).bind(reroute_id).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE reroute_bundles SET state='compensation_blocked',lifecycle_state='recovery_blocked',finished_at=UTC_TIMESTAMP(),interrupted_at=UTC_TIMESTAMP(),failure_reason=?,rate_reserved_actions=0 WHERE id=? AND state IN ('planned','running','compensating')")
        .bind(reason).bind(bundle_id).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO audit_logs(actor_type,event_type,entity_type,entity_id,message) SELECT 'system','automatic_worker_interrupted','reroute_bundle',?,? WHERE NOT EXISTS(SELECT 1 FROM audit_logs WHERE event_type='automatic_worker_interrupted' AND entity_type='reroute_bundle' AND entity_id=?)")
        .bind(bundle_id).bind(reason).bind(bundle_id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

/// Submit a timer-owned recovery child that was durably published by the short
/// background claim transaction. Router reads and writes run only in the shared
/// bounded foreground worker queue.
pub async fn submit_scheduled_recovery_worker(
    pool: &MySqlPool,
    cfg: &Config,
    bundle_id: u64,
) -> Result<()> {
    let claimed=sqlx::query("UPDATE reroute_bundles SET source_json=JSON_SET(source_json,'$.preparation_phase','preparing') WHERE id=? AND state='planned' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.preparation_phase'))='published'")
        .bind(bundle_id).execute(pool).await?;
    if claimed.rows_affected() != 1 {
        return Ok(());
    }
    let pool = pool.clone();
    let cfg = cfg.clone();
    let port = cfg
        .automatic_work_port
        .clone()
        .unwrap_or_else(|| Arc::new(ProductionAutomaticWorkPort::new(&pool)));
    let queue = cfg.automatic_work_queue.clone();
    let job_pool = pool.clone();
    let settle_pool = pool.clone();
    let future = Box::pin(async move {
        let runtime = match cfg.advisory_runtime(&pool).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(event_type="scheduled_recovery_scope_failed",bundle_id,error=%error);
                settle_worker_failure(
                    &pool,
                    bundle_id,
                    JobKind::Recovery,
                    &format!("lock runtime unavailable: {error:#}"),
                )
                .await;
                return;
            }
        };
        let work = async {
            anyhow::ensure!(
                crate::api::settings::operating_mode(&pool, &cfg).await == "enforce"
                    && crate::api::settings::bool_setting(
                        &pool,
                        "automatic_actions_enabled",
                        cfg.safety.automatic_actions_enabled
                    )
                    .await,
                "scheduled recovery authority is off"
            );
            let source: sqlx::types::Json<Value> = sqlx::query_scalar(
                "SELECT source_json FROM reroute_bundles WHERE id=? AND state='planned'",
            )
            .bind(bundle_id)
            .fetch_one(&pool)
            .await?;
            let originals = source.0["original_reroute_ids"]
                .as_array()
                .map(|ids| ids.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
                .unwrap_or_default();
            let reason = source
                .0
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("scheduled recovery")
                .to_string();
            let actions = port.prepare_recovery(&pool, &originals, &reason).await?;
            let fence = crate::reroute::guard::policy_fence(&pool).await?;
            anyhow::ensure!(
                crate::api::settings::operating_mode(&pool, &cfg).await == "enforce"
                    && crate::api::settings::bool_setting(
                        &pool,
                        "automatic_actions_enabled",
                        cfg.safety.automatic_actions_enabled
                    )
                    .await,
                "scheduled recovery authority changed during preparation"
            );
            let devices = actions
                .iter()
                .map(|action| action.device_id)
                .collect::<Vec<_>>();
            let identities = port.transport_identities(&devices).await?;
            fence.release().await?;
            let mut next = source.0;
            next["transport_identities"] = json!(identities);
            next["preparation_phase"] = json!("prepared");
            sqlx::query("UPDATE reroute_bundles SET source_json=? WHERE id=? AND state='planned'")
                .bind(sqlx::types::Json(next))
                .bind(bundle_id)
                .execute(&pool)
                .await?;
            crate::reroute::bundle::persist_actions(&pool, bundle_id, &actions).await?;
            let outcome = port
                .run_bundle(
                    &pool,
                    &cfg,
                    crate::reroute::bundle::BundleRun::scheduled_recovery(
                        bundle_id,
                        crate::reroute::bundle::FailurePolicy::AbortAndCompensate,
                    ),
                    actions,
                )
                .await;
            anyhow::ensure!(
                outcome.state == "succeeded",
                "scheduled recovery ended {}: {}",
                outcome.state,
                outcome.failure_reason.as_deref().unwrap_or("no diagnostic")
            );
            Ok::<(), anyhow::Error>(())
        };
        let result = crate::db::advisory::foreground_scope(runtime, work).await;
        if let Err(error) = result.and_then(|value| value) {
            let _ = crate::reroute::recovery::finalize_recovery_child(
                &pool,
                bundle_id,
                "failed",
                Some(&format!("{error:#}")),
                &format!("recovery:bundle:{bundle_id}"),
            )
            .await;
        }
    });
    let job = SupervisedJob {
        future,
        pool: Some(job_pool),
        bundle_id,
        kind: JobKind::Recovery,
    };
    if let Err(error) = queue.submit(job).await {
        settle_worker_failure(
            &settle_pool,
            bundle_id,
            JobKind::Recovery,
            &format!("worker submission failed: {error:#}"),
        )
        .await;
        return Err(error);
    }
    Ok(())
}

async fn submit_automatic_worker(
    pool: &MySqlPool,
    cfg: &Config,
    rule: InterfaceRule,
    rule_event_id: u64,
    alert_id: u64,
    bundle_id: u64,
) -> Result<()> {
    let port = cfg
        .automatic_work_port
        .clone()
        .unwrap_or_else(|| Arc::new(ProductionAutomaticWorkPort::new(pool)));
    submit_automatic_worker_with_port(pool, cfg, rule, rule_event_id, alert_id, bundle_id, port)
        .await
}

async fn submit_automatic_worker_with_port(
    pool: &MySqlPool,
    cfg: &Config,
    rule: InterfaceRule,
    rule_event_id: u64,
    alert_id: u64,
    bundle_id: u64,
    port: Arc<dyn AutomaticWorkPort>,
) -> Result<()> {
    let pool = pool.clone();
    let cfg = cfg.clone();
    let queue = cfg.automatic_work_queue.clone();
    let job_pool = pool.clone();
    let settle_pool = pool.clone();
    let future = Box::pin(async move {
        let runtime = match cfg.advisory_runtime(&pool).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(event_type="automatic_worker_scope_failed",bundle_id,error=%error);
                settle_worker_failure(
                    &pool,
                    bundle_id,
                    JobKind::Activation,
                    &format!("lock runtime unavailable: {error:#}"),
                )
                .await;
                return;
            }
        };
        let work = async {
            let result =
                auto_execute_actions(&pool, &cfg, &rule, rule_event_id, bundle_id, &*port).await;
            match result {
                Ok(executed) => {
                    let _=sqlx::query("UPDATE alerts SET payload_json=JSON_SET(payload_json,'$.automatic_execution_completed',true,'$.executed_actions',?) WHERE id=?")
                        .bind(sqlx::types::Json(executed)).bind(alert_id).execute(&pool).await;
                }
                Err(error) => {
                    let reason = format!("automatic preparation/execution failed: {error:#}");
                    let _=sqlx::query("UPDATE reroute_bundles SET state='failed',finished_at=UTC_TIMESTAMP(),failure_reason=? WHERE id=? AND state='planned'")
                        .bind(&reason).bind(bundle_id).execute(&pool).await;
                    tracing::error!(event_type="automatic_action_failed",rule_id=rule.id,bundle_id,error=%error);
                }
            }
        };
        if let Err(error) = crate::db::advisory::foreground_scope(runtime, work).await {
            tracing::error!(event_type="automatic_worker_scope_failed",bundle_id,error=%error);
            settle_worker_failure(
                &pool,
                bundle_id,
                JobKind::Activation,
                &format!("foreground scope failed: {error:#}"),
            )
            .await;
        }
    });
    let job = SupervisedJob {
        future,
        pool: Some(job_pool),
        bundle_id,
        kind: JobKind::Activation,
    };
    if let Err(error) = queue.submit(job).await {
        settle_worker_failure(
            &settle_pool,
            bundle_id,
            JobKind::Activation,
            &format!("worker submission failed: {error:#}"),
        )
        .await;
        return Err(error);
    }
    Ok(())
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
    bundle_id: u64,
    port: &dyn AutomaticWorkPort,
) -> Result<Vec<Value>> {
    let current: Option<(u64, bool)> = sqlx::query_as(
        "SELECT actions_revision,automatic_reroute_enabled FROM rules WHERE id=? AND enabled=1",
    )
    .bind(rule.id)
    .fetch_optional(pool)
    .await?;
    anyhow::ensure!(
        current == Some((rule.actions_revision, true)),
        "rule authority or action revision changed before automatic preparation"
    );
    anyhow::ensure!(
        crate::api::settings::operating_mode(pool, cfg).await == "enforce",
        "automatic execution is no longer enforced"
    );
    anyhow::ensure!(
        crate::api::settings::bool_setting(
            pool,
            "automatic_actions_enabled",
            cfg.safety.automatic_actions_enabled
        )
        .await,
        "automatic master switch is off"
    );
    if is_flow_metric(&rule.metric) {
        let current = flow_observation(pool, cfg, rule).await?;
        anyhow::ensure!(
            current.is_some_and(|obs| !obs.low_confidence && obs.source_corroborated),
            "flow evidence is no longer qualified for automatic execution"
        );
    }
    let mut source: sqlx::types::Json<Value> = sqlx::query_scalar(
        "SELECT source_json FROM reroute_bundles WHERE id=? AND state='planned'",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    let specs = source
        .0
        .get("input_actions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let sel = flow_selector(rule);
    let mut out = Vec::with_capacity(specs.len());
    // Resolve every action first, then run the resolved set as ONE ordered bundle.
    // Resolving up front is what lets the bundle be admitted (or refused) whole.
    let mut ready: Vec<crate::reroute::bundle::BundleAction> = Vec::new();
    for spec in specs {
        let template_id = spec["template_id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("planned action lacks template"))?;
        let device_id = spec["device_id"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("planned action lacks device"))?;
        let params = spec.get("params").cloned().unwrap_or(Value::Null);
        let auto_target = spec.get("auto_target").and_then(Value::as_str);
        let position = spec["position"]
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| anyhow::anyhow!("planned action lacks position"))?;
        match flow_target::prepare_action(pool, &sel, template_id, device_id, params, auto_target)
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
                ready.push(crate::reroute::bundle::BundleAction {
                    prepared: None,
                    original_reroute_id: None,
                    device_id,
                    template,
                    params,
                    reason,
                    position,
                    auto_target: at.as_ref().map(|a| a.cidr.clone()),
                    auto_target_low_confidence: at.as_ref().map(|a| a.low_confidence),
                });
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

    if ready.is_empty() || !out.is_empty() {
        sqlx::query("UPDATE reroute_bundles SET state='failed',finished_at=UTC_TIMESTAMP(),failure_reason='automatic inputs could not all be resolved' WHERE id=? AND state='planned'")
            .bind(bundle_id).execute(pool).await?;
        out.push(json!({"executed":false,"blocked_reason":"entire mitigation refused: every enabled action must be resolved with sufficient confidence"}));
        return Ok(out);
    }
    if let Err(e) = port.prepare_activation(pool, &mut ready).await {
        sqlx::query("UPDATE reroute_bundles SET state='failed',finished_at=UTC_TIMESTAMP(),failure_reason=? WHERE id=? AND state='planned'")
            .bind(format!("automatic preparation refused: {e:#}")).bind(bundle_id).execute(pool).await?;
        return Ok(vec![
            json!({"executed":false,"blocked_reason":format!("entire mitigation preparation refused: {e:#}")}),
        ]);
    }

    let device_ids: Vec<_> = ready.iter().map(|a| a.device_id).collect();
    let identities = port.transport_identities(&device_ids).await?;
    let policy_fence = crate::reroute::guard::policy_fence(pool).await?;
    let current: Option<(u64, bool)> = sqlx::query_as(
        "SELECT actions_revision,automatic_reroute_enabled FROM rules WHERE id=? AND enabled=1",
    )
    .bind(rule.id)
    .fetch_optional(pool)
    .await?;
    anyhow::ensure!(
        current == Some((rule.actions_revision, true))
            && crate::api::settings::operating_mode(pool, cfg).await == "enforce"
            && crate::api::settings::bool_setting(
                pool,
                "automatic_actions_enabled",
                cfg.safety.automatic_actions_enabled
            )
            .await,
        "automatic authority changed during preparation"
    );
    if is_flow_metric(&rule.metric) {
        anyhow::ensure!(
            automatic_flow_evidence_qualified(pool, cfg, rule.id).await?,
            "flow evidence changed during preparation"
        );
    }
    policy_fence.release().await?;

    let total = ready.len() as u32;
    let policy = crate::reroute::bundle::FailurePolicy::AbortAndCompensate;
    source.0["transport_identities"] = json!(identities);
    source.0["admission_state"] = json!("prepared");
    sqlx::query("UPDATE reroute_bundles SET source_json = ? WHERE id = ? AND state='planned'")
        .bind(&source)
        .bind(bundle_id)
        .execute(pool)
        .await?;
    if let Err(e) = crate::reroute::bundle::persist_actions(pool, bundle_id, &ready).await {
        sqlx::query("UPDATE reroute_bundles SET state = 'failed', finished_at = UTC_TIMESTAMP(), failure_reason = ? WHERE id = ?")
            .bind(format!("complete action snapshot could not be persisted: {e:#}")).bind(bundle_id).execute(pool).await?;
        return Ok(vec![
            json!({"executed":false,"bundle_id":bundle_id,"blocked_reason":format!("snapshot failed before any router write: {e:#}")}),
        ]);
    }
    if let Err(block) = crate::reroute::guard::admit_bundle(pool, cfg, bundle_id, total).await {
        let message = block.to_string();
        tracing::warn!(
            event_type = "auto_bundle_not_admitted",
            rule_id = rule.id,
            bundle_id,
            total,
            reason = %message,
            "automatic activation refused whole; nothing executed"
        );
        let _ = sqlx::query(
            "UPDATE reroute_bundles SET state = 'failed', failure_reason = ?, \
                    finished_at = UTC_TIMESTAMP() WHERE id = ?",
        )
        .bind(&message)
        .bind(bundle_id)
        .execute(pool)
        .await;
        out.push(json!({
            "executed": false,
            "bundle_id": bundle_id,
            "blocked_reason": message,
            "total_actions": total,
        }));
        return Ok(out);
    }

    let outcome = port
        .run_bundle(
            pool,
            cfg,
            crate::reroute::bundle::BundleRun::automatic(bundle_id, policy, rule.id, rule_event_id),
            ready,
        )
        .await;

    out.extend(outcome.results);
    if outcome.state != "succeeded" {
        out.push(json!({
            "bundle_id": bundle_id,
            "bundle_state": outcome.state,
            "still_applied_reroute_ids": outcome.still_applied,
            "failure_reason": outcome.failure_reason,
        }));
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

/// Explicit operator reset, independent of observation-driven publication.
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

#[allow(clippy::too_many_arguments)]
async fn publish_simple_observation(
    pool: &MySqlPool,
    rule: &InterfaceRule,
    state: &str,
    first_matched: Option<Ts>,
    consecutive: u32,
    value: f64,
    obs: &Observation,
    recovery_first: Option<Ts>,
    recovery_consecutive: u32,
    event: Option<&str>,
) -> Result<()> {
    let persist_started = std::time::Instant::now();
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO rule_states(rule_id,current_state,first_matched_at,last_matched_at,consecutive_match_count,recovery_first_at,recovery_consecutive,last_metric_value,last_observation_json,last_observation_at,last_evaluated_at) VALUES(?,?,?,?,?,?,?,?,?,?,UTC_TIMESTAMP()) ON DUPLICATE KEY UPDATE current_state=VALUES(current_state),first_matched_at=VALUES(first_matched_at),last_matched_at=VALUES(last_matched_at),consecutive_match_count=VALUES(consecutive_match_count),recovery_first_at=VALUES(recovery_first_at),recovery_consecutive=VALUES(recovery_consecutive),last_metric_value=VALUES(last_metric_value),last_observation_json=VALUES(last_observation_json),last_observation_at=VALUES(last_observation_at),last_evaluated_at=UTC_TIMESTAMP()")
        .bind(rule.id).bind(state).bind(first_matched).bind(obs.sampled_at).bind(consecutive).bind(recovery_first).bind(recovery_consecutive).bind(value).bind(sqlx::types::Json(&obs.evidence)).bind(obs.sampled_at).execute(&mut *tx).await?;
    if let Some(event) = event {
        sqlx::query(
            "INSERT INTO rule_events(rule_id,event,metric_value,sampled_at) VALUES(?,?,?,?)",
        )
        .bind(rule.id)
        .bind(event)
        .bind(value)
        .bind(obs.sampled_at)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    tracing::info!(event_type="hardening_timing",stage="decision_persist",subject_id=rule.id,elapsed_us=persist_started.elapsed().as_micros() as u64,outcome="committed",observation_at=?obs.sampled_at);
    Ok(())
}

/// Recovery edge. A rule stays firing until every automatic reroute created by
/// this exact firing edge has either no rollback or a verified successful one.
#[allow(clippy::too_many_arguments)]
async fn recover_and_clear(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
    low_confidence: bool,
    source_corroborated: bool,
    evidence: &std::collections::BTreeMap<u64, Ts>,
) -> Result<()> {
    let observation = Observation {
        value,
        sampled_at,
        evidence: evidence.clone(),
        low_confidence,
        source_corroborated,
    };
    let all_owned = rule_owned_changes(pool, rule.id, false).await?;
    if !rule.automatic_revert_enabled {
        if all_owned == 0 {
            publish_simple_observation(
                pool,
                rule,
                "clear",
                None,
                0,
                value,
                &observation,
                None,
                0,
                Some("cleared"),
            )
            .await?;
            return Ok(());
        }
        publish_simple_observation(
            pool,
            rule,
            "recovered_awaiting_revert",
            None,
            0,
            value,
            &observation,
            None,
            0,
            Some("recovered_awaiting_revert"),
        )
        .await?;
        return Ok(());
    }
    if is_flow_metric(&rule.metric)
        && (!cfg.flow.automatic_actions_enabled
            || !cfg.flow.allowlist_enrolled_only
            || low_confidence
            || !source_corroborated)
    {
        publish_simple_observation(
            pool,
            rule,
            "recovered_awaiting_revert",
            None,
            0,
            value,
            &observation,
            None,
            0,
            None,
        )
        .await?;
        return Ok(());
    }
    if all_owned > 0 && rule_owned_changes(pool, rule.id, true).await? == 0 {
        publish_simple_observation(
            pool,
            rule,
            "recovered_awaiting_revert",
            None,
            0,
            value,
            &observation,
            None,
            0,
            None,
        )
        .await?;
        return Ok(());
    }
    if !publish_recovery_attempt(pool, cfg, rule, value, sampled_at, evidence).await? {
        tracing::warn!(
            event_type = "rule_recovery_pending",
            rule_id = rule.id,
            "rule remains firing until its automatic mitigations are verified rolled back"
        );
        return Ok(());
    }
    if rule_owned_changes(pool, rule.id, false).await? > 0 {
        return Ok(());
    }
    publish_simple_observation(
        pool,
        rule,
        "clear",
        None,
        0,
        value,
        &observation,
        None,
        0,
        Some("cleared"),
    )
    .await?;
    Ok(())
}

async fn rule_owned_changes(pool: &MySqlPool, rule_id: u64, eligible_only: bool) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT COUNT(*) FROM reroutes r LEFT JOIN reroute_bundles owner ON owner.id=r.bundle_id WHERE r.rule_id=? AND r.rollback_of_reroute_id IS NULL AND r.mutation_effect IN ('changed','unknown') AND (?=0 OR (r.trigger_type='automatic' AND owner.automatic_recovery_cancelled_at IS NULL)) AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=r.id AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop'))")
        .bind(rule_id).bind(eligible_only).fetch_one(pool).await?)
}

async fn publish_recovery_attempt(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
    evidence: &std::collections::BTreeMap<u64, Ts>,
) -> Result<bool> {
    let current: Option<(bool, bool)> =
        sqlx::query_as("SELECT enabled,automatic_revert_enabled FROM rules WHERE id=?")
            .bind(rule.id)
            .fetch_optional(pool)
            .await?;
    if current != Some((true, true))
        || crate::api::settings::operating_mode(pool, cfg).await != "enforce"
        || !crate::api::settings::bool_setting(
            pool,
            "automatic_actions_enabled",
            cfg.safety.automatic_actions_enabled,
        )
        .await
    {
        return Ok(false);
    }
    let originals:Vec<u64>=sqlx::query_scalar("SELECT r.id FROM reroutes r JOIN reroute_bundles owner ON owner.id=r.bundle_id WHERE r.rule_id=? AND r.trigger_type='automatic' AND r.rollback_of_reroute_id IS NULL AND r.state IN ('succeeded','failed') AND r.mutation_effect='changed' AND owner.automatic_recovery_cancelled_at IS NULL AND owner.automatic_recovery_block_reason IS NULL AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=r.id AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop')) ORDER BY r.id DESC")
        .bind(rule.id).fetch_all(pool).await?;
    if originals.is_empty() {
        return Ok(true);
    }
    let mut sources = Vec::new();
    for original in &originals {
        if let Some(source) =
            sqlx::query_scalar::<_, Option<u64>>("SELECT bundle_id FROM reroutes WHERE id=?")
                .bind(original)
                .fetch_one(pool)
                .await?
        {
            sources.push(source);
        }
    }
    sources.sort_unstable();
    sources.dedup();
    let existing:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles child ON child.id=ras.recovery_bundle_id WHERE ras.source_bundle_id IN (SELECT bundle_id FROM reroutes WHERE rule_id=? AND bundle_id IS NOT NULL) AND ras.settlement='active' AND child.state IN ('planned','running','compensating')")
        .bind(rule.id).fetch_one(pool).await?;
    if existing > 0 {
        return Ok(true);
    }
    let claim_token = format!("rule-recovery:{}", crate::auth::sessions::generate_token());
    let reason = format!("automatic recovery of rule '{}'", rule.name);
    let persist_started = std::time::Instant::now();
    let mut tx = pool.begin().await?;
    let child=sqlx::query("INSERT INTO reroute_bundles(rule_id,trigger_type,reason,state,failure_policy,total_actions,source_json) VALUES(?,'automatic',?,'planned','abort_and_compensate',?,?)")
        .bind(rule.id).bind(&reason).bind(originals.len() as u32)
        .bind(sqlx::types::Json(json!({"kind":"recovery","rule_id":rule.id,"original_reroute_ids":originals,"source_bundle_ids":sources,"preparation_phase":"published","flow_evidence_qualified":!is_flow_metric(&rule.metric) || (cfg.flow.automatic_actions_enabled && cfg.flow.allowlist_enrolled_only)})))
        .execute(&mut *tx).await?.last_insert_id();
    crate::reroute::recovery::claim_sources_for_child_on(
        &mut tx,
        child,
        &sources,
        &originals,
        &claim_token,
        false,
    )
    .await?;
    sqlx::query("UPDATE rule_states SET current_state='recovered_awaiting_revert',recovery_first_at=NULL,recovery_consecutive=0,last_metric_value=?,last_observation_json=?,last_observation_at=?,last_evaluated_at=UTC_TIMESTAMP() WHERE rule_id=?")
        .bind(value).bind(sqlx::types::Json(evidence)).bind(sampled_at).bind(rule.id).execute(&mut *tx).await?;
    let event=sqlx::query("INSERT INTO rule_events(rule_id,event,metric_value,sampled_at) VALUES(?,'recovered_awaiting_revert',?,?)")
        .bind(rule.id).bind(value).bind(sampled_at).execute(&mut *tx).await?.last_insert_id();
    sqlx::query("INSERT INTO alerts(event_type,severity,rule_id,payload_json,dedup_key) VALUES('automatic_recovery_planned','info',?,?,?)")
        .bind(rule.id).bind(sqlx::types::Json(json!({"rule_id":rule.id,"rule_event_id":event,"bundle_id":child,"original_reroute_ids":originals})))
        .bind(format!("automatic_recovery_planned:bundle:{child}")).execute(&mut *tx).await?;
    if cfg.fail_automatic_decision_before_commit {
        anyhow::bail!("injected recovery publication failure")
    }
    tx.commit().await?;
    tracing::info!(event_type="hardening_timing",stage="decision_persist",subject_id=rule.id,elapsed_us=persist_started.elapsed().as_micros() as u64,outcome="committed",observation_at=?sampled_at);
    if let Err(error) = submit_recovery_worker(pool, cfg, rule.clone(), child).await {
        tracing::error!(event_type="recovery_worker_submit_failed",rule_id=rule.id,bundle_id=child,error=%error,"durable recovery decision remains committed for startup repair");
    }
    Ok(true)
}

async fn submit_recovery_worker(
    pool: &MySqlPool,
    cfg: &Config,
    rule: InterfaceRule,
    bundle_id: u64,
) -> Result<()> {
    let port = cfg
        .automatic_work_port
        .clone()
        .unwrap_or_else(|| Arc::new(ProductionAutomaticWorkPort::new(pool)));
    submit_recovery_worker_with_port(pool, cfg, rule, bundle_id, port).await
}

async fn submit_recovery_worker_with_port(
    pool: &MySqlPool,
    cfg: &Config,
    rule: InterfaceRule,
    bundle_id: u64,
    port: Arc<dyn AutomaticWorkPort>,
) -> Result<()> {
    let claimed=sqlx::query("UPDATE reroute_bundles SET source_json=JSON_SET(source_json,'$.preparation_phase','preparing') WHERE id=? AND state='planned' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.preparation_phase'))='published'")
        .bind(bundle_id).execute(pool).await?;
    if claimed.rows_affected() != 1 {
        return Ok(());
    }
    let pool = pool.clone();
    let cfg = cfg.clone();
    let queue = cfg.automatic_work_queue.clone();
    let job_pool = pool.clone();
    let settle_pool = pool.clone();
    let future = Box::pin(async move {
        let runtime = match cfg.advisory_runtime(&pool).await {
            Ok(value) => value,
            Err(error) => {
                tracing::error!(event_type="recovery_worker_scope_failed",bundle_id,error=%error);
                settle_worker_failure(
                    &pool,
                    bundle_id,
                    JobKind::Recovery,
                    &format!("lock runtime unavailable: {error:#}"),
                )
                .await;
                return;
            }
        };
        let work = async {
            let source: sqlx::types::Json<Value> = sqlx::query_scalar(
                "SELECT source_json FROM reroute_bundles WHERE id=? AND state='planned'",
            )
            .bind(bundle_id)
            .fetch_one(&pool)
            .await?;
            let current: Option<bool> = sqlx::query_scalar(
                "SELECT automatic_revert_enabled FROM rules WHERE id=? AND enabled=1",
            )
            .bind(rule.id)
            .fetch_optional(&pool)
            .await?;
            anyhow::ensure!(
                current == Some(true),
                "automatic recovery preference changed"
            );
            anyhow::ensure!(
                crate::api::settings::operating_mode(&pool, &cfg).await == "enforce",
                "automatic recovery is no longer enforced"
            );
            anyhow::ensure!(
                crate::api::settings::bool_setting(
                    &pool,
                    "automatic_actions_enabled",
                    cfg.safety.automatic_actions_enabled
                )
                .await,
                "automatic master switch is off"
            );
            anyhow::ensure!(
                source
                    .0
                    .get("flow_evidence_qualified")
                    .and_then(Value::as_bool)
                    != Some(false),
                "flow recovery evidence is no longer qualified"
            );
            if is_flow_metric(&rule.metric) {
                let current = flow_observation(&pool, &cfg, &rule).await?;
                anyhow::ensure!(
                    current.is_some_and(|obs| !obs.low_confidence && obs.source_corroborated),
                    "flow recovery evidence became stale or uncorroborated"
                );
            }
            anyhow::ensure!(
                automatic_condition_recovery_qualified(&pool, &cfg, rule.id).await?,
                "condition recovery evidence is no longer current"
            );
            let blocked:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles owner ON owner.id=ras.source_bundle_id WHERE ras.recovery_bundle_id=? AND (owner.automatic_recovery_cancelled_at IS NOT NULL OR owner.automatic_recovery_block_reason IS NOT NULL OR owner.recovery_claim_token<>ras.claim_token)")
                .bind(bundle_id).fetch_one(&pool).await?;
            anyhow::ensure!(blocked == 0, "automatic recovery source authority changed");
            let originals = source.0["original_reroute_ids"]
                .as_array()
                .map(|ids| ids.iter().filter_map(Value::as_u64).collect::<Vec<_>>())
                .unwrap_or_default();
            let reason = format!("automatic recovery of rule '{}'", rule.name);
            let actions = port.prepare_recovery(&pool, &originals, &reason).await?;
            let device_ids = actions
                .iter()
                .map(|action| action.device_id)
                .collect::<Vec<_>>();
            let identities = port.transport_identities(&device_ids).await?;
            let fence = crate::reroute::guard::policy_fence(&pool).await?;
            let current: Option<bool> = sqlx::query_scalar(
                "SELECT automatic_revert_enabled FROM rules WHERE id=? AND enabled=1",
            )
            .bind(rule.id)
            .fetch_optional(&pool)
            .await?;
            anyhow::ensure!(
                current == Some(true)
                    && crate::api::settings::operating_mode(&pool, &cfg).await == "enforce"
                    && crate::api::settings::bool_setting(
                        &pool,
                        "automatic_actions_enabled",
                        cfg.safety.automatic_actions_enabled
                    )
                    .await,
                "automatic recovery authority changed during preparation"
            );
            anyhow::ensure!(
                automatic_condition_recovery_qualified(&pool, &cfg, rule.id).await?,
                "condition recovery evidence changed during preparation"
            );
            let blocked:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles owner ON owner.id=ras.source_bundle_id WHERE ras.recovery_bundle_id=? AND (owner.automatic_recovery_cancelled_at IS NOT NULL OR owner.automatic_recovery_block_reason IS NOT NULL OR owner.recovery_claim_token<>ras.claim_token)")
                .bind(bundle_id).fetch_one(&pool).await?;
            anyhow::ensure!(
                blocked == 0,
                "automatic recovery source authority changed during preparation"
            );
            fence.release().await?;
            let mut next = source.0;
            next["transport_identities"] = json!(identities);
            next["preparation_phase"] = json!("prepared");
            sqlx::query("UPDATE reroute_bundles SET source_json=? WHERE id=? AND state='planned'")
                .bind(sqlx::types::Json(next))
                .bind(bundle_id)
                .execute(&pool)
                .await?;
            crate::reroute::bundle::persist_actions(&pool, bundle_id, &actions).await?;
            let outcome = port
                .run_bundle(
                    &pool,
                    &cfg,
                    crate::reroute::bundle::BundleRun::automatic_recovery(
                        bundle_id,
                        crate::reroute::bundle::FailurePolicy::AbortAndCompensate,
                        rule.id,
                    ),
                    actions,
                )
                .await;
            anyhow::ensure!(
                outcome.state == "succeeded",
                "recovery ended {}",
                outcome.state
            );
            Ok::<(), anyhow::Error>(())
        };
        let result = crate::db::advisory::foreground_scope(runtime, work).await;
        if let Err(error) = result.and_then(|value| value) {
            let _ = crate::reroute::recovery::finalize_recovery_child(
                &pool,
                bundle_id,
                "failed",
                Some(&format!("{error:#}")),
                &format!("recovery:bundle:{bundle_id}"),
            )
            .await;
        }
    });
    let job = SupervisedJob {
        future,
        pool: Some(job_pool),
        bundle_id,
        kind: JobKind::Recovery,
    };
    if let Err(error) = queue.submit(job).await {
        settle_worker_failure(
            &settle_pool,
            bundle_id,
            JobKind::Recovery,
            &format!("worker submission failed: {error:#}"),
        )
        .await;
        return Err(error);
    }
    Ok(())
}

/// Roll back successful automatic reroutes from the latest firing event, in
/// reverse execution order. Uses each reroute's persisted resolved parameters,
/// never the rule's mutable action definition. Returns false while any corrective
/// action is blocked, failed, or uncertain; the next evaluation retries it.
#[allow(dead_code)]
async fn run_recovery_rollback(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
    rule_name: &str,
    actor_user_id: Option<u64>,
    _actor_context: Option<crate::reroute::executor::ActorContext>,
) -> Result<bool> {
    anyhow::ensure!(
        actor_user_id.is_none(),
        "operator recovery requires an authorized preview plan"
    );
    let current_revert: Option<bool> =
        sqlx::query_scalar("SELECT automatic_revert_enabled FROM rules WHERE id=? AND enabled=1")
            .bind(rule_id)
            .fetch_optional(pool)
            .await?;
    if current_revert != Some(true) {
        return Ok(false);
    }
    // Ownership is the durable action ledger, not the latest retained event.
    let unresolved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes r WHERE r.rule_id = ? AND r.trigger_type = 'automatic' \
         AND NOT EXISTS (SELECT 1 FROM reroute_bundles owner WHERE owner.id=r.bundle_id AND (owner.automatic_recovery_cancelled_at IS NOT NULL OR owner.automatic_recovery_block_reason IS NOT NULL)) \
         AND (r.state IN ('planned','pending','running','verifying','uncertain') \
              OR (r.state = 'succeeded' AND r.mutation_effect IN ('pending','unknown'))) \
         AND NOT EXISTS (SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id = r.id AND rb.state = 'succeeded')")
        .bind(rule_id).fetch_one(pool).await?;
    if unresolved > 0 {
        return Ok(false);
    }
    let originals: Vec<u64> = sqlx::query_scalar(
        "SELECT r.id FROM reroutes r WHERE r.rule_id = ? AND r.trigger_type = 'automatic' \
         AND NOT EXISTS (SELECT 1 FROM reroute_bundles owner WHERE owner.id=r.bundle_id AND (owner.automatic_recovery_cancelled_at IS NOT NULL OR owner.automatic_recovery_block_reason IS NOT NULL)) \
         AND r.mutation_effect = 'changed' AND r.state IN ('succeeded','failed') \
         AND NOT EXISTS (SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id = r.id AND rb.state = 'succeeded') ORDER BY r.id DESC")
        .bind(rule_id).fetch_all(pool).await?;
    if originals.is_empty() {
        return Ok(true);
    }
    if crate::api::settings::operating_mode(pool, cfg).await != "enforce" {
        return Ok(false);
    }
    if !crate::api::settings::bool_setting(
        pool,
        "automatic_actions_enabled",
        cfg.safety.automatic_actions_enabled,
    )
    .await
    {
        return Ok(false);
    }
    let policy_fence = crate::reroute::guard::policy_fence(pool).await?;
    let source_bundles:Vec<u64>=sqlx::query_scalar("SELECT DISTINCT original.bundle_id FROM reroutes original JOIN reroute_bundles owner ON owner.id=original.bundle_id WHERE original.rule_id=? AND original.trigger_type='automatic' AND original.mutation_effect='changed' AND owner.automatic_recovery_cancelled_at IS NULL AND owner.automatic_recovery_block_reason IS NULL AND NOT EXISTS(SELECT 1 FROM reroutes rb WHERE rb.rollback_of_reroute_id=original.id AND rb.state='succeeded') AND original.bundle_id IS NOT NULL ORDER BY original.bundle_id")
        .bind(rule_id).fetch_all(pool).await?;
    let claim_token = format!("rule-recovery:{}", crate::auth::sessions::generate_token());
    let reason = format!("automatic recovery of rule '{rule_name}'");
    let actions = match crate::reroute::preparation::prepare_rollbacks(
        pool, &originals, &reason, true,
    )
    .await
    {
        Ok(actions) => actions,
        Err(e) => {
            policy_fence.release().await?;
            tracing::warn!(event_type="automatic_recovery_refused",rule_id,error=%e,"recovery remains pending");
            return Ok(false);
        }
    };
    if actions.is_empty() {
        policy_fence.release().await?;
        return Ok(true);
    }
    let device_ids: Vec<_> = actions.iter().map(|a| a.device_id).collect();
    let identities = match crate::ssh::RusshExecutor::new(pool.clone())
        .transport_identities(&device_ids)
        .await
    {
        Ok(value) => value,
        Err(_e) => {
            policy_fence.release().await?;
            return Ok(false);
        }
    };
    policy_fence.release().await?;
    let policy = crate::reroute::bundle::FailurePolicy::AbortAndCompensate;
    let bundle_id = match crate::reroute::bundle::create(
        pool,
        Some(rule_id),
        None,
        "automatic",
        None,
        &reason,
        policy,
        actions.len() as u32,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            return Err(e);
        }
    };
    let setup=async {
        let mut tx=pool.begin().await?;
        crate::reroute::recovery::claim_sources_for_child_on(&mut tx,bundle_id,&source_bundles,&originals,&claim_token,false).await?;
        sqlx::query("UPDATE reroute_bundles SET source_json = ? WHERE id = ?")
            .bind(sqlx::types::Json(json!({"kind":"recovery","rule_id":rule_id,"original_reroute_ids":originals,"transport_identities":identities}))).bind(bundle_id).execute(&mut *tx).await?;
        tx.commit().await?;
        crate::reroute::bundle::persist_actions(pool,bundle_id,&actions).await
    }.await;
    if let Err(e) = setup {
        let _ = crate::reroute::recovery::finalize_recovery_child(
            pool,
            bundle_id,
            "failed",
            Some(&format!("{e:#}")),
            &format!("recovery:bundle:{bundle_id}"),
        )
        .await;
        return Err(e);
    }
    let result = crate::reroute::bundle::run(
        pool,
        cfg,
        crate::reroute::bundle::BundleRun::automatic_recovery(bundle_id, policy, rule_id),
        actions,
    )
    .await;
    Ok(result.state == "succeeded")
}

/// Reset a rule's evaluation state to clear (zeroing streaks + recovery), without
/// recording an event. Called when a rule is edited so its old match/firing
/// progress doesn't carry over against the new condition.
pub async fn reset_rule_state(pool: &MySqlPool, rule_id: u64) -> Result<()> {
    clear_state(pool, rule_id, 0.0).await
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Timelike, Utc};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use super::{flow_observation, persistence_satisfied, should_auto_execute, InterfaceRule};
    use crate::config::Config;

    #[tokio::test]
    async fn supervised_queue_drains_with_two_active_jobs() {
        let queue = super::AutomaticWorkQueue::default();
        let active = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let gate = Arc::new(tokio::sync::Notify::new());
        let done = Arc::new(tokio::sync::Notify::new());
        for _ in 0..5 {
            let active = active.clone();
            let peak = peak.clone();
            let gate = gate.clone();
            let done = done.clone();
            queue
                .submit(super::SupervisedJob {
                    future: Box::pin(async move {
                        let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                        peak.fetch_max(now, Ordering::SeqCst);
                        gate.notified().await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        done.notify_one();
                    }),
                    pool: None,
                    bundle_id: 0,
                    kind: super::JobKind::Activation,
                })
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await
            }
        })
        .await
        .unwrap();
        assert_eq!(peak.load(Ordering::SeqCst), 2);
        for _ in 0..5 {
            gate.notify_one();
            done.notified().await;
        }
        assert_eq!(active.load(Ordering::SeqCst), 0);
        queue
            .submit(super::SupervisedJob {
                future: Box::pin(async { panic!("injected worker panic") }),
                pool: None,
                bundle_id: 0,
                kind: super::JobKind::Activation,
            })
            .await
            .unwrap();
        let survived = Arc::new(tokio::sync::Notify::new());
        let signal = survived.clone();
        queue
            .submit(super::SupervisedJob {
                future: Box::pin(async move { signal.notify_one() }),
                pool: None,
                bundle_id: 0,
                kind: super::JobKind::Activation,
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), survived.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn saturated_worker_queue_refuses_without_waiting() {
        let queue = super::AutomaticWorkQueue::default();
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        for _ in 0..2 {
            let gate = gate.clone();
            let active = active.clone();
            queue
                .submit(super::SupervisedJob {
                    future: Box::pin(async move {
                        active.fetch_add(1, Ordering::SeqCst);
                        let _ = gate.acquire().await;
                    }),
                    pool: None,
                    bundle_id: 0,
                    kind: super::JobKind::Activation,
                })
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while active.load(Ordering::SeqCst) < 2 {
                tokio::task::yield_now().await
            }
        })
        .await
        .unwrap();
        for _ in 0..4096 {
            queue
                .submit(super::SupervisedJob {
                    future: Box::pin(async {}),
                    pool: None,
                    bundle_id: 0,
                    kind: super::JobKind::Activation,
                })
                .await
                .unwrap();
        }
        let started = std::time::Instant::now();
        assert!(queue
            .submit(super::SupervisedJob {
                future: Box::pin(async {}),
                pool: None,
                bundle_id: 0,
                kind: super::JobKind::Activation
            })
            .await
            .is_err());
        assert!(started.elapsed() < std::time::Duration::from_millis(50));
        gate.add_permits(2);
    }

    #[test]
    fn aggregate_progress_requires_every_member_to_advance() {
        use std::collections::BTreeMap;
        let first = Utc::now();
        let prior = serde_json::json!({"1":first,"2":first});
        let one = BTreeMap::from([(1, first + Duration::seconds(10)), (2, first)]);
        assert!(!super::evidence_advanced(Some(&prior), &one));
        let both = BTreeMap::from([
            (1, first + Duration::seconds(10)),
            (2, first + Duration::seconds(5)),
        ]);
        assert!(super::evidence_advanced(Some(&prior), &both));
        assert!(!super::evidence_advanced(Some(&prior), &BTreeMap::new()));
    }

    #[test]
    fn unavailable_error_and_status_metrics_are_not_zero_measurements() {
        let mut metrics = super::CurrentMetrics {
            sampled_at: Some(Utc::now()),
            valid_sample: true,
            rx_bps: 0.,
            tx_bps: 0.,
            rx_pps: 0.,
            tx_pps: 0.,
            rx_util_percent: 0.,
            tx_util_percent: 0.,
            in_err_rate: 30000.,
            out_err_rate: 0.,
            oper_status: None,
            in_err_rate_valid: false,
            out_err_rate_valid: false,
            oper_status_valid: false,
        };
        assert_eq!(metrics.value("in_err_rate"), None);
        assert_eq!(metrics.value("out_err_rate"), None);
        assert_eq!(metrics.value("oper_status"), None);
        assert_eq!(metrics.value("rx_bps"), Some(0.));
        metrics.out_err_rate_valid = true;
        assert_eq!(metrics.value("out_err_rate"), Some(0.));
        metrics.oper_status_valid = true;
        metrics.oper_status = Some("unknown".into());
        assert_eq!(metrics.value("oper_status"), None);
    }

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
        let test_database = crate::db::connect_test_database().await;
        let pool = (*test_database).clone();

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
        sqlx::query("UPDATE flow_publication_barrier SET registry_ready=1 WHERE id=1")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO flow_exporter_interfaces(exporter_id,device_id,interface_id,if_index,direction,first_seen_at,last_seen_at) VALUES(?,?,?,42,'ingress',?,?)")
            .bind(exporter_id).bind(device_id).bind(interface_id).bind(older).bind(latest)
            .execute(&pool).await.unwrap();
        for bucket_ts in [older, latest] {
            sqlx::query("INSERT INTO flow_bucket_quality(exporter_id,bucket_ts,iface_complete,port_complete) VALUES(?,?,1,1)")
                .bind(exporter_id).bind(bucket_ts).execute(&pool).await.unwrap();
            sqlx::query(
                "INSERT INTO flow_iface_buckets \
                 (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, \
                  pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence, pkts_available, bytes_available) \
                 VALUES (?, ?, ?, 42, 'ingress', ?, 100, 10000, 1, 1, 'high', 1, 1)",
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
              port_kind, port, pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence, pkts_available, bytes_available) \
             VALUES (?, ?, ?, 42, 'ingress', ?, 6, 'src', 443, 100, 10000, 1, 1, 'high', 1, 1)",
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
            actions_revision: 1,
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
            automatic_revert_enabled: false,
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

        // Selector absence inherits proven high sampling confidence when the
        // complete bucket is corroborated by fresh interface telemetry.
        sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_pps) VALUES(?,?,UTC_TIMESTAMP(),1,100)")
            .bind(interface_id).bind(device_id).execute(&pool).await.unwrap();
        let corroborated = flow_observation(&pool, &cfg, &rule).await.unwrap().unwrap();
        assert_eq!(corroborated.value, 0.0);
        assert!(!corroborated.low_confidence);

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
