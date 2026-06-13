//! Interface-rule evaluation, run after every device poll.
//!
//! Stateful per rule via `rule_states` (clear -> matching -> firing) with
//! hysteresis. A rule FIRES on the rising edge once its condition has held for
//! `duration_seconds` OR `consecutive_samples` consecutive valid samples; on that
//! edge we write a `rule_events` (fired) row and INSERT an `alerts` row. While
//! firing we do not re-alert each tick. The condition clearing drops the rule
//! back toward `clear` after a `hysteresis_seconds` settle window.
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

/// One enabled interface rule with the bits the evaluator needs.
#[derive(Debug, Clone, sqlx::FromRow)]
struct InterfaceRule {
    id: u64,
    name: String,
    interface_id: u64,
    device_id: Option<u64>,
    metric: String,
    operator: String,
    threshold_value: f64,
    duration_seconds: u32,
    consecutive_samples: u32,
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

/// The prior `rule_states` row (absent => treated as clear/zero).
#[derive(Debug, Clone, Default, sqlx::FromRow)]
struct RuleStateRow {
    current_state: Option<String>,
    first_matched_at: Option<Ts>,
    last_matched_at: Option<Ts>,
    consecutive_match_count: u32,
}

/// Evaluate every enabled interface rule on `device_id` against the latest
/// metrics. Called by the scheduler right after a poll stores fresh samples.
/// Per-rule failures are logged and skipped; one bad rule never stops the rest.
pub async fn evaluate_device(pool: &MySqlPool, cfg: &Config, device_id: u64) -> Result<usize> {
    let rules = sqlx::query_as::<_, InterfaceRule>(
        "SELECT id, name, interface_id, device_id, metric, operator, threshold_value, \
                duration_seconds, consecutive_samples, severity, \
                automatic_reroute_enabled \
         FROM rules \
         WHERE enabled = 1 AND interface_id IS NOT NULL AND device_id = ?",
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

/// Evaluate a single rule and advance its state. Returns Ok(true) iff the rule
/// transitioned INTO `firing` on this evaluation (the alert edge).
async fn evaluate_rule(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Result<bool> {
    let Some(op) = Op::parse(&rule.operator) else {
        return Ok(false); // unknown operator: never matches.
    };

    let metrics = sqlx::query_as::<_, CurrentMetrics>(
        "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
                rx_util_percent, tx_util_percent, oper_status \
         FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(rule.interface_id)
    .fetch_optional(pool)
    .await?;

    let Some(metrics) = metrics else { return Ok(false) }; // no sample yet.

    // Ignore stale/invalid samples — they must not advance a rule's state.
    if !metrics.valid_sample {
        return Ok(false);
    }
    let stale_after = cfg.telemetry.stale_after_seconds as i64;
    if let Some(ts) = metrics.sampled_at {
        let age = (Utc::now() - ts).num_seconds();
        if age > stale_after {
            return Ok(false);
        }
    } else {
        return Ok(false);
    }

    let Some(value) = metrics.value(&rule.metric) else {
        return Ok(false); // unknown metric.
    };
    let matched = op.compare(value, rule.threshold_value);

    // Load prior state.
    let prev = sqlx::query_as::<_, RuleStateRow>(
        "SELECT current_state, first_matched_at, last_matched_at, consecutive_match_count \
         FROM rule_states WHERE rule_id = ?",
    )
    .bind(rule.id)
    .fetch_optional(pool)
    .await?
    .unwrap_or_default();

    let prev_state = prev.current_state.as_deref().unwrap_or("clear");
    let now = Utc::now();
    let sampled_at = metrics.sampled_at;

    if matched {
        let consecutive = prev.consecutive_match_count.saturating_add(1);
        // first_matched_at is the start of the current matching streak.
        let first_matched = prev.first_matched_at.unwrap_or(now);
        let held_secs = (now - first_matched).num_seconds();

        let duration_ok = rule.duration_seconds == 0 || held_secs >= rule.duration_seconds as i64;
        let consecutive_ok = consecutive >= rule.consecutive_samples.max(1);
        let should_fire = duration_ok || consecutive_ok;

        if should_fire && prev_state != "firing" {
            // Rising edge: fire.
            upsert_state(pool, rule.id, "firing", Some(first_matched), sampled_at, consecutive, value).await?;
            on_fire(pool, cfg, rule, value, sampled_at).await?;
            return Ok(true);
        } else if should_fire {
            // Already firing: keep firing, refresh activity (no new alert).
            upsert_state(pool, rule.id, "firing", Some(first_matched), sampled_at, consecutive, value).await?;
            return Ok(false);
        } else {
            // Matching but threshold-for-duration not yet met.
            if prev_state == "clear" {
                let _ = record_event(pool, rule, "matched", value, sampled_at).await;
            }
            upsert_state(pool, rule.id, "matching", Some(first_matched), sampled_at, consecutive, value).await?;
            return Ok(false);
        }
    }

    // Not matched this tick. Hysteresis: a firing rule only clears once the
    // settle window has elapsed since the last match (anti-flap).
    let hysteresis = cfg.detection.hysteresis_seconds as i64;
    if prev_state == "firing" {
        let since_last_match = prev
            .last_matched_at
            .map(|t| (now - t).num_seconds())
            .unwrap_or(i64::MAX);
        if since_last_match < hysteresis {
            // Still within hysteresis: hold the firing state.
            return Ok(false);
        }
        // Settled: clear.
        clear_state(pool, rule.id, value).await?;
        let _ = record_event(pool, rule, "cleared", value, sampled_at).await;
        return Ok(false);
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

/// On the firing edge: record the rule_event and enqueue the alert. In observe
/// mode (and always, since execution is gated elsewhere) the alert carries the
/// would-run plan instead of any reroute.
async fn on_fire(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
) -> Result<()> {
    record_event(pool, rule, "fired", value, sampled_at).await?;

    let mode = crate::api::settings::operating_mode(pool, cfg).await;

    // Direction phrasing for the alert body.
    let direction = match Op::parse(&rule.operator) {
        Some(Op::Lt) | Some(Op::Le) => "below",
        _ => "above",
    };

    let interface_label = interface_label(pool, rule.interface_id).await;

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

    // "The rule decides": in enforce mode, a rule with auto enabled runs its
    // actions now (gated further by the executor's locks/cooldowns). Otherwise —
    // observe mode, or a manual-only rule — we only RENDER the would-run plan.
    let auto = mode == "enforce" && rule.automatic_reroute_enabled;
    if auto {
        let executed = auto_execute_actions(pool, cfg, rule).await;
        if !executed.is_empty() {
            payload["executed_actions"] = json!(executed);
        }
    } else {
        let would_run_actions = render_would_run_actions(pool, rule.id).await;
        if !would_run_actions.is_empty() {
            payload["would_run_actions"] = json!(would_run_actions);
        }
    }

    let dedup_key = format!("rule_fired:rule:{}:iface:{}", rule.id, rule.interface_id);
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, device_id, interface_id, rule_id, payload_json, dedup_key) \
         VALUES ('rule_fired', ?, ?, ?, ?, ?, ?)",
    )
    .bind(&rule.severity)
    .bind(rule.device_id)
    .bind(rule.interface_id)
    .bind(rule.id)
    .bind(sqlx::types::Json(&payload))
    .bind(&dedup_key)
    .execute(pool)
    .await?;

    tracing::info!(
        event_type = "rule_fired",
        rule_id = rule.id,
        interface_id = rule.interface_id,
        metric = %rule.metric,
        observed = value,
        threshold = rule.threshold_value,
        mode = %mode,
        "detection rule fired (observe-safe: no reroute executed)"
    );
    Ok(())
}

/// Render every attached action of a rule (template + target router + params)
/// to its exact would-run commands, for the alert payload. Best-effort and
/// observe-safe: it loads templates and renders strings; it executes nothing.
async fn render_would_run_actions(pool: &MySqlPool, rule_id: u64) -> Vec<Value> {
    let rows = sqlx::query_as::<_, (u64, u64, String, u64, String, Option<sqlx::types::Json<Value>>)>(
        "SELECT ra.id, ra.reroute_template_id, t.name, ra.device_id, d.name, ra.params_json \
         FROM rule_actions ra \
         JOIN reroute_templates t ON t.id = ra.reroute_template_id \
         JOIN devices d ON d.id = ra.device_id \
         WHERE ra.rule_id = ? AND ra.enabled = 1 \
         ORDER BY ra.position, ra.id",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for (action_id, template_id, template_name, device_id, device_name, params_json) in rows {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        let rendered = match crate::reroute::templates::load(pool, template_id).await {
            Ok(t) => match crate::reroute::templates::render(&t, &params) {
                Ok(plan) => json!({
                    "commands": plan.commands,
                    "verify": plan.verify,
                }),
                Err(e) => json!({ "error": e.to_string() }),
            },
            Err(_) => json!({ "error": "template not found" }),
        };
        out.push(json!({
            "action_id": action_id,
            "template_id": template_id,
            "template_name": template_name,
            "device_id": device_id,
            "device_name": device_name,
            "params": params,
            "rendered": rendered,
        }));
    }
    out
}

/// Execute every attached action of a rule via the reroute executor. Called only
/// on the firing edge, only in enforce mode, only when the rule's auto switch is
/// on. The executor re-checks Gate 0 + device locks/cooldowns/uncertain, so a
/// device that's locked or recently acted on is safely skipped. Returns each
/// action's outcome for the alert payload.
async fn auto_execute_actions(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Vec<Value> {
    let specs = sqlx::query_as::<_, (u64, u64, Option<sqlx::types::Json<Value>>)>(
        "SELECT reroute_template_id, device_id, params_json FROM rule_actions \
         WHERE rule_id = ? AND enabled = 1 ORDER BY position, id",
    )
    .bind(rule.id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    let mut out = Vec::with_capacity(specs.len());
    for (template_id, device_id, params_json) in specs {
        let template = match crate::reroute::templates::load(pool, template_id).await {
            Ok(t) => t,
            Err(_) => continue,
        };
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        let req = crate::reroute::executor::ActionRequest {
            device_id,
            template,
            params,
            trigger_type: "automatic",
            rule_id: Some(rule.id),
            user_id: None,
            reason: Some(format!("automatic: rule '{}' fired", rule.name)),
        };
        let outcome = crate::reroute::executor::execute(pool, cfg, req, false).await;
        out.push(serde_json::to_value(&outcome).unwrap_or(Value::Null));
    }
    out
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
            let iface = if_name.or(if_descr).unwrap_or_else(|| format!("if#{interface_id}"));
            format!("{iface} on {device}")
        }
        None => format!("interface #{interface_id}"),
    }
}

/// Insert a rule_events row for the rule's timeline (matched / fired / cleared).
async fn record_event(
    pool: &MySqlPool,
    rule: &InterfaceRule,
    event: &str,
    value: f64,
    sampled_at: Option<Ts>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO rule_events (rule_id, event, metric_value, sampled_at) VALUES (?, ?, ?, ?)",
    )
    .bind(rule.id)
    .bind(event)
    .bind(value)
    .bind(sampled_at)
    .execute(pool)
    .await?;
    Ok(())
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
            current_state = 'clear', first_matched_at = NULL, consecutive_match_count = 0, \
            last_metric_value = VALUES(last_metric_value), last_cleared_at = UTC_TIMESTAMP(), \
            last_evaluated_at = UTC_TIMESTAMP()",
    )
    .bind(rule_id)
    .bind(value)
    .execute(pool)
    .await?;
    Ok(())
}
