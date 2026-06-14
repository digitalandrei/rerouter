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
}

/// One enabled interface rule with the bits the evaluator needs.
#[derive(Debug, Clone, sqlx::FromRow)]
struct InterfaceRule {
    id: u64,
    name: String,
    interface_id: u64,
    device_id: Option<u64>,
    metric: String,
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
        "SELECT id, name, interface_id, device_id, metric, \
                flow_direction, flow_protocol, flow_port, flow_port_kind, \
                operator, threshold_value, \
                duration_seconds, consecutive_samples, \
                recovery_mode, recovery_threshold_value, recovery_window_seconds, \
                recovery_consecutive_samples, severity, \
                automatic_reroute_enabled \
         FROM rules \
         WHERE enabled = 1 AND interface_id IS NOT NULL AND device_id = ? \
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

/// Evaluate a single rule and advance its state. Returns Ok(true) iff the rule
/// transitioned INTO `firing` on this evaluation (the alert edge).
async fn evaluate_rule(pool: &MySqlPool, cfg: &Config, rule: &InterfaceRule) -> Result<bool> {
    let Some(op) = Op::parse(&rule.operator) else {
        return Ok(false); // unknown operator: never matches.
    };

    // Source the reading from flow buckets or interface metrics. Either path
    // returns None for no/stale/invalid sample (which must not advance state).
    let obs = if is_flow_metric(&rule.metric) {
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
        let duration_ok = rule.duration_seconds == 0 || held_secs >= rule.duration_seconds as i64;
        let consecutive_ok =
            rule.consecutive_samples == 0 || consecutive >= rule.consecutive_samples;
        let should_fire = duration_ok && consecutive_ok;

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
            on_fire(pool, cfg, rule, value, sampled_at, obs.low_confidence).await?;
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
                let _ = record_event(pool, rule, "matched", value, sampled_at).await;
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
    let metrics = sqlx::query_as::<_, CurrentMetrics>(
        "SELECT sampled_at, valid_sample, rx_bps, tx_bps, rx_pps, tx_pps, \
                rx_util_percent, tx_util_percent, oper_status \
         FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(rule.interface_id)
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
    }))
}

/// Read a flow-derived metric (flow_pps / flow_bps) from the latest CLOSED flow
/// bucket matching the rule's (interface, direction[, protocol][, port])
/// selector. Counts are sampling-scaled (estimated). None when there is no flow
/// data for the selector or the newest bucket is stale. `low_confidence` is set
/// when the sampling rate behind the estimate is unverified.
async fn flow_observation(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
) -> Result<Option<Observation>> {
    let bucket_secs = cfg.flow.bucket_seconds.max(1) as f64;
    let direction = rule.flow_direction.as_deref().unwrap_or("ingress");

    // (est_pkts, est_bytes, low_conf flag, latest bucket_ts) — all NULL if the
    // selector matched no rows.
    type Agg = (Option<u64>, Option<u64>, Option<u64>, Option<Ts>);
    let agg = "CAST(SUM(pkts * effective_sampling_rate) AS UNSIGNED), \
               CAST(SUM(bytes * effective_sampling_rate) AS UNSIGNED), \
               CAST(MAX(sampling_confidence = 'low') AS UNSIGNED)";

    let row: Agg = if let Some(port) = rule.flow_port {
        let port_kind = rule.flow_port_kind.as_deref().unwrap_or("dst");
        sqlx::query_as(&format!(
            "SELECT {agg}, MAX(bucket_ts) FROM flow_port_buckets \
             WHERE interface_id = ? AND direction = ? AND port_kind = ? AND port = ? \
               AND (? IS NULL OR protocol = ?) \
               AND bucket_ts = (SELECT MAX(bucket_ts) FROM flow_port_buckets \
                  WHERE interface_id = ? AND direction = ? AND port_kind = ? AND port = ? \
                    AND (? IS NULL OR protocol = ?))"
        ))
        .bind(rule.interface_id)
        .bind(direction)
        .bind(port_kind)
        .bind(port)
        .bind(rule.flow_protocol)
        .bind(rule.flow_protocol)
        .bind(rule.interface_id)
        .bind(direction)
        .bind(port_kind)
        .bind(port)
        .bind(rule.flow_protocol)
        .bind(rule.flow_protocol)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_as(&format!(
            "SELECT {agg}, MAX(bucket_ts) FROM flow_iface_buckets \
             WHERE interface_id = ? AND direction = ? \
               AND bucket_ts = (SELECT MAX(bucket_ts) FROM flow_iface_buckets \
                  WHERE interface_id = ? AND direction = ?)"
        ))
        .bind(rule.interface_id)
        .bind(direction)
        .bind(rule.interface_id)
        .bind(direction)
        .fetch_one(pool)
        .await?
    };

    let (est_pkts, est_bytes, low_conf, bucket_ts) = row;
    let Some(bucket_ts) = bucket_ts else {
        return Ok(None);
    }; // no flow data for the selector.

    // Flow buckets lag (bucket close + flush), so allow a wider staleness window
    // than the SNMP path — a few bucket widths.
    let flow_stale =
        (cfg.flow.bucket_seconds as i64 * 3).max(cfg.telemetry.stale_after_seconds as i64);
    if (Utc::now() - bucket_ts).num_seconds() > flow_stale {
        return Ok(None);
    }

    let value = match rule.metric.as_str() {
        "flow_pps" => est_pkts.unwrap_or(0) as f64 / bucket_secs,
        "flow_bps" => est_bytes.unwrap_or(0) as f64 * 8.0 / bucket_secs,
        _ => return Ok(None),
    };
    // Unknown confidence is treated as low (cautious): never auto-act on it.
    Ok(Some(Observation {
        value,
        sampled_at: Some(bucket_ts),
        low_confidence: low_conf.unwrap_or(1) != 0,
    }))
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

    // For a flow rule, surface the selector + that the value is a sampled estimate.
    if is_flow_metric(&rule.metric) {
        payload["flow_selector"] = json!({
            "flow_direction": rule.flow_direction,
            "flow_protocol": rule.flow_protocol,
            "flow_port": rule.flow_port,
            "flow_port_kind": rule.flow_port_kind,
        });
        payload["flow_estimated"] = json!(true);
        payload["sampling_low_confidence"] = json!(low_confidence);
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
            "flow rule fired but auto-action suppressed: low sampling confidence"
        );
    }
    let auto = should_auto_execute(
        mode == "enforce",
        global_auto,
        rule.automatic_reroute_enabled,
        low_confidence,
    );
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
    let rows = sqlx::query_as::<
        _,
        (
            u64,
            u64,
            String,
            u64,
            String,
            Option<sqlx::types::Json<Value>>,
        ),
    >(
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
            let iface = if_name
                .or(if_descr)
                .unwrap_or_else(|| format!("if#{interface_id}"));
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

/// Recovery edge: clear the rule, record the cleared event, and — if the rule
/// auto-executed mitigations (enforce mode + the rule's auto switch) — run the
/// rollback (the "no ..." inverse) of each action. Observe mode never executes,
/// so it never rolls back.
async fn recover_and_clear(
    pool: &MySqlPool,
    cfg: &Config,
    rule: &InterfaceRule,
    value: f64,
    sampled_at: Option<Ts>,
) -> Result<()> {
    clear_state(pool, rule.id, value).await?;
    let _ = record_event(pool, rule, "cleared", value, sampled_at).await;
    run_recovery_rollback(
        pool,
        cfg,
        rule.id,
        &rule.name,
        rule.automatic_reroute_enabled,
    )
    .await;
    Ok(())
}

/// Run the rollback of every action attached to a rule, in reverse order. Gated
/// exactly like auto-execution: only in enforce mode and only when the rule's
/// auto switch is on. The executor re-checks its own safety gates per action.
async fn run_recovery_rollback(
    pool: &MySqlPool,
    cfg: &Config,
    rule_id: u64,
    rule_name: &str,
    auto_enabled: bool,
) {
    if !auto_enabled {
        return;
    }
    let mode = crate::api::settings::operating_mode(pool, cfg).await;
    if mode != "enforce" {
        return;
    }
    let specs = sqlx::query_as::<_, (u64, u64, Option<sqlx::types::Json<Value>>)>(
        "SELECT reroute_template_id, device_id, params_json FROM rule_actions \
         WHERE rule_id = ? AND enabled = 1 ORDER BY position DESC, id DESC",
    )
    .bind(rule_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (template_id, device_id, params_json) in specs {
        let params = params_json.map(|j| j.0).unwrap_or(Value::Null);
        let reason = format!("automatic rollback: rule '{rule_name}' recovered");
        match crate::reroute::rollback::rollback_of(
            pool,
            cfg,
            device_id,
            template_id,
            &params,
            None,
            reason,
        )
        .await
        {
            Some(_) => tracing::info!(
                event_type = "rule_recovery_rollback",
                rule_id,
                device_id,
                template_id,
                "ran rollback on recovery"
            ),
            None => tracing::debug!(
                event_type = "rule_recovery_no_rollback",
                rule_id,
                template_id,
                "action template has no rollback; nothing to undo"
            ),
        }
    }
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
pub async fn clear_rule_manual(pool: &MySqlPool, cfg: &Config, rule_id: u64) -> Result<bool> {
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
    // The rule's name + auto switch, for the rollback reason + gate.
    let meta: Option<(String, bool)> =
        sqlx::query_as("SELECT name, automatic_reroute_enabled FROM rules WHERE id = ?")
            .bind(rule_id)
            .fetch_optional(pool)
            .await?;
    let (name, auto_enabled) = meta.unwrap_or_else(|| (format!("#{rule_id}"), false));

    clear_state(pool, rule_id, 0.0).await?;
    sqlx::query("INSERT INTO rule_events (rule_id, event, metric_value, sampled_at) VALUES (?, 'cleared', NULL, NULL)")
        .bind(rule_id)
        .execute(pool)
        .await?;
    tracing::info!(
        event_type = "rule_cleared_manual",
        rule_id,
        "rule manually cleared by operator"
    );
    run_recovery_rollback(pool, cfg, rule_id, &name, auto_enabled).await;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::should_auto_execute;

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
}
