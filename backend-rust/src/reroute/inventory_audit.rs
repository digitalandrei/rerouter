//! Inventory DRIFT detection and automatic disarm of AUTOMATIC execution.
//!
//! The executor re-validates every inventory-backed parameter at fire time
//! ([`super::executor`]), so a prefix-list or route-map that the router no longer
//! has is always caught before a command is pushed. But that check happens
//! *during an attack*: until then the rule looks healthy and stays armed, and the
//! operator learns their mitigation is unusable at the worst possible moment.
//!
//! This module closes that window. After a discovery run reconciles and commits
//! ([`crate::ssh::discover_prefixes_and_store`]) it re-runs the SAME read-only
//! validators over every enabled `rule_actions` row bound to that device. It
//! executes nothing — it is a dry check whose only outputs are a marker column, a
//! disarm, an audit row, an alert and a log line.
//!
//! # The safety rule that governs this whole module
//!
//! Auto-disarm may fire ONLY on a **positive, confirmed** drift signal:
//!
//! 1. the discovery read for this device was **conclusive** ([`InventoryRead`]),
//!    i.e. the router proved its current configuration; **and**
//! 2. the stored parameter genuinely no longer validates against the inventory
//!    that run just reconciled.
//!
//! It must never fire on a denied, failed, truncated or empty-but-unproven read,
//! on a stale-but-unrefreshed snapshot, or on a database error. The reason is
//! adversarial, not tidiness: anyone who can make a router return an empty or
//! failing read would otherwise be able to switch off the operator's automatic
//! mitigations — exactly what an attacker wants before a flood. So the
//! conclusive/inconclusive distinction is *threaded in from the discovery run*
//! (never re-derived here), a DB failure yields [`Verdict::Indeterminate`], and
//! every indeterminate outcome changes nothing at all.
//!
//! Disarm is also deliberately narrow: it clears `rules.automatic_reroute_enabled`
//! only. The rule stays `enabled`, so it keeps DETECTING and ALERTING, and manual
//! operator-triggered execution stays available (it still goes through preview +
//! the fire-time validation, which will refuse it with the same visible reason).
//!
//! Self-heal is likewise half a step: a later conclusive audit that passes clears
//! the drift marker, but **never re-arms**. Re-arming is a human act gated by the
//! global enable plus step-up re-auth (doctrine §8).
//!
//! # This never runs on an incident path
//!
//! Two structural rules keep the audit out of the way of a live mitigation:
//!
//! * **Nothing here is ever called from a trigger path.** The single caller is
//!   [`crate::ssh::discover_prefixes_and_store`], driven by the background
//!   discovery loop and by the operator's explicit "Discover prefixes" button.
//!   Inventory is never refreshed inline just before firing: under a volumetric
//!   attack the router's control plane is the saturated resource, SSH is the first
//!   thing to go slow, and the executor already has cheaper, stricter liveness
//!   gates (the reachability probe plus
//!   [`super::reachability::STABILITY_WINDOW`]).
//! * **A device or rule that is mid-incident is skipped entirely**, so a discovery
//!   run that happens to land while a rule is firing cannot disarm the very rule
//!   that is mitigating. The next run re-checks. See [`device_is_quiet`] and the
//!   `current_state` guard in [`audit_device`].

use std::collections::BTreeSet;

use anyhow::Result;
use serde_json::{json, Value};
use sqlx::MySqlPool;

use super::templates::{self, ROUTING_INVENTORY_MAX_AGE_HOURS};

/// `rule_actions.inventory_drift_reason` / `rules.auto_disarmed_reason` width.
const REASON_MAX: usize = 500;

/// Did the discovery run that just finished PROVE this device's routing state,
/// or did it only fail to disprove it?
///
/// This is produced by the discovery run itself (which owns the distinction) and
/// passed in. It is never inferred from the database, because the database looks
/// identical in both cases: an inconclusive run deliberately leaves the previous
/// snapshot untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryRead {
    /// Every read succeeded, was not denied, and produced a snapshot that was
    /// reconciled into the database in this run. Only this value may disarm.
    Conclusive,
    /// Denied, failed, truncated, or empty-but-unproven. The previous snapshot
    /// was kept; nothing may be concluded from it. The `&'static str` is the
    /// machine-readable reason, logged so the skip is diagnosable.
    Inconclusive(&'static str),
}

impl InventoryRead {
    fn reason(self) -> Option<&'static str> {
        match self {
            InventoryRead::Conclusive => None,
            InventoryRead::Inconclusive(reason) => Some(reason),
        }
    }
}

/// What one audit pass did. Returned for logging and for tests; the durable
/// record is the marker columns, the audit rows and the alerts.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AuditSummary {
    /// The read was inconclusive, so no action was examined at all.
    pub skipped: bool,
    pub audited: usize,
    /// Actions that transitioned ok -> drifted in this pass.
    pub newly_drifted: usize,
    /// Actions that transitioned drifted -> ok in this pass.
    pub recovered: usize,
    /// Rules whose `automatic_reroute_enabled` this pass switched off.
    pub rules_disarmed: usize,
    /// Actions whose verdict could not be established (DB failure). Nothing was
    /// written for these.
    pub indeterminate: usize,
    /// Actions left alone because their rule is mid-incident (matching/firing).
    /// Re-checked on the next discovery run.
    pub deferred: usize,
    /// The whole device was skipped because a reroute is in flight on it.
    pub device_busy: bool,
}

/// Why one stored parameter set did or did not survive the fresh inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Verdict {
    /// Still validates. (Clears a previous drift marker; never re-arms.)
    Valid,
    /// The validator positively REFUSED it against freshly reconciled inventory.
    /// This is the only verdict that may mark or disarm.
    Drifted(String),
    /// Infrastructure failure — a database error, or a template that could not be
    /// loaded. Decides nothing: not drift, not recovery.
    Indeterminate(String),
}

#[derive(sqlx::FromRow)]
struct ActionRow {
    id: u64,
    rule_id: u64,
    rule_name: String,
    rule_enabled: bool,
    automatic_reroute_enabled: bool,
    reroute_template_id: u64,
    params_json: Option<sqlx::types::Json<Value>>,
    inventory_state: String,
    /// `rule_states.current_state` (clear / matching / firing), NULL when the rule
    /// has never been evaluated. Anything other than `clear` means an incident is
    /// in progress for this rule and the audit leaves it completely alone.
    current_state: Option<String>,
}

/// Audit every enabled rule action bound to `device_id` against the inventory a
/// discovery run just reconciled, and disarm automatic execution where a stored
/// parameter no longer validates.
///
/// Never executes anything. Never fails the discovery run: the caller logs the
/// error and the database is left exactly as it was (every write is transactional
/// and per-action).
pub async fn audit_device(
    pool: &MySqlPool,
    device_id: u64,
    read: InventoryRead,
) -> Result<AuditSummary> {
    // The expiry check runs whatever the read said — its entire purpose is to
    // notice that discovery has NOT been succeeding, which is precisely the
    // inconclusive case.
    if let Err(e) = alert_on_expired_inventory(pool, device_id).await {
        tracing::warn!(event_type = "routing_inventory_expiry_check_failed", device_id, error = %e, "could not check routing-inventory expiry");
    }

    if let Some(reason) = read.reason() {
        tracing::info!(
            event_type = "inventory_drift_audit_skipped",
            device_id,
            reason,
            "routing read was inconclusive — no drift conclusions drawn, nothing changed"
        );
        return Ok(AuditSummary {
            skipped: true,
            ..AuditSummary::default()
        });
    }

    // Structural interlock #1: a reroute in flight on this device means a
    // mitigation is being applied or verified right now. Nothing is audited,
    // nothing is marked, nothing is disarmed — the next run re-checks.
    if !device_is_quiet(pool, device_id).await? {
        tracing::info!(
            event_type = "inventory_drift_audit_deferred",
            device_id,
            reason = "reroute_in_flight",
            "a reroute is in flight on this device — drift audit deferred to the next discovery run"
        );
        return Ok(AuditSummary {
            device_busy: true,
            ..AuditSummary::default()
        });
    }

    let actions = sqlx::query_as::<_, ActionRow>(
        "SELECT ra.id, ra.rule_id, r.name AS rule_name, r.enabled AS rule_enabled, \
                r.automatic_reroute_enabled, ra.reroute_template_id, ra.params_json, \
                ra.inventory_state, rs.current_state \
           FROM rule_actions ra \
           JOIN rules r ON r.id = ra.rule_id \
           LEFT JOIN rule_states rs ON rs.rule_id = r.id \
          WHERE ra.device_id = ? AND ra.enabled = 1 \
          ORDER BY ra.id",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await?;

    let mut summary = AuditSummary::default();
    for action in &actions {
        // Structural interlock #2: the rule is matching or already firing, i.e.
        // this action is part of a mitigation that is happening now. Disarming it
        // here would switch off the protection mid-incident, so the audit does not
        // even evaluate it and simply comes back next run.
        if let Some(state) = action.current_state.as_deref() {
            if state != "clear" {
                summary.deferred += 1;
                tracing::info!(
                    event_type = "inventory_drift_audit_deferred",
                    device_id,
                    rule_id = action.rule_id,
                    rule_action_id = action.id,
                    rule_state = state,
                    "rule is mid-incident — drift audit deferred to the next discovery run"
                );
                continue;
            }
        }
        summary.audited += 1;
        match verdict(pool, device_id, action).await {
            Verdict::Valid => match clear_drift(pool, device_id, action).await {
                Ok(true) => summary.recovered += 1,
                Ok(false) => {}
                Err(e) => {
                    summary.indeterminate += 1;
                    tracing::warn!(event_type = "inventory_drift_write_failed", device_id, rule_action_id = action.id, error = %e, "could not record a clean inventory audit; nothing changed");
                }
            },
            Verdict::Drifted(reason) => {
                match record_drift(pool, device_id, action, &reason).await {
                    Ok((marked, disarmed)) => {
                        summary.newly_drifted += usize::from(marked);
                        summary.rules_disarmed += usize::from(disarmed);
                    }
                    Err(e) => {
                        summary.indeterminate += 1;
                        tracing::error!(event_type = "inventory_drift_write_failed", device_id, rule_action_id = action.id, error = %e, "CONFIRMED drift could not be persisted; the rule is unchanged and still armed");
                    }
                }
            }
            Verdict::Indeterminate(detail) => {
                summary.indeterminate += 1;
                tracing::warn!(event_type = "inventory_drift_indeterminate", device_id, rule_action_id = action.id, rule_id = action.rule_id, detail = %detail, "could not establish an inventory verdict — no drift concluded, nothing changed");
            }
        }
    }

    tracing::info!(
        event_type = "inventory_drift_audit",
        device_id,
        audited = summary.audited,
        newly_drifted = summary.newly_drifted,
        recovered = summary.recovered,
        rules_disarmed = summary.rules_disarmed,
        indeterminate = summary.indeterminate,
        deferred = summary.deferred,
        "inventory drift audit finished"
    );
    Ok(summary)
}

/// True when no reroute is in flight on this device.
///
/// Deliberately the same in-flight state set the executor's own
/// `running_on_device` gate uses (`planned`/`pending`/`running`/`verifying`), so
/// "the executor would refuse a new action here" and "the audit stays out of the
/// way here" can never disagree. A DB error propagates: an unknown answer must
/// abort the audit, never license it.
async fn device_is_quiet(pool: &MySqlPool, device_id: u64) -> Result<bool> {
    let in_flight: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? \
           AND state IN ('planned','pending','running','verifying')",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await?;
    Ok(in_flight == 0)
}

/// Re-run the read-only executor validators over one action's STORED parameters.
/// Mirrors `executor::execute_with` exactly (canonicalize, then prefix
/// containment) so a clean verdict here means the same check will pass at fire
/// time — and a drifted verdict means it would be refused.
async fn verdict(pool: &MySqlPool, device_id: u64, action: &ActionRow) -> Verdict {
    let template = match templates::load(pool, action.reroute_template_id).await {
        Ok(t) => t,
        Err(e) => return Verdict::Indeterminate(format!("could not load template: {e}")),
    };
    let params = action
        .params_json
        .as_ref()
        .map(|j| j.0.clone())
        .unwrap_or(Value::Null);

    let canonical =
        match templates::canonicalize_inventory_params(pool, device_id, &template, &params).await {
            Ok(v) => v,
            Err(e) if is_infrastructure(&e) => return Verdict::Indeterminate(e.to_string()),
            Err(e) => return Verdict::Drifted(e.to_string()),
        };
    match templates::prefix_target_is_contained(pool, device_id, &template, &canonical).await {
        Ok(true) => Verdict::Valid,
        Ok(false) => {
            Verdict::Drifted("prefix target is outside the device's announced space".into())
        }
        Err(e) if is_infrastructure(&e) => Verdict::Indeterminate(e.to_string()),
        Err(e) => Verdict::Drifted(e.to_string()),
    }
}

/// True when a validator failure came from the DATABASE rather than from the
/// device's configuration. A `sqlx::Error` anywhere in the chain means we never
/// learned what the router looks like, so the failure must decide nothing —
/// otherwise a database hiccup would disarm live mitigations.
fn is_infrastructure(e: &anyhow::Error) -> bool {
    e.chain().any(|c| c.is::<sqlx::Error>())
}

/// Persist a CONFIRMED drift: mark the action, disarm only the owning rule's
/// automatic execution, audit, and alert — all in one transaction, so a partial
/// write can never leave a rule disarmed with nobody told (or told with nothing
/// disarmed). Returns `(newly_marked, newly_disarmed)`.
async fn record_drift(
    pool: &MySqlPool,
    device_id: u64,
    action: &ActionRow,
    reason: &str,
) -> Result<(bool, bool)> {
    let reason = clip(reason, REASON_MAX);
    let newly_marked = action.inventory_state != "drifted";

    // begin()/commit() only: MySQL 8.x cannot PREPARE `START TRANSACTION`.
    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE rule_actions SET inventory_state = 'drifted', inventory_drift_reason = ?, \
                inventory_checked_at = UTC_TIMESTAMP() \
          WHERE id = ?",
    )
    .bind(&reason)
    .bind(action.id)
    .execute(&mut *tx)
    .await?;

    // ONLY automatic execution. `rules.enabled` is untouched on purpose: the rule
    // must keep detecting and alerting, and manual execution stays available.
    let disarm_reason = clip(
        &format!("routing inventory drift on action #{}: {reason}", action.id),
        REASON_MAX,
    );
    let disarmed = sqlx::query(
        "UPDATE rules SET automatic_reroute_enabled = 0, auto_disarmed_at = UTC_TIMESTAMP(), \
                auto_disarmed_reason = ? \
          WHERE id = ? AND automatic_reroute_enabled = 1",
    )
    .bind(&disarm_reason)
    .bind(action.rule_id)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;

    if !newly_marked && !disarmed {
        // Still drifted, still disarmed, same reason — re-alerting every run would
        // train operators to ignore the alert. The refreshed
        // `inventory_checked_at` above is the record that the audit ran.
        tx.commit().await?;
        return Ok((false, false));
    }

    let payload = json!({
        "rule_id": action.rule_id,
        "rule_name": action.rule_name,
        "rule_action_id": action.id,
        "device_id": device_id,
        "device_name": device_name(pool, device_id).await,
        "template_id": action.reroute_template_id,
        "reason": reason,
        "automatic_reroute_disarmed": disarmed,
        "rule_still_enabled": action.rule_enabled,
        "operator_action": "the stored parameter no longer matches the router's configuration; \
    fix the action (or the router) and re-arm automatic execution by hand — the rule keeps detecting \
    and alerting, and manual execution remains available",
    });
    let (event_type, severity) = if disarmed {
        ("rule_auto_disarmed", "critical")
    } else {
        ("rule_action_inventory_drift", "warning")
    };
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, device_id, rule_id, payload_json, dedup_key) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(event_type)
    .bind(severity)
    .bind(device_id)
    .bind(action.rule_id)
    .bind(sqlx::types::Json(&payload))
    .bind(format!("{event_type}:rule_action:{}", action.id))
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO audit_logs \
            (actor_type, event_type, entity_type, entity_id, message, after_json) \
         VALUES ('system', 'rule_action_inventory_drift', 'rule_action', ?, ?, ?)",
    )
    .bind(action.id)
    .bind(clip(
        &format!(
            "rule '{}' action #{} on device {device_id} no longer validates: {reason}",
            action.rule_name, action.id
        ),
        1000,
    ))
    .bind(sqlx::types::Json(&payload))
    .execute(&mut *tx)
    .await?;

    if disarmed {
        sqlx::query(
            "INSERT INTO audit_logs \
                (actor_type, event_type, entity_type, entity_id, message, after_json) \
             VALUES ('system', 'rule_auto_disarmed', 'rule', ?, ?, ?)",
        )
        .bind(action.rule_id)
        .bind(clip(&format!(
            "automatic execution disarmed for rule '{}' (rule stays enabled; detection and alerting continue): {reason}",
            action.rule_name
        ), 1000))
        .bind(sqlx::types::Json(&payload))
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;

    if newly_marked {
        tracing::warn!(
            event_type = "rule_action_inventory_drift",
            device_id,
            rule_id = action.rule_id,
            rule_action_id = action.id,
            template_id = action.reroute_template_id,
            reason = %reason,
            "stored reroute parameter no longer validates against freshly discovered inventory"
        );
    }
    if disarmed {
        tracing::warn!(
            event_type = "rule_auto_disarmed",
            device_id,
            rule_id = action.rule_id,
            rule_action_id = action.id,
            reason = %reason,
            "AUTOMATIC execution disarmed for this rule; detection, alerting and manual execution are unaffected"
        );
    }
    Ok((newly_marked, disarmed))
}

/// Record a clean audit. Clears a previous drift marker but **never re-arms**:
/// `automatic_reroute_enabled` and the `auto_disarmed_*` record are left exactly
/// as they are until a human re-arms through the normal gate. Returns true when
/// this pass actually cleared a drift.
async fn clear_drift(pool: &MySqlPool, device_id: u64, action: &ActionRow) -> Result<bool> {
    if action.inventory_state != "drifted" {
        sqlx::query("UPDATE rule_actions SET inventory_checked_at = UTC_TIMESTAMP() WHERE id = ?")
            .bind(action.id)
            .execute(pool)
            .await?;
        return Ok(false);
    }

    let mut tx = pool.begin().await?;
    sqlx::query(
        "UPDATE rule_actions SET inventory_state = 'ok', inventory_drift_reason = NULL, \
                inventory_checked_at = UTC_TIMESTAMP() \
          WHERE id = ?",
    )
    .bind(action.id)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO audit_logs \
            (actor_type, event_type, entity_type, entity_id, message, after_json) \
         VALUES ('system', 'rule_action_inventory_recovered', 'rule_action', ?, ?, ?)",
    )
    .bind(action.id)
    .bind(clip(&format!(
        "rule '{}' action #{} validates again against discovered inventory; automatic execution stays OFF until re-armed by an operator",
        action.rule_name, action.id
    ), 1000))
    .bind(sqlx::types::Json(json!({
        "rule_id": action.rule_id,
        "rule_action_id": action.id,
        "device_id": device_id,
        "automatic_reroute_enabled": action.automatic_reroute_enabled,
        "re_armed": false,
    })))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    tracing::info!(
        event_type = "rule_action_inventory_recovered",
        device_id,
        rule_id = action.rule_id,
        rule_action_id = action.id,
        "inventory drift cleared; automatic execution deliberately NOT re-armed"
    );
    Ok(true)
}

/// The freshness marker each inventory `source` is actually gated on, as a
/// (source, column, literal query) triple. The SQL is a compile-time constant —
/// never built from input.
const MARKERS: &[(&str, &str, &str)] = &[
    (
        "peer_out_prefix_list",
        "device_bgp_peers.route_context_discovered_at",
        "SELECT MAX(route_context_discovered_at) FROM device_bgp_peers WHERE device_id = ?",
    ),
    (
        "route_map",
        "device_route_maps.last_discovered_at",
        "SELECT MAX(last_discovered_at) FROM device_route_maps WHERE device_id = ?",
    ),
    (
        "announced_prefix",
        "device_bgp_networks.last_discovered_at",
        "SELECT MAX(last_discovered_at) FROM device_bgp_networks WHERE device_id = ?",
    ),
];

/// Alert (never disarm) when a device's SSH-discovered routing inventory has aged
/// past the validator window while enabled rules still depend on it.
///
/// Without this, two consecutive failed discovery runs silently age the route
/// context out and every dependent action starts being refused at fire time with
/// nobody told. Expiry is NOT drift — the router never said anything — so it
/// changes no state: it only pages.
async fn alert_on_expired_inventory(pool: &MySqlPool, device_id: u64) -> Result<()> {
    let (sources, rules) = dependent_sources(pool, device_id).await?;
    if sources.is_empty() {
        return Ok(());
    }

    let mut expired: Vec<Value> = Vec::new();
    for (source, column, sql) in MARKERS {
        if !sources.contains(*source) {
            continue;
        }
        let discovered_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(sql)
            .bind(device_id)
            .fetch_one(pool)
            .await?;
        let age_hours = discovered_at
            .map(|t| (chrono::Utc::now() - t).num_hours())
            .unwrap_or(i64::MAX);
        if age_hours >= ROUTING_INVENTORY_MAX_AGE_HOURS {
            expired.push(json!({
                "source": source,
                "column": column,
                "discovered_at": discovered_at.map(|t| t.to_rfc3339()),
                "age_hours": if discovered_at.is_some() { Some(age_hours) } else { None },
            }));
        }
    }
    if expired.is_empty() {
        return Ok(());
    }

    let rule_names: Vec<&str> = rules.iter().map(|(_, n)| n.as_str()).collect();
    tracing::warn!(
        event_type = "routing_inventory_expired",
        device_id,
        expired = expired.len(),
        dependent_rules = rules.len(),
        max_age_hours = ROUTING_INVENTORY_MAX_AGE_HOURS,
        "SSH-discovered routing inventory aged past the validator window; dependent actions will be REFUSED at fire time"
    );
    let payload = json!({
        "device_id": device_id,
        "device_name": device_name(pool, device_id).await,
        "max_age_hours": ROUTING_INVENTORY_MAX_AGE_HOURS,
        "expired": expired,
        "dependent_rule_ids": rules.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        "dependent_rules": rule_names,
        "operator_action": "SSH discovery has not succeeded for this device inside the validator \
    window; dependent reroute actions will be refused at fire time. Check device reachability and the \
    router account's read access, then re-run Discover prefixes.",
    });
    sqlx::query(
        "INSERT INTO alerts (event_type, severity, device_id, payload_json, dedup_key) \
         VALUES ('routing_inventory_expired', 'critical', ?, ?, ?)",
    )
    .bind(device_id)
    .bind(sqlx::types::Json(&payload))
    .bind(format!("routing_inventory_expired:device:{device_id}"))
    .execute(pool)
    .await?;
    Ok(())
}

/// The inventory `source` annotations that this device's enabled rule actions
/// depend on, plus the (id, name) of the rules that depend on them.
async fn dependent_sources(
    pool: &MySqlPool,
    device_id: u64,
) -> Result<(BTreeSet<String>, Vec<(u64, String)>)> {
    let rows = sqlx::query_as::<_, (u64, String, String, Option<sqlx::types::Json<Value>>)>(
        "SELECT r.id, r.name, t.name, t.parameter_schema_json \
           FROM rule_actions ra \
           JOIN rules r ON r.id = ra.rule_id \
           JOIN reroute_templates t ON t.id = ra.reroute_template_id \
          WHERE ra.device_id = ? AND ra.enabled = 1 AND r.enabled = 1",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await?;

    let mut sources = BTreeSet::new();
    let mut rules: Vec<(u64, String)> = Vec::new();
    for (rule_id, rule_name, template_name, schema) in rows {
        let mut relevant = false;
        if let Some(obj) = schema.as_ref().and_then(|j| j.0.as_object()) {
            for spec in obj.values() {
                if let Some(source) = spec.get("source").and_then(Value::as_str) {
                    if MARKERS.iter().any(|(s, _, _)| *s == source) {
                        sources.insert(source.to_string());
                        relevant = true;
                    }
                }
            }
        }
        // Null0/RTBH templates depend on freshly discovered announced space via
        // `prefix_target_is_contained`, not via a schema `source` annotation.
        if templates::requires_announced_prefix_containment(&template_name) {
            sources.insert("announced_prefix".to_string());
            relevant = true;
        }
        if relevant && !rules.iter().any(|(id, _)| *id == rule_id) {
            rules.push((rule_id, rule_name));
        }
    }
    Ok((sources, rules))
}

async fn device_name(pool: &MySqlPool, device_id: u64) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT name FROM devices WHERE id = ?")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

/// Truncate to `max` BYTES without splitting a UTF-8 character, so a long
/// validator message can never blow the VARCHAR and lose the whole write.
fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inconclusive_reads_carry_a_reason_and_conclusive_ones_do_not() {
        assert_eq!(InventoryRead::Conclusive.reason(), None);
        assert_eq!(
            InventoryRead::Inconclusive("route_map_discovery_denied").reason(),
            Some("route_map_discovery_denied")
        );
    }

    #[test]
    fn a_database_failure_is_infrastructure_and_never_drift() {
        let db = anyhow::Error::new(sqlx::Error::PoolClosed).context("loading reroute template");
        assert!(is_infrastructure(&db));

        let router =
            anyhow::anyhow!("prefix-list 'pfx-to-viva' is not attached to peer 23.45.23.197");
        assert!(!is_infrastructure(&router));
    }

    /// HARD constraint: inventory discovery is a background job, never something a
    /// trigger path waits on. During a volumetric attack the router's control
    /// plane is the saturated resource and SSH is the first thing to go slow, so an
    /// inline "refresh inventory before we fire" would spend incident time badly
    /// and could stall a mitigation behind a 60s russh inactivity timeout. Liveness
    /// is already covered by the reachability probe and
    /// [`super::super::reachability::STABILITY_WINDOW`].
    ///
    /// This lint keeps the call graph that way: only the scheduler's background
    /// loop and the operator's explicit endpoint may call discovery.
    #[test]
    fn discovery_is_never_called_from_a_trigger_path() {
        const ALLOWED: &[&str] = &["scheduler.rs", "api/devices.rs"];
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        collect_rs(&src, &mut files);
        assert!(!files.is_empty(), "no source files found under {src:?}");

        // Built at runtime so this lint's own source does not match it.
        let needle = format!("::{}(", "discover_prefixes_and_store");
        let mut offenders = Vec::new();
        for file in &files {
            let rel = file
                .strip_prefix(&src)
                .unwrap_or(file)
                .to_string_lossy()
                .replace('\\', "/");
            if ALLOWED.contains(&rel.as_str()) {
                continue;
            }
            let text = std::fs::read_to_string(file).expect("read source file");
            for (idx, line) in text.lines().enumerate() {
                // Doc links (`[`crate::ssh::…`]`) carry no call parenthesis.
                if line.contains(&needle) && !line.trim_start().starts_with("//") {
                    offenders.push(format!("{rel}:{}", idx + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "SSH inventory discovery may only be driven by the background scheduler \
             loop or the operator's explicit endpoint — never inline on a path that \
             leads to a mitigation:\n{}",
            offenders.join("\n"),
        );
    }

    fn collect_rs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    #[test]
    fn reasons_are_clipped_on_a_character_boundary() {
        assert_eq!(clip("short", REASON_MAX), "short");
        let long = "é".repeat(400); // 800 bytes
        let clipped = clip(&long, REASON_MAX);
        assert!(clipped.len() <= REASON_MAX);
        assert!(long.starts_with(&clipped));
    }
}
