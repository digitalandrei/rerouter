//! Reroute Guard — owns every safety gate and the atomic slot reservation, and
//! decides whether a reroute may execute.
//!
//! The decision is split into a PURE [`decide`] over [`GateInputs`] (no I/O —
//! unit-tested for gate precedence) and an async [`gather`] that reads the gate
//! facts from the database. [`reserve_and_persist`] closes the concurrent
//! double-apply race with a per-device MySQL advisory lock.
//!
//! Operating-mode (`observe`) and dry-run are NOT gates here — they return the
//! would-run plan, so the orchestration in [`super::executor`] handles them.

use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::MySqlPool;

use crate::config::Config;
use crate::detection::cooldown;
use crate::reroute::executor::ActionRequest;
use crate::reroute::locks;
use crate::reroute::templates::{RenderedPlan, Template};

/// The reason the Guard refuses a reroute. `Display` renders the exact strings
/// the executor returned before the Guard existed, so the API/UI are unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    ProtectedInterface(String),
    AutomaticDisabled,
    NoVerifyStep,
    MaintenanceLock,
    DeviceLocked,
    DeviceCooldown(DateTime<Utc>),
    RuleCooldown {
        rule_id: u64,
        until: DateTime<Utc>,
    },
    RateLimit {
        recent: i64,
        window_secs: u64,
        max: u32,
    },
    GuardConnection(String),
    GuardBusy,
    AlreadyRunning,
    UnresolvedUncertain,
    PersistFailed(String),
}

impl fmt::Display for BlockReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockReason::ProtectedInterface(iface) => write!(
                f,
                "interface '{iface}' is flagged as a protected management/transit path; \
                 disruptive interface actions on it are blocked to prevent self-lockout"
            ),
            BlockReason::AutomaticDisabled => write!(
                f,
                "automatic actions are globally disabled (automatic_actions_enabled = false)"
            ),
            BlockReason::NoVerifyStep => write!(
                f,
                "template has no verification step and reroute.require_verification is enabled"
            ),
            BlockReason::MaintenanceLock => write!(f, "global maintenance lock is active"),
            BlockReason::DeviceLocked => write!(
                f,
                "device is locked (a prior action needs admin acknowledgement)"
            ),
            BlockReason::DeviceCooldown(until) => {
                write!(f, "device is in cooldown until {}", until.to_rfc3339())
            }
            BlockReason::RuleCooldown { rule_id, until } => {
                write!(
                    f,
                    "rule {rule_id} is in cooldown until {}",
                    until.to_rfc3339()
                )
            }
            BlockReason::RateLimit {
                recent,
                window_secs,
                max,
            } => write!(
                f,
                "global action rate limit reached ({recent} in {window_secs}s; max {max})"
            ),
            BlockReason::GuardConnection(e) => write!(f, "could not acquire device guard: {e}"),
            BlockReason::GuardBusy => write!(
                f,
                "could not acquire the per-device reroute guard (another action is being set up)"
            ),
            BlockReason::AlreadyRunning => {
                write!(f, "another reroute is already running on this device")
            }
            BlockReason::UnresolvedUncertain => {
                write!(f, "an unresolved uncertain action exists on this device")
            }
            BlockReason::PersistFailed(e) => write!(f, "could not persist reroute: {e}"),
        }
    }
}

/// The facts the gates decide over, gathered once from the database.
#[derive(Debug, Clone)]
pub struct GateInputs {
    /// "manual" | "rollback" | "automatic".
    pub trigger_type: &'static str,
    /// `Some(interface_name)` when the action targets a protected path.
    pub protected_interface: Option<String>,
    pub automatic_actions_enabled: bool,
    pub has_verify_step: bool,
    pub require_verification: bool,
    pub global_maintenance_lock: bool,
    pub device_locked: bool,
    pub device_cooldown_until: Option<DateTime<Utc>>,
    pub rule_id: Option<u64>,
    pub rule_cooldown_until: Option<DateTime<Utc>>,
    pub rate_limit: u32,
    pub rate_window_secs: u64,
    pub recent_count: i64,
}

impl GateInputs {
    /// An all-clear set of inputs for `trigger_type` — a readable base for
    /// struct-update overrides in tests.
    pub fn clear(trigger_type: &'static str) -> Self {
        Self {
            trigger_type,
            protected_interface: None,
            automatic_actions_enabled: true,
            has_verify_step: true,
            require_verification: true,
            global_maintenance_lock: false,
            device_locked: false,
            device_cooldown_until: None,
            rule_id: None,
            rule_cooldown_until: None,
            rate_limit: 0,
            rate_window_secs: 600,
            recent_count: 0,
        }
    }
}

/// PURE gate decision. The order matches the executor's historical gate order,
/// so a blocked action reports the same reason it always did. No I/O.
pub fn decide(i: &GateInputs) -> Result<(), BlockReason> {
    if let Some(iface) = &i.protected_interface {
        return Err(BlockReason::ProtectedInterface(iface.clone()));
    }
    // Automatic master switch — gates AUTOMATIC triggers only.
    if i.trigger_type == "automatic" && !i.automatic_actions_enabled {
        return Err(BlockReason::AutomaticDisabled);
    }
    // Verify-or-refuse — only blocks automatic; manual/rollback run but the state
    // machine forces `uncertain` instead of claiming success.
    if i.require_verification && !i.has_verify_step && i.trigger_type == "automatic" {
        return Err(BlockReason::NoVerifyStep);
    }
    if i.global_maintenance_lock {
        return Err(BlockReason::MaintenanceLock);
    }
    if i.device_locked {
        return Err(BlockReason::DeviceLocked);
    }
    if let Some(until) = i.device_cooldown_until {
        return Err(BlockReason::DeviceCooldown(until));
    }
    if let (Some(rule_id), Some(until)) = (i.rule_id, i.rule_cooldown_until) {
        return Err(BlockReason::RuleCooldown { rule_id, until });
    }
    if i.rate_limit > 0 && i.recent_count >= i.rate_limit as i64 {
        return Err(BlockReason::RateLimit {
            recent: i.recent_count,
            window_secs: i.rate_window_secs,
            max: i.rate_limit,
        });
    }
    Ok(())
}

/// Convenience: gather the facts and decide in one call.
pub async fn can_execute(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<(), BlockReason> {
    decide(&gather(pool, cfg, req, plan).await)
}

/// Read the gate facts from the database. Mirrors the executor's previous read
/// pattern: a lock-read error fails safe (blocks); a cooldown-read error does not.
pub async fn gather(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> GateInputs {
    let device_ref = req.device_id.to_string();
    let protected_interface =
        protected_interface_name(pool, req.device_id, &req.template, &req.params).await;
    let automatic_actions_enabled = if req.trigger_type == "automatic" {
        crate::api::settings::bool_setting(
            pool,
            "automatic_actions_enabled",
            cfg.safety.automatic_actions_enabled,
        )
        .await
    } else {
        true
    };
    let global_maintenance_lock =
        crate::api::settings::bool_setting(pool, "global_maintenance_lock", false).await;
    let device_locked = locks::is_blocked(pool, "device", &device_ref)
        .await
        .unwrap_or(true);
    let device_cooldown_until = cooldown::active_until(pool, "device", &device_ref)
        .await
        .ok()
        .flatten();
    let rule_cooldown_until = match req.rule_id {
        Some(rid) => cooldown::active_until(pool, "rule", &rid.to_string())
            .await
            .ok()
            .flatten(),
        None => None,
    };
    let rate_limit = cfg.safety.global_action_rate_limit_count;
    let rate_window_secs = cfg.safety.global_action_rate_limit_window_seconds;
    let recent_count = if rate_limit > 0 {
        recent_reroute_count(pool, rate_window_secs).await
    } else {
        0
    };
    GateInputs {
        trigger_type: req.trigger_type,
        protected_interface,
        automatic_actions_enabled,
        has_verify_step: plan.verify.is_some(),
        require_verification: cfg.reroute.require_verification,
        global_maintenance_lock,
        device_locked,
        device_cooldown_until,
        rule_id: req.rule_id,
        rule_cooldown_until,
        rate_limit,
        rate_window_secs,
        recent_count,
    }
}

/// Reserve a reroute row under advisory locks. For AUTOMATIC triggers we first
/// take a single GLOBAL lock and re-check the rate limit *inside* it, so N devices
/// firing at once can't each read a stale count and collectively blow past the
/// circuit breaker (the count read in `gather` is only an early check; this is the
/// authoritative one). Then, for every trigger, we take the per-device lock and
/// re-check the device-scoped guards (already-running / uncertain) and INSERT
/// atomically. Lock order is ALWAYS global-before-device, so triggers can't deadlock.
pub async fn reserve_and_persist(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<u64, BlockReason> {
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;

    // Global rate-limit critical section — applied to AUTOMATIC triggers (the ones
    // that can fire concurrently across many devices in a storm). Held across the
    // reservation so count-then-insert is atomic vs other automatic reservations.
    // Manual/rollback are human-paced and keep only the early gather-time rate
    // check in decide(), which needs no locked re-check.
    let rate_limit = cfg.safety.global_action_rate_limit_count;
    let rate_window = cfg.safety.global_action_rate_limit_window_seconds;
    let use_global = req.trigger_type == "automatic" && rate_limit > 0;
    if use_global {
        let got: Option<i64> =
            sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK('rrt_rate_global', 5)")
                .fetch_one(&mut *conn)
                .await
                .ok()
                .flatten();
        if got != Some(1) {
            return Err(BlockReason::GuardBusy);
        }
        let recent = recent_reroute_count(pool, rate_window).await;
        if recent >= rate_limit as i64 {
            let _ = sqlx::query("SELECT RELEASE_LOCK('rrt_rate_global')")
                .execute(&mut *conn)
                .await;
            return Err(BlockReason::RateLimit {
                recent,
                window_secs: rate_window,
                max: rate_limit,
            });
        }
    }

    let lock_name = format!("reroute_dev_{}", req.device_id);
    let got: Option<i64> = sqlx::query_scalar::<_, Option<i64>>("SELECT GET_LOCK(?, 5)")
        .bind(&lock_name)
        .fetch_one(&mut *conn)
        .await
        .ok()
        .flatten();
    if got != Some(1) {
        if use_global {
            let _ = sqlx::query("SELECT RELEASE_LOCK('rrt_rate_global')")
                .execute(&mut *conn)
                .await;
        }
        return Err(BlockReason::GuardBusy);
    }

    let reserved = reserve_slot(pool, req, plan).await;

    let _ = sqlx::query("SELECT RELEASE_LOCK(?)")
        .bind(&lock_name)
        .execute(&mut *conn)
        .await;
    if use_global {
        let _ = sqlx::query("SELECT RELEASE_LOCK('rrt_rate_global')")
            .execute(&mut *conn)
            .await;
    }
    drop(conn);
    reserved
}

async fn reserve_slot(
    pool: &MySqlPool,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<u64, BlockReason> {
    if running_on_device(pool, req.device_id).await {
        return Err(BlockReason::AlreadyRunning);
    }
    if has_uncertain(pool, req.device_id).await {
        return Err(BlockReason::UnresolvedUncertain);
    }
    insert_reroute(pool, req, plan)
        .await
        .map_err(|e| BlockReason::PersistFailed(e.to_string()))
}

// ---- gather / reservation DB helpers -------------------------------------------

/// `Some(interface_name)` when a disruptive interface action targets a `protected`
/// management/transit path (so the controller can't black-hole its own path). A
/// template "targets an interface" when its parameter schema has a param with
/// `source: "interface_name"`; the value is matched against
/// `device_interfaces.if_name`/`if_descr`. Templates without such a param (BGP,
/// null-route, etc.) are never blocked; an unknown interface proceeds.
async fn protected_interface_name(
    pool: &MySqlPool,
    device_id: u64,
    template: &Template,
    params: &Value,
) -> Option<String> {
    let schema = template.parameter_schema.as_object()?;
    let iface_param = schema.iter().find_map(|(name, spec)| {
        (spec.get("source").and_then(Value::as_str) == Some("interface_name")).then(|| name.clone())
    })?;
    let iface = params
        .get(&iface_param)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?;

    let protected: Option<i64> = sqlx::query_scalar(
        "SELECT protected FROM device_interfaces \
         WHERE device_id = ? AND (if_name = ? OR if_descr = ?) ORDER BY protected DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(iface)
    .bind(iface)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    match protected {
        Some(p) if p != 0 => Some(iface.to_string()),
        _ => None,
    }
}

async fn running_on_device(pool: &MySqlPool, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state IN ('planned','pending','running','verifying')",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1);
    n > 0
}

async fn has_uncertain(pool: &MySqlPool, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state = 'uncertain'",
    )
    .bind(device_id)
    .fetch_one(pool)
    .await
    .unwrap_or(1);
    n > 0
}

/// Count reroute rows created within the last `window_secs`. On a DB error,
/// returns a large number so the breaker fails safe (blocks).
async fn recent_reroute_count(pool: &MySqlPool, window_secs: u64) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reroutes WHERE created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(window_secs as i64)
    .fetch_one(pool)
    .await
    .unwrap_or(i64::MAX)
}

async fn insert_reroute(
    pool: &MySqlPool,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> anyhow::Result<u64> {
    let steps = json!({ "commands": plan.commands, "verify": plan.verify });
    let res = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, rule_id, reroute_template_id, trigger_type, triggered_by_user_id, \
             state, reason, parameters_json, planned_steps_json) \
         VALUES (?, ?, ?, ?, ?, 'planned', ?, ?, ?)",
    )
    .bind(req.device_id)
    .bind(req.rule_id)
    .bind(req.template.id)
    .bind(req.trigger_type)
    .bind(req.user_id)
    .bind(&req.reason)
    .bind(sqlx::types::Json(&req.params))
    .bind(sqlx::types::Json(&steps))
    .execute(pool)
    .await?;
    let reroute_id = res.last_insert_id();

    for (i, cmd) in plan.commands.iter().enumerate() {
        let _ = sqlx::query(
            "INSERT INTO reroute_steps (reroute_id, step_number, description, mode, state) \
             VALUES (?, ?, ?, 'ios_ssh', 'planned')",
        )
        .bind(reroute_id)
        .bind((i + 1) as u32)
        .bind(cmd)
        .execute(pool)
        .await;
    }
    Ok(reroute_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed timestamp (no `Utc::now()` so the tests stay deterministic).
    fn ts() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    #[test]
    fn all_clear_passes() {
        assert!(decide(&GateInputs::clear("manual")).is_ok());
        assert!(decide(&GateInputs::clear("automatic")).is_ok());
        assert!(decide(&GateInputs::clear("rollback")).is_ok());
    }

    #[test]
    fn protected_interface_blocks_before_everything() {
        let i = GateInputs {
            protected_interface: Some("GigabitEthernet0/0".into()),
            global_maintenance_lock: true,
            device_locked: true,
            ..GateInputs::clear("manual")
        };
        assert_eq!(
            decide(&i),
            Err(BlockReason::ProtectedInterface("GigabitEthernet0/0".into()))
        );
    }

    #[test]
    fn automatic_master_switch_gates_automatic_only() {
        let auto = GateInputs {
            automatic_actions_enabled: false,
            ..GateInputs::clear("automatic")
        };
        assert_eq!(decide(&auto), Err(BlockReason::AutomaticDisabled));
        // Manual and rollback are not gated by the master switch.
        let manual = GateInputs {
            automatic_actions_enabled: false,
            ..GateInputs::clear("manual")
        };
        assert!(decide(&manual).is_ok());
    }

    #[test]
    fn verify_or_refuse_gates_automatic_only() {
        let auto = GateInputs {
            has_verify_step: false,
            require_verification: true,
            ..GateInputs::clear("automatic")
        };
        assert_eq!(decide(&auto), Err(BlockReason::NoVerifyStep));
        // Manual/rollback run even with no verify step.
        let manual = GateInputs {
            has_verify_step: false,
            require_verification: true,
            ..GateInputs::clear("manual")
        };
        assert!(decide(&manual).is_ok());
        // No verify step but verification not required → allowed even automatic.
        let off = GateInputs {
            has_verify_step: false,
            require_verification: false,
            ..GateInputs::clear("automatic")
        };
        assert!(decide(&off).is_ok());
    }

    #[test]
    fn device_scoped_gate_precedence() {
        // maintenance beats device lock beats device cooldown beats rule cooldown
        // beats rate limit — assert each layer wins over the next.
        let i = GateInputs {
            global_maintenance_lock: true,
            device_locked: true,
            device_cooldown_until: Some(ts()),
            ..GateInputs::clear("manual")
        };
        assert_eq!(decide(&i), Err(BlockReason::MaintenanceLock));

        let i = GateInputs {
            device_locked: true,
            device_cooldown_until: Some(ts()),
            ..GateInputs::clear("manual")
        };
        assert_eq!(decide(&i), Err(BlockReason::DeviceLocked));

        let i = GateInputs {
            device_cooldown_until: Some(ts()),
            rule_id: Some(7),
            rule_cooldown_until: Some(ts()),
            ..GateInputs::clear("manual")
        };
        assert_eq!(decide(&i), Err(BlockReason::DeviceCooldown(ts())));

        let i = GateInputs {
            rule_id: Some(7),
            rule_cooldown_until: Some(ts()),
            rate_limit: 3,
            recent_count: 99,
            ..GateInputs::clear("manual")
        };
        assert_eq!(
            decide(&i),
            Err(BlockReason::RuleCooldown {
                rule_id: 7,
                until: ts()
            })
        );
    }

    #[test]
    fn rule_cooldown_requires_a_rule_id() {
        // A rule cooldown timestamp with no rule_id is not a block.
        let i = GateInputs {
            rule_cooldown_until: Some(ts()),
            ..GateInputs::clear("manual")
        };
        assert!(decide(&i).is_ok());
    }

    #[test]
    fn rate_limit_threshold_and_disabled() {
        let block = GateInputs {
            rate_limit: 3,
            recent_count: 3,
            ..GateInputs::clear("manual")
        };
        assert_eq!(
            decide(&block),
            Err(BlockReason::RateLimit {
                recent: 3,
                window_secs: 600,
                max: 3
            })
        );
        let under = GateInputs {
            rate_limit: 3,
            recent_count: 2,
            ..GateInputs::clear("manual")
        };
        assert!(decide(&under).is_ok());
        // rate_limit == 0 disables the breaker.
        let disabled = GateInputs {
            rate_limit: 0,
            recent_count: 9999,
            ..GateInputs::clear("manual")
        };
        assert!(decide(&disabled).is_ok());
    }

    #[test]
    fn block_reason_strings_match_legacy_exactly() {
        assert_eq!(
            BlockReason::MaintenanceLock.to_string(),
            "global maintenance lock is active"
        );
        assert_eq!(
            BlockReason::DeviceLocked.to_string(),
            "device is locked (a prior action needs admin acknowledgement)"
        );
        assert_eq!(
            BlockReason::AutomaticDisabled.to_string(),
            "automatic actions are globally disabled (automatic_actions_enabled = false)"
        );
        assert_eq!(
            BlockReason::NoVerifyStep.to_string(),
            "template has no verification step and reroute.require_verification is enabled"
        );
        assert_eq!(
            BlockReason::AlreadyRunning.to_string(),
            "another reroute is already running on this device"
        );
        assert_eq!(
            BlockReason::UnresolvedUncertain.to_string(),
            "an unresolved uncertain action exists on this device"
        );
        assert_eq!(
            BlockReason::RateLimit {
                recent: 5,
                window_secs: 600,
                max: 3
            }
            .to_string(),
            "global action rate limit reached (5 in 600s; max 3)"
        );
        let until = ts();
        assert_eq!(
            BlockReason::DeviceCooldown(until).to_string(),
            format!("device is in cooldown until {}", until.to_rfc3339())
        );
        assert_eq!(
            BlockReason::RuleCooldown { rule_id: 7, until }.to_string(),
            format!("rule 7 is in cooldown until {}", until.to_rfc3339())
        );
        assert_eq!(
            BlockReason::ProtectedInterface("Gi0/0".into()).to_string(),
            "interface 'Gi0/0' is flagged as a protected management/transit path; \
             disruptive interface actions on it are blocked to prevent self-lockout"
        );
    }
}
