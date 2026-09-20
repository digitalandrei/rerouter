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
use sqlx::{Connection, MySqlConnection, MySqlPool};

use crate::config::Config;
use crate::detection::cooldown;
use crate::reroute::executor::ActionRequest;
use crate::reroute::locks;
use crate::reroute::templates::{RenderedPlan, Template};

#[derive(Debug, Clone)]
enum RateScope {
    Routing {
        limit: u32,
        window: u64,
    },
    ConfigurationOnly {
        device_id: u64,
        limit: u32,
        window: u64,
    },
}

async fn bundle_rate_scope(
    pool: &MySqlPool,
    cfg: &Config,
    bundle_id: u64,
) -> Result<RateScope, BlockReason> {
    let row: Option<(Option<String>, Option<u64>)> = sqlx::query_as(
        "SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.verification_mode')) AS CHAR), MIN(a.device_id) FROM reroute_bundles b LEFT JOIN reroute_bundle_actions a ON a.bundle_id=b.id WHERE b.id=? GROUP BY b.id",
    ).bind(bundle_id).fetch_optional(pool).await.map_err(|e|BlockReason::GateReadFailed(e.to_string()))?;
    let (mode, device_id) =
        row.ok_or_else(|| BlockReason::GateReadFailed("bundle missing".into()))?;
    if mode.as_deref() == Some("configuration_only") {
        let device_id = device_id.ok_or_else(|| {
            BlockReason::GateReadFailed("configuration-only bundle has no device".into())
        })?;
        let invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=? AND (device_id<>? OR COALESCE(JSON_UNQUOTE(JSON_EXTRACT(prepared_action_json,'$.verification_mode')),'routing')<>'configuration_only')")
            .bind(bundle_id).bind(device_id).fetch_one(pool).await.map_err(|e|BlockReason::GateReadFailed(e.to_string()))?;
        if invalid != 0 {
            return Err(BlockReason::GateReadFailed(
                "configuration-only bundle ledger has mixed scope or targets".into(),
            ));
        }
        let rate_override = cfg
            .safety
            .configuration_test_devices
            .iter()
            .find(|d| d.device_id == device_id);
        Ok(RateScope::ConfigurationOnly {
            device_id,
            limit: rate_override
                .map(|device| device.action_rate_limit_count)
                .unwrap_or(crate::config::DEFAULT_CONFIGURATION_ONLY_ACTION_RATE_LIMIT_COUNT),
            window: rate_override
                .map(|device| device.action_rate_limit_window_seconds)
                .unwrap_or(
                    crate::config::DEFAULT_CONFIGURATION_ONLY_ACTION_RATE_LIMIT_WINDOW_SECONDS,
                ),
        })
    } else if mode.as_deref().is_none() || mode.as_deref() == Some("routing") {
        let invalid: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=? AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(prepared_action_json,'$.verification_mode')),'routing')<>'routing'")
            .bind(bundle_id).fetch_one(pool).await.map_err(|e|BlockReason::GateReadFailed(e.to_string()))?;
        if invalid != 0 {
            return Err(BlockReason::GateReadFailed(
                "routing bundle ledger has mixed verification scope".into(),
            ));
        }
        Ok(RateScope::Routing {
            limit: cfg.safety.global_action_rate_limit_count,
            window: cfg.safety.global_action_rate_limit_window_seconds,
        })
    } else {
        Err(BlockReason::GateReadFailed(
            "bundle has unknown verification scope".into(),
        ))
    }
}

fn rate_values(scope: &RateScope) -> (u32, u64, String) {
    match scope {
        RateScope::Routing { limit, window } => (*limit, *window, "20:reroute:rate-global".into()),
        RateScope::ConfigurationOnly {
            device_id,
            limit,
            window,
        } => (
            *limit,
            *window,
            format!("20:reroute:rate-config-only:{device_id}"),
        ),
    }
}

/// Cross-component policy fence backed by the current bounded advisory-lock
/// operation. Nested gates reuse that operation's one database session.
pub struct PolicyFence {
    guard: Option<crate::db::advisory::AdvisoryGuard>,
}

impl PolicyFence {
    pub async fn release(mut self) -> anyhow::Result<()> {
        if let Some(guard) = self.guard.take() {
            guard.release().await?;
        }
        Ok(())
    }
}

/// Acquire the policy fence used by both actuation and safety-policy mutations.
/// The caller must keep the returned guard alive through exact verification.
pub async fn policy_fence(_pool: &MySqlPool) -> anyhow::Result<PolicyFence> {
    Ok(PolicyFence {
        guard: Some(crate::db::advisory::acquire("10:execution:policy").await?),
    })
}

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
    GateReadFailed(String),
    GuardConnection(String),
    GuardBusy,
    AlreadyRunning,
    UnresolvedUncertain,
    DeviceUnreachable(String),
    DeviceStabilizing,
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
            BlockReason::GateReadFailed(e) => {
                write!(f, "could not verify a safety gate: {e}")
            }
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
            BlockReason::DeviceUnreachable(detail) => write!(
                f,
                "device is not reachable over SSH for a mitigation ({detail}); a reroute pushes \
                 config over SSH, so it is refused up front rather than failing mid-push"
            ),
            BlockReason::DeviceStabilizing => write!(
                f,
                "device has not been continuously SSH-reachable long enough (stabilizing); \
                 automatic mitigations resume after 5 minutes of continuous reachability. \
                 A manual reroute is still allowed."
            ),
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
    // A rollback is corrective work. Locks and maintenance mode still gate it,
    // but throttles created by the original action must not prevent its inverse.
    if i.trigger_type != "rollback" {
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
    decide(&gather(pool, cfg, req, plan).await?)
}

/// Read the gate facts from the database. Mirrors the executor's previous read
/// pattern: every safety-read error fails safe and blocks execution.
pub async fn gather(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<GateInputs, BlockReason> {
    let device_ref = req.device_id.to_string();
    let corrective_interface = prepared_corrective_interface(pool, req)
        .await
        .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?;
    let protected_interface = if corrective_interface {
        None
    } else {
        protected_interface_name(pool, req.device_id, &req.template, &req.params)
            .await
            .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?
    };
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
    let administratively_locked = locks::is_blocked(pool, "device", &device_ref)
        .await
        .unwrap_or(true);
    let owner_token = req.authorization.as_ref().map(|a| a.owner_token.as_str());
    let change_window_locked = !locks::change_window_allows(pool, req.device_id, owner_token)
        .await
        .unwrap_or(false);
    let device_locked = administratively_locked || change_window_locked;
    let device_cooldown_until = effective_cooldown(
        pool,
        "device",
        &device_ref,
        req.device_id,
        None,
        cfg.safety.same_device_cooldown_seconds,
        req.bundle.map(|b| b.bundle_id),
    )
    .await
    .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?;
    let rule_cooldown_until = match req.rule_id {
        Some(rid) => effective_cooldown(
            pool,
            "rule",
            &rid.to_string(),
            req.device_id,
            Some(rid),
            cfg.safety.same_rule_cooldown_seconds,
            req.bundle.map(|b| b.bundle_id),
        )
        .await
        .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?,
        None => None,
    };
    let rate_limit = cfg.safety.global_action_rate_limit_count;
    let rate_window_secs = cfg.safety.global_action_rate_limit_window_seconds;
    let recent_count = if rate_limit > 0 && req.bundle.is_none() {
        let recent = recent_reroute_count(pool, rate_window_secs, None).await;
        let reserved = outstanding_bundle_actions_pool(pool, rate_window_secs, None).await;
        recent.saturating_add(reserved)
    } else {
        0
    };
    Ok(GateInputs {
        trigger_type: req.trigger_type,
        protected_interface,
        automatic_actions_enabled,
        has_verify_step: plan.verify.is_some() || req.authorization.is_some(),
        require_verification: cfg.reroute.require_verification,
        global_maintenance_lock,
        device_locked,
        device_cooldown_until,
        rule_id: req.rule_id,
        rule_cooldown_until,
        rate_limit,
        rate_window_secs,
        recent_count,
    })
}

fn corrective_interface_state(states: &[crate::reroute::device_plan::DeviceStateSnapshot]) -> bool {
    let mut saw_interface = false;
    for state in states {
        match state {
            crate::reroute::device_plan::DeviceStateSnapshot::InterfaceAdmin {
                shutdown: false,
                ..
            }
            | crate::reroute::device_plan::DeviceStateSnapshot::InterfaceMss {
                mss: None, ..
            } => saw_interface = true,
            crate::reroute::device_plan::DeviceStateSnapshot::InterfaceAdmin {
                shutdown: true,
                ..
            }
            | crate::reroute::device_plan::DeviceStateSnapshot::InterfaceMss {
                mss: Some(_), ..
            } => return false,
            _ => {}
        }
    }
    saw_interface
}

async fn prepared_corrective_interface(
    pool: &MySqlPool,
    req: &ActionRequest,
) -> anyhow::Result<bool> {
    let Some(auth) = req.authorization.as_ref() else {
        return Ok(false);
    };
    if let Some(action_id) = auth.snapshot_action_id {
        let prepared: Option<sqlx::types::Json<Value>> = sqlx::query_scalar(
            "SELECT prepared_action_json FROM reroute_bundle_actions WHERE id = ?",
        )
        .bind(action_id)
        .fetch_optional(pool)
        .await?;
        let Some(prepared) = prepared else {
            return Ok(false);
        };
        let prepared: crate::reroute::device_plan::PreparedDeviceAction =
            serde_json::from_value(prepared.0)?;
        return Ok(corrective_interface_state(&prepared.after));
    }
    if auth.kind == crate::reroute::executor::ExecutionAuthorityKind::Compensation {
        let original_id = req
            .rollback_of_reroute_id
            .ok_or_else(|| anyhow::anyhow!("compensation has no original action"))?;
        let inverse: Option<sqlx::types::Json<Value>> =
            sqlx::query_scalar("SELECT rollback_snapshot_json FROM reroutes WHERE id = ?")
                .bind(original_id)
                .fetch_optional(pool)
                .await?;
        let inverse: crate::reroute::device_plan::PreparedInverse = serde_json::from_value(
            inverse
                .ok_or_else(|| anyhow::anyhow!("original action has no prepared inverse"))?
                .0,
        )?;
        return Ok(corrective_interface_state(&inverse.restore));
    }
    Ok(false)
}

/// Cooldown rows are convenient bookkeeping, but the durable reroute history is
/// the fallback source of truth. This prevents a post-action cooldown INSERT
/// failure from permitting an immediate repeat.
///
/// `exclude_bundle` names the bundle this action belongs to. Its own earlier
/// siblings are ONE authorized activation, already previewed and confirmed
/// together, so they must not throttle each other — otherwise the first sibling's
/// `started_at` blocks the remaining thirteen (audit SPEC-13). Nothing else is
/// exempted: unrelated activations on the same rule or device still throttle
/// normally, and an explicit cooldown row is never bypassed, because a deferred
/// bundle writes no such row until the whole batch is done.
async fn effective_cooldown(
    pool: &MySqlPool,
    scope: &str,
    scope_ref: &str,
    device_id: u64,
    rule_id: Option<u64>,
    seconds: u64,
    exclude_bundle: Option<u64>,
) -> anyhow::Result<Option<DateTime<Utc>>> {
    if seconds == 0 {
        return Ok(None);
    }
    let explicit = cooldown::active_until(pool, scope, scope_ref).await?;
    // NULL `exclude_bundle` must not swallow standalone rows, whose `bundle_id`
    // is also NULL — hence the explicit `? IS NULL` arm rather than `<>`.
    let historical: Option<DateTime<Utc>> = if let Some(rule_id) = rule_id {
        sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT DATE_ADD(MAX(started_at), INTERVAL ? SECOND) FROM reroutes \
             WHERE rule_id = ? AND started_at IS NOT NULL \
               AND (? IS NULL OR bundle_id IS NULL OR bundle_id <> ?)",
        )
        .bind(seconds as i64)
        .bind(rule_id)
        .bind(exclude_bundle)
        .bind(exclude_bundle)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
            "SELECT DATE_ADD(MAX(started_at), INTERVAL ? SECOND) FROM reroutes \
             WHERE device_id = ? AND started_at IS NOT NULL \
               AND (? IS NULL OR bundle_id IS NULL OR bundle_id <> ?)",
        )
        .bind(seconds as i64)
        .bind(device_id)
        .bind(exclude_bundle)
        .bind(exclude_bundle)
        .fetch_one(pool)
        .await?
    };
    Ok([explicit, historical]
        .into_iter()
        .flatten()
        .filter(|until| *until > Utc::now())
        .max())
}

/// Admit a whole bundle against the global rate budget, ALL-OR-NOTHING.
///
/// The budget is still spent per action — a 14-action bundle costs 14 — but it is
/// spent atomically before anything runs. Today the budget is consumed mid-bundle,
/// so a bundle larger than the remaining budget applies part of a mitigation and
/// is then refused, which for an ISP-withdraw/scrubber-advertise pair is the
/// black-hole case. Refusing the bundle whole is the safe failure.
///
/// Reserved-but-unrun capacity of other in-flight bundles counts too, so two
/// concurrent bundles cannot both be admitted against the same free budget.
///
/// Returns the remaining budget check as a [`BlockReason::RateLimit`] when the
/// bundle does not fit. A deployment that routinely runs bundles larger than
/// `global_action_rate_limit_count` must raise that setting deliberately; this
/// function will not quietly stretch it.
pub async fn admit_bundle(
    pool: &MySqlPool,
    cfg: &Config,
    bundle_id: u64,
    size: u32,
) -> Result<(), BlockReason> {
    let runtime = cfg
        .advisory_runtime(pool)
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    // Erase the very large guard future at this public scope boundary. These
    // entry points are also called from the executor's already-large future;
    // embedding the inner state machine there can overflow ordinary worker
    // thread stacks before the first database await is polled.
    crate::db::advisory::foreground_scope(
        runtime,
        Box::pin(admit_bundle_inner(pool, cfg, bundle_id, size)),
    )
    .await
    .map_err(|e| BlockReason::GuardConnection(e.to_string()))?
}

async fn admit_bundle_inner(
    pool: &MySqlPool,
    cfg: &Config,
    bundle_id: u64,
    size: u32,
) -> Result<(), BlockReason> {
    let scope = bundle_rate_scope(pool, cfg, bundle_id).await?;
    let (limit, window, rate_lock_suffix) = rate_values(&scope);
    if limit == 0 {
        return Ok(());
    }
    let rate_guard = crate::db::advisory::acquire(&rate_lock_suffix)
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;

    let lab_device = match scope {
        RateScope::ConfigurationOnly { device_id, .. } => Some(device_id),
        _ => None,
    };
    let already = scoped_recent_reroute_count(&mut conn, window, Some(bundle_id), lab_device).await;
    let outstanding =
        scoped_outstanding_bundle_actions(&mut conn, window, bundle_id, lab_device).await;
    let projected = already.saturating_add(outstanding);
    if projected.saturating_add(size as i64) > limit as i64 {
        rate_guard
            .release()
            .await
            .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
        return Err(BlockReason::RateLimit {
            recent: projected,
            window_secs: window,
            max: limit,
        });
    }
    let reserved = sqlx::query(
        "UPDATE reroute_bundles SET rate_reserved_actions = ? \
         WHERE id = ? AND state = 'planned' AND rate_reserved_actions = 0",
    )
    .bind(size)
    .bind(bundle_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| BlockReason::PersistFailed(e.to_string()))?;
    if reserved.rows_affected() != 1 {
        let existing: Option<u32> =
            sqlx::query_scalar("SELECT rate_reserved_actions FROM reroute_bundles WHERE id = ?")
                .bind(bundle_id)
                .fetch_optional(&mut *conn)
                .await
                .map_err(|e| BlockReason::PersistFailed(e.to_string()))?;
        if existing != Some(size) {
            rate_guard
                .release()
                .await
                .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
            return Err(BlockReason::PersistFailed(
                "bundle was not in an admissible planned state".into(),
            ));
        }
    }
    rate_guard
        .release()
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    Ok(())
}

/// Scoped recent action count. Fails closed on a read error.
async fn scoped_recent_reroute_count(
    conn: &mut MySqlConnection,
    window_secs: u64,
    exclude_bundle: Option<u64>,
    lab_device: Option<u64>,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reroutes r LEFT JOIN reroute_bundles b ON b.id=r.bundle_id \
         WHERE r.created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND) \
           AND (? IS NULL OR r.bundle_id IS NULL OR r.bundle_id<>?) \
           AND (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(r.planned_steps_json,'$.verification_mode')),JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.verification_mode')),'routing')='configuration_only')=? \
           AND (? IS NULL OR r.device_id=?)",
    )
    .bind(window_secs as i64).bind(exclude_bundle).bind(exclude_bundle).bind(lab_device.is_some()).bind(lab_device).bind(lab_device)
    .fetch_one(&mut *conn).await.unwrap_or(i64::MAX)
}

async fn scoped_outstanding_bundle_actions(
    conn: &mut MySqlConnection,
    window_secs: u64,
    exclude_bundle: u64,
    lab_device: Option<u64>,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT CAST(COALESCE(SUM(CAST(rate_reserved_actions AS SIGNED)),0) AS SIGNED) FROM reroute_bundles \
         WHERE state IN ('planned','running','compensating') AND id<>? \
           AND created_at>DATE_SUB(UTC_TIMESTAMP(),INTERVAL ? SECOND) \
           AND (COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')='configuration_only')=? \
           AND (? IS NULL OR EXISTS(SELECT 1 FROM reroute_bundle_actions a WHERE a.bundle_id=reroute_bundles.id AND a.device_id=?))",
    )
    .bind(exclude_bundle).bind(window_secs as i64).bind(lab_device.is_some()).bind(lab_device).bind(lab_device)
    .fetch_one(&mut *conn).await.unwrap_or(i64::MAX)
}

async fn outstanding_bundle_actions_pool(
    pool: &MySqlPool,
    window_secs: u64,
    exclude_bundle: Option<u64>,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT CAST(COALESCE(SUM(CAST(rate_reserved_actions AS SIGNED)), 0) AS SIGNED) \
           FROM reroute_bundles \
          WHERE state IN ('planned', 'running', 'compensating') \
            AND (? IS NULL OR id <> ?) \
            AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')<>'configuration_only' \
            AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(exclude_bundle)
    .bind(exclude_bundle)
    .bind(window_secs as i64)
    .fetch_one(pool)
    .await
    .unwrap_or(i64::MAX)
}

async fn outstanding_bundle_actions_pool_on(
    conn: &mut MySqlConnection,
    window_secs: u64,
    exclude_bundle: Option<u64>,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT CAST(COALESCE(SUM(CAST(rate_reserved_actions AS SIGNED)), 0) AS SIGNED) \
           FROM reroute_bundles \
          WHERE state IN ('planned', 'running', 'compensating') \
            AND (? IS NULL OR id <> ?) \
            AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')<>'configuration_only' \
            AND created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)",
    )
    .bind(exclude_bundle)
    .bind(exclude_bundle)
    .bind(window_secs as i64)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(i64::MAX)
}

/// Reserve a reroute row under advisory locks. For AUTOMATIC triggers we first
/// take a single GLOBAL lock and re-check the rate limit *inside* it, so N devices
/// firing at once can't each read a stale count and collectively blow past the
/// circuit breaker (the count read in `gather` is only an early check; this is the
/// authoritative one). Then, for every trigger, we take the per-device lock and
/// re-check the device-scoped guards (already-running / uncertain) and INSERT
/// atomically. Those re-checks also repeat the global maintenance lock and the
/// per-device admin lock, so an admin lock set after the lock-free early check
/// still stops the action at this last gate. Lock order is ALWAYS
/// global-before-device, so triggers can't deadlock.
pub async fn reserve_and_persist(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<u64, BlockReason> {
    let runtime = cfg
        .advisory_runtime(pool)
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    // Keep the public runtime boundary small when this is nested inside the
    // executor and compensation futures.
    crate::db::advisory::foreground_scope(
        runtime,
        Box::pin(reserve_and_persist_inner(pool, cfg, req, plan)),
    )
    .await
    .map_err(|e| BlockReason::GuardConnection(e.to_string()))?
}

async fn reserve_and_persist_inner(
    pool: &MySqlPool,
    cfg: &Config,
    req: &ActionRequest,
    plan: &RenderedPlan,
) -> Result<u64, BlockReason> {
    let rate_scope = match req.bundle {
        Some(bundle) => bundle_rate_scope(pool, cfg, bundle.bundle_id).await?,
        None => RateScope::Routing {
            limit: cfg.safety.global_action_rate_limit_count,
            window: cfg.safety.global_action_rate_limit_window_seconds,
        },
    };
    let (rate_limit, rate_window, rate_lock_suffix) = rate_values(&rate_scope);
    // Global rate-limit critical section. Every non-corrective trigger participates
    // so concurrent manual and automatic requests share one authoritative budget.
    let use_global = req.trigger_type != "rollback" && rate_limit > 0;
    let mut rate_guard = if use_global {
        Some(
            crate::db::advisory::acquire(&rate_lock_suffix)
                .await
                .map_err(|e| BlockReason::GuardConnection(e.to_string()))?,
        )
    } else {
        None
    };
    // Never consume an application-data connection while waiting for bounded
    // advisory capacity or the server-side lock.
    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    if use_global {
        let lab_device = match rate_scope {
            RateScope::ConfigurationOnly { device_id, .. } => Some(device_id),
            _ => None,
        };
        let recent = scoped_recent_reroute_count(
            &mut conn,
            rate_window,
            req.bundle.map(|b| b.bundle_id),
            lab_device,
        )
        .await;
        let reserved_elsewhere = if lab_device.is_some() {
            scoped_outstanding_bundle_actions(
                &mut conn,
                rate_window,
                req.bundle.map(|b| b.bundle_id).unwrap_or(0),
                lab_device,
            )
            .await
        } else {
            outstanding_bundle_actions_pool_on(
                &mut conn,
                rate_window,
                req.bundle.map(|b| b.bundle_id),
            )
            .await
        };
        let projected = recent.saturating_add(reserved_elsewhere);
        let own_reserved = if let Some(bundle) = req.bundle {
            sqlx::query_scalar::<_, u32>(
                "SELECT rate_reserved_actions FROM reroute_bundles WHERE id = ?",
            )
            .bind(bundle.bundle_id)
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten()
            .unwrap_or(0)
        } else {
            0
        };
        if (req.bundle.is_some() && own_reserved == 0)
            || (req.bundle.is_none() && projected >= rate_limit as i64)
        {
            if let Some(guard) = rate_guard.take() {
                guard
                    .release()
                    .await
                    .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
            }
            return Err(BlockReason::RateLimit {
                recent: projected,
                window_secs: rate_window,
                max: rate_limit,
            });
        }
    }

    let device_guard =
        crate::db::advisory::acquire(&format!("30:reroute:device:{}", req.device_id))
            .await
            .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;

    let reserved = reserve_slot(&mut conn, req, plan, use_global).await;
    device_guard
        .release()
        .await
        .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    if let Some(guard) = rate_guard {
        guard
            .release()
            .await
            .map_err(|e| BlockReason::GuardConnection(e.to_string()))?;
    }
    drop(conn);
    reserved
}

async fn reserve_slot(
    conn: &mut MySqlConnection,
    req: &ActionRequest,
    plan: &RenderedPlan,
    consume_bundle_reservation: bool,
) -> Result<u64, BlockReason> {
    // Authoritative re-check under the advisory lock: an admin lock set after the
    // lock-free early check must still stop this action (same pattern as the
    // global rate limit above). Both reads fail closed.
    let maintenance = sqlx::query_scalar::<_, String>(
        "SELECT `value` FROM system_settings WHERE `key`='global_maintenance_lock'",
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?
    .is_some_and(|value| matches!(value.as_str(), "true" | "1" | "yes" | "on"));
    if maintenance {
        return Err(BlockReason::MaintenanceLock);
    }
    let blocked:i64=sqlx::query_scalar("SELECT COUNT(*) FROM locks WHERE cleared_at IS NULL AND (scope='global' OR (scope='device' AND scope_ref=?))")
        .bind(req.device_id.to_string()).fetch_one(&mut *conn).await.map_err(|e|BlockReason::GateReadFailed(e.to_string()))?;
    if blocked > 0 {
        return Err(BlockReason::DeviceLocked);
    }
    let owner_token = req
        .authorization
        .as_ref()
        .map(|auth| auth.owner_token.as_str());
    let window_owner: Option<String> =
        sqlx::query_scalar("SELECT owner_token FROM device_change_windows WHERE device_id=?")
            .bind(req.device_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| BlockReason::GateReadFailed(e.to_string()))?;
    if window_owner.is_some_and(|owner| owner_token != Some(owner.as_str())) {
        return Err(BlockReason::DeviceLocked);
    }
    if running_on_device(conn, req.device_id).await {
        return Err(BlockReason::AlreadyRunning);
    }
    if has_uncertain(conn, req.device_id).await {
        return Err(BlockReason::UnresolvedUncertain);
    }
    if let Some(original_id) = req.rollback_of_reroute_id {
        let inverse_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reroutes \
             WHERE rollback_of_reroute_id = ? \
               AND state IN ('planned','pending','running','verifying','succeeded')",
        )
        .bind(original_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(1);
        if inverse_exists > 0 {
            return Err(BlockReason::AlreadyRunning);
        }
    }
    insert_reroute(conn, req, plan, consume_bundle_reservation)
        .await
        .map_err(|e| BlockReason::PersistFailed(e.to_string()))
}

// ---- gather / reservation DB helpers -------------------------------------------

/// `Some(interface_name)` when a disruptive interface action targets a `protected`
/// management/transit path (so the controller can't black-hole its own path). A
/// template "targets an interface" when its parameter schema has a param with
/// `source: "interface_name"`; the value is matched against
/// `device_interfaces.if_name`/`if_descr`. Templates without such a param (BGP,
/// null-route, etc.) are never blocked. Unknown interface inventory fails closed
/// for disruptive actions; the explicit corrective templates above bypass it.
async fn protected_interface_name(
    pool: &MySqlPool,
    device_id: u64,
    template: &Template,
    params: &Value,
) -> anyhow::Result<Option<String>> {
    // These are corrective inverses. Their disruptive counterparts remain
    // protected, including when invoked as a rollback of a prior corrective action.
    if matches!(
        template.name.as_str(),
        "iface_no_shutdown" | "iface_tcp_adjust_mss_remove"
    ) {
        return Ok(None);
    }
    let Some(schema) = template.parameter_schema.as_object() else {
        return Ok(None);
    };
    let iface_param = schema.iter().find_map(|(name, spec)| {
        (spec.get("source").and_then(Value::as_str) == Some("interface_name")).then(|| name.clone())
    });
    let Some(iface_param) = iface_param else {
        return Ok(None);
    };
    let iface = params
        .get(&iface_param)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(iface) = iface else {
        return Ok(None);
    };

    let row: Option<(Option<String>, i64)> = sqlx::query_as(
        "SELECT if_name, protected FROM device_interfaces \
         WHERE device_id = ? AND (if_name = ? OR if_descr = ?) ORDER BY protected DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(iface)
    .bind(iface)
    .fetch_optional(pool)
    .await?;

    let (canonical_name, protected) =
        row.ok_or_else(|| anyhow::anyhow!("interface '{iface}' is no longer in device inventory"))?;
    Ok(match protected {
        p if p != 0 => Some(canonical_name.unwrap_or_else(|| iface.to_string())),
        _ => None,
    })
}

async fn running_on_device(conn: &mut MySqlConnection, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state IN ('planned','pending','running','verifying')",
    )
    .bind(device_id)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(1);
    n > 0
}

async fn has_uncertain(conn: &mut MySqlConnection, device_id: u64) -> bool {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE device_id = ? AND state = 'uncertain'",
    )
    .bind(device_id)
    .fetch_one(&mut *conn)
    .await
    .unwrap_or(1);
    n > 0
}

/// Count reroute rows created within the last `window_secs`. On a DB error,
/// returns a large number so the breaker fails safe (blocks).
///
/// A bundle reserves its FULL size against the budget once, at admission
/// ([`admit_bundle`]), so its siblings must not each re-consume it as they run —
/// hence `exclude_bundle`. The budget is still spent per action; it is merely
/// spent atomically up front, which is what stops a bundle from half-running.
async fn recent_reroute_count(
    pool: &MySqlPool,
    window_secs: u64,
    exclude_bundle: Option<u64>,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM reroutes r LEFT JOIN reroute_bundles b ON b.id=r.bundle_id \
          WHERE r.created_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND) \
            AND (? IS NULL OR r.bundle_id IS NULL OR r.bundle_id <> ?) \
            AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(r.planned_steps_json,'$.verification_mode')),JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.verification_mode')),'routing')<>'configuration_only'",
    )
    .bind(window_secs as i64)
    .bind(exclude_bundle)
    .bind(exclude_bundle)
    .fetch_one(pool)
    .await
    .unwrap_or(i64::MAX)
}

async fn insert_reroute(
    conn: &mut MySqlConnection,
    req: &ActionRequest,
    plan: &RenderedPlan,
    consume_bundle_reservation: bool,
) -> anyhow::Result<u64> {
    let mut steps = json!({ "commands": plan.commands, "verify": plan.verify });
    let mut tx = conn.begin().await?;
    let auth = req
        .authorization
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("reroute has no durable execution authority"))?;
    let (template_snapshot, catalog_rollback_snapshot, prepared) =
        if let Some(snapshot_action_id) = auth.snapshot_action_id {
            let snapshot: (
                sqlx::types::Json<Value>,
                Option<sqlx::types::Json<Value>>,
                sqlx::types::Json<Value>,
            ) = sqlx::query_as(
                "SELECT template_snapshot_json, rollback_snapshot_json, prepared_action_json \
                 FROM reroute_bundle_actions WHERE id = ? FOR UPDATE",
            )
            .bind(snapshot_action_id)
            .fetch_one(&mut *tx)
            .await?;
            let prepared = serde_json::from_value(snapshot.2 .0)?;
            (snapshot.0 .0, snapshot.1.map(|value| value.0), prepared)
        } else if auth.kind == crate::reroute::executor::ExecutionAuthorityKind::Compensation {
            let original_id = req
                .rollback_of_reroute_id
                .ok_or_else(|| anyhow::anyhow!("compensation has no original reroute"))?;
            type OriginalSnapshot = (
                Option<sqlx::types::Json<Value>>,
                Option<sqlx::types::Json<Value>>,
                Option<sqlx::types::Json<Value>>,
            );
            let original: OriginalSnapshot = sqlx::query_as(
                "SELECT template_snapshot_json, parameters_json, rollback_snapshot_json \
                 FROM reroutes WHERE id = ? FOR UPDATE",
            )
            .bind(original_id)
            .fetch_one(&mut *tx)
            .await?;
            let inverse: crate::reroute::device_plan::PreparedInverse = serde_json::from_value(
                original
                    .2
                    .ok_or_else(|| anyhow::anyhow!("original reroute has no prepared inverse"))?
                    .0,
            )?;
            let prepared = crate::reroute::device_plan::PreparedDeviceAction {
                schema_version: crate::reroute::device_plan::PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
                device_id: req.device_id,
                template_id: req.template.id,
                template_name: req.template.name.clone(),
                canonical_params: original.1.map(|value| value.0).unwrap_or(Value::Null),
                verification_mode: inverse.verification_mode,
                commands: inverse.commands,
                before: inverse.expected_current,
                after: inverse.restore,
                verify: inverse.verify,
                effect: crate::reroute::device_plan::PreparedEffect::Change,
                inverse: None,
                prepared_at: chrono::Utc::now(),
            };
            (
                serde_json::to_value(&req.template)?,
                original.0.map(|value| value.0),
                prepared,
            )
        } else {
            anyhow::bail!("reroute has no durable prepared sibling");
        };
    prepared.validate()?;
    steps["verification_mode"] = serde_json::to_value(prepared.verification_mode)?;
    let prior_state = serde_json::to_value(&prepared.before)?;
    let after_state = serde_json::to_value(&prepared.after)?;
    let rollback_snapshot = match prepared.inverse.as_ref() {
        Some(inverse) => Some(serde_json::to_value(inverse)?),
        None => catalog_rollback_snapshot,
    };
    if consume_bundle_reservation {
        if let Some(bundle) = req.bundle {
            let consumed = sqlx::query(
                "UPDATE reroute_bundles \
                    SET rate_reserved_actions = rate_reserved_actions - 1, \
                        rate_consumed_actions = rate_consumed_actions + 1 \
                  WHERE id = ? AND rate_reserved_actions > 0",
            )
            .bind(bundle.bundle_id)
            .execute(&mut *tx)
            .await?;
            anyhow::ensure!(
                consumed.rows_affected() == 1,
                "bundle has no unspent rate reservation"
            );
        }
    }
    let res = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, rule_id, bundle_id, bundle_position, rule_event_id, \
             reroute_template_id, rollback_of_reroute_id, \
             trigger_type, triggered_by_user_id, state, reason, parameters_json, planned_steps_json, \
             prior_state_json, after_state_json, template_snapshot_json, rollback_snapshot_json) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'planned', ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(req.device_id)
    .bind(req.rule_id)
    .bind(req.bundle.map(|b| b.bundle_id))
    .bind(req.bundle.map(|b| b.position))
    .bind(req.rule_event_id)
    .bind(req.template.id)
    .bind(req.rollback_of_reroute_id)
    .bind(req.trigger_type)
    .bind(req.user_id)
    .bind(&req.reason)
    .bind(sqlx::types::Json(&req.params))
    .bind(sqlx::types::Json(&steps))
    .bind(sqlx::types::Json(prior_state))
    .bind(sqlx::types::Json(after_state))
    .bind(sqlx::types::Json(template_snapshot))
    .bind(rollback_snapshot.map(sqlx::types::Json))
    .execute(&mut *tx)
    .await?;
    let reroute_id = res.last_insert_id();

    for (i, cmd) in plan.commands.iter().enumerate() {
        sqlx::query(
            "INSERT INTO reroute_steps (reroute_id, step_number, description, mode, state) \
             VALUES (?, ?, ?, 'ios_ssh', 'planned')",
        )
        .bind(reroute_id)
        .bind((i + 1) as u32)
        .bind(cmd)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
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

    #[test]
    fn typed_interface_restore_is_corrective_but_disruptive_inverse_is_not() {
        use crate::reroute::device_plan::DeviceStateSnapshot;

        assert!(corrective_interface_state(&[
            DeviceStateSnapshot::InterfaceAdmin {
                interface: "Gi0/0".into(),
                shutdown: false,
            }
        ]));
        assert!(corrective_interface_state(&[
            DeviceStateSnapshot::InterfaceMss {
                interface: "Gi0/0".into(),
                mss: None,
            }
        ]));
        assert!(!corrective_interface_state(&[
            DeviceStateSnapshot::InterfaceAdmin {
                interface: "Gi0/0".into(),
                shutdown: true,
            }
        ]));
        assert!(!corrective_interface_state(&[
            DeviceStateSnapshot::InterfaceMss {
                interface: "Gi0/0".into(),
                mss: Some(1_436),
            }
        ]));
    }
}
