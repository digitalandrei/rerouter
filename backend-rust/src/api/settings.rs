//! GET/PUT /api/settings — the `system_settings` key/value store.
//!
//! Reads require a session (view_dashboard). Writes are admin-only and audited;
//! flipping `operating_mode` to "enforce" or `automatic_actions_enabled` to true
//! is a high-visibility safety change — nothing in the system may flip either
//! implicitly. Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: SystemSettings).
//!
//! SAFETY default: a missing `operating_mode` row falls back to the config
//! default (observe). We never infer "enforce".

use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::net::SocketAddr;

use super::{client_ip, err, user_agent, AppState};
use crate::auth::rbac;
use crate::auth::sessions::Session;
use crate::config::{Config, OperatingMode};

type JsonResp = (StatusCode, Json<Value>);

/// The resolved runtime operating mode: the `system_settings.operating_mode`
/// row, or the config fallback (observe) if the row is missing/unreadable. Used
/// by /status, the detection engine (GATE 0), and the settings response.
pub async fn operating_mode(pool: &sqlx::MySqlPool, cfg: &Config) -> &'static str {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = 'operating_mode'")
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    match stored.as_deref() {
        Some("enforce") => "enforce",
        Some("observe") => "observe",
        // Missing/unknown -> config default (which itself defaults to observe).
        _ => match cfg.safety.operating_mode {
            OperatingMode::Enforce => "enforce",
            OperatingMode::Observe => "observe",
        },
    }
}

/// Read a boolean setting (`"true"`/`"false"`), defaulting to `default`.
pub async fn bool_setting(pool: &sqlx::MySqlPool, key: &str, default: bool) -> bool {
    let stored: Option<String> =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key` = ?")
            .bind(key)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    match stored.as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}

/// Load every system_settings row into a string map.
async fn all_settings(pool: &sqlx::MySqlPool) -> BTreeMap<String, String> {
    sqlx::query_as::<_, (String, String)>("SELECT `key`, `value` FROM system_settings")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Build the SystemSettings JSON: the typed fields the contract pins, plus every
/// other raw key (the contract allows extra `[key]: unknown` entries).
fn settings_json(map: &BTreeMap<String, String>, cfg: &Config) -> Value {
    let operating_mode = match map.get("operating_mode").map(String::as_str) {
        Some("enforce") => "enforce",
        Some("observe") => "observe",
        _ => match cfg.safety.operating_mode {
            OperatingMode::Enforce => "enforce",
            OperatingMode::Observe => "observe",
        },
    };
    let automatic = map
        .get("automatic_actions_enabled")
        .map(|v| v == "true")
        .unwrap_or(false);
    let global_lock = map
        .get("global_maintenance_lock")
        .map(|v| v == "true")
        .unwrap_or(false);

    let mut obj = serde_json::Map::new();
    obj.insert("operating_mode".into(), json!(operating_mode));
    obj.insert("automatic_actions_enabled".into(), json!(automatic));
    obj.insert("global_lock".into(), json!(global_lock));
    // Surface any additional keys verbatim (raw string values).
    for (k, v) in map {
        if k == "operating_mode"
            || k == "automatic_actions_enabled"
            || k == "global_maintenance_lock"
        {
            continue;
        }
        obj.entry(k.clone()).or_insert(json!(v));
    }
    Value::Object(obj)
}

/// GET /api/settings.
pub async fn show(
    _g: rbac::RequirePermission<rbac::markers::ViewDashboard>,
    State(state): State<AppState>,
) -> JsonResp {
    let map = all_settings(&state.pool).await;
    (StatusCode::OK, Json(settings_json(&map, &state.config)))
}

/// PUT /api/settings — admin only. Accepts a partial SystemSettings; persists the
/// recognized keys and audits every change (especially operating_mode and
/// automatic_actions_enabled). Returns the full settings after the update.
pub async fn update(
    session: Session,
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(socket): ConnectInfo<SocketAddr>,
    Json(body): Json<Value>,
) -> JsonResp {
    let pool = &state.pool;

    // Admin only — this is the safety boundary for the operating mode.
    match rbac::is_admin(pool, session.user_id).await {
        Ok(true) => {}
        Ok(false) => return err(StatusCode::FORBIDDEN, "admin role required"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "authz check failed"),
    }
    let ip = client_ip(&headers, Some(&socket));
    let ua = user_agent(&headers);

    let before = all_settings(pool).await;

    // Step-up re-auth for the ARMING changes: turning operating_mode to "enforce"
    // or automatic_actions_enabled to true arms the whole system, so require a
    // fresh password + live TOTP right now — a stolen/hijacked admin session must
    // not be enough on its own. Turning either OFF, or the global maintenance
    // lock, is a safe direction and needs no step-up.
    let arming_enforce = body.get("operating_mode").and_then(Value::as_str) == Some("enforce")
        && before.get("operating_mode").map(String::as_str) != Some("enforce");
    let arming_auto = body
        .get("automatic_actions_enabled")
        .and_then(Value::as_bool)
        == Some(true)
        && before.get("automatic_actions_enabled").map(String::as_str) != Some("true");
    if arming_enforce || arming_auto {
        let password = body.get("password").and_then(Value::as_str).unwrap_or("");
        let totp_code = body.get("totp_code").and_then(Value::as_str).unwrap_or("");
        // 403 (not 401) on purpose: the SPA hard-redirects to /login on any 401,
        // which would wrongly log the operator out mid-arming. 403 keeps the
        // session and lets the UI show the step-up prompt/error.
        if password.is_empty() || totp_code.is_empty() {
            return err(StatusCode::FORBIDDEN, "reauth_required");
        }
        match crate::auth::verify_step_up(pool, session.user_id, password, totp_code).await {
            Ok(true) => {}
            Ok(false) => {
                audit(
                    pool,
                    session.user_id,
                    "settings_reauth_failed",
                    &ip,
                    &ua,
                    "step-up re-auth failed for an arming settings change",
                )
                .await;
                return err(StatusCode::FORBIDDEN, "reauth_failed");
            }
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "authz check failed"),
        }
    }

    // operating_mode: must be "observe" | "enforce".
    if let Some(v) = body.get("operating_mode").and_then(Value::as_str) {
        if v != "observe" && v != "enforce" {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "operating_mode must be observe or enforce",
            );
        }
        let prev = before.get("operating_mode").cloned().unwrap_or_default();
        if prev != v {
            if let Err(_e) = upsert(pool, "operating_mode", v, session.user_id).await {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
            audit(
                pool,
                session.user_id,
                "operating_mode_changed",
                &ip,
                &ua,
                &format!("operating_mode {prev} -> {v}"),
            )
            .await;
            let before = if prev.is_empty() { "observe" } else { &prev };
            let severity = if v == "enforce" { "critical" } else { "warning" };
            enqueue_change_alert(
                pool,
                session.user_id,
                "operating_mode_changed",
                before,
                v,
                severity,
                &format!("operating_mode changed from {before} to {v}"),
            )
            .await;
        }
    }

    // automatic_actions_enabled: boolean.
    if let Some(b) = body
        .get("automatic_actions_enabled")
        .and_then(Value::as_bool)
    {
        let v = if b { "true" } else { "false" };
        let prev = before
            .get("automatic_actions_enabled")
            .cloned()
            .unwrap_or_default();
        if prev != v {
            if upsert(pool, "automatic_actions_enabled", v, session.user_id)
                .await
                .is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
            audit(
                pool,
                session.user_id,
                "automatic_actions_changed",
                &ip,
                &ua,
                &format!("automatic_actions_enabled {prev} -> {v}"),
            )
            .await;
            let before = if prev.is_empty() { "false" } else { &prev };
            let severity = if b { "critical" } else { "warning" };
            enqueue_change_alert(
                pool,
                session.user_id,
                "automatic_actions_changed",
                before,
                v,
                severity,
                &format!("automatic_actions_enabled changed from {before} to {v}"),
            )
            .await;
        }
    }

    // global_lock maps to the global_maintenance_lock row.
    if let Some(b) = body.get("global_lock").and_then(Value::as_bool) {
        let v = if b { "true" } else { "false" };
        let prev = before
            .get("global_maintenance_lock")
            .cloned()
            .unwrap_or_default();
        if prev != v {
            if upsert(pool, "global_maintenance_lock", v, session.user_id)
                .await
                .is_err()
            {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
            audit(
                pool,
                session.user_id,
                "global_lock_changed",
                &ip,
                &ua,
                &format!("global_maintenance_lock {prev} -> {v}"),
            )
            .await;
            let before = if prev.is_empty() { "false" } else { &prev };
            enqueue_change_alert(
                pool,
                session.user_id,
                "global_lock_changed",
                before,
                v,
                "warning",
                &format!("global_maintenance_lock changed from {before} to {v}"),
            )
            .await;
        }
    }

    let after = all_settings(pool).await;
    (StatusCode::OK, Json(settings_json(&after, &state.config)))
}

/// Enqueue an alert for an arming / mode-flip change so subscribers are emailed.
/// These are the highest-consequence state changes (they can allow traffic-moving
/// actions), so they are in `ALWAYS_IMMEDIATE` and page right away. `before`/`after`
/// and the acting user are rendered by `alerts::body::render_mode_change`.
async fn enqueue_change_alert(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    event: &str,
    before: &str,
    after: &str,
    severity: &str,
    message: &str,
) {
    let actor = crate::alerts::actor_json(pool, Some(user_id)).await;
    let payload = json!({
        "actor": actor,
        "before": before,
        "after": after,
        "message": message,
    });
    let dedup_key = format!("{event}:{before}->{after}");
    if let Err(e) = sqlx::query(
        "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) VALUES (?, ?, ?, ?)",
    )
    .bind(event)
    .bind(severity)
    .bind(sqlx::types::Json(&payload))
    .bind(&dedup_key)
    .execute(pool)
    .await
    {
        tracing::error!(event_type = "settings_alert_enqueue_failed", change = %event, error = %e, "failed to enqueue settings-change alert");
    }
}

/// Upsert one system_settings row, stamping updated_by.
async fn upsert(
    pool: &sqlx::MySqlPool,
    key: &str,
    value: &str,
    user_id: u64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO system_settings (`key`, `value`, updated_by) VALUES (?, ?, ?) \
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_by = VALUES(updated_by)",
    )
    .bind(key)
    .bind(value)
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Best-effort audit row for a settings change.
async fn audit(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    event: &str,
    ip: &str,
    ua: &str,
    message: &str,
) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(event)
    .bind(message)
    .bind(ip)
    .bind(ua)
    .execute(pool)
    .await;
}
