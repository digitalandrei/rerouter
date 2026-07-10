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
/// row, or the config fallback if the row is missing. Read failures always fail
/// closed to observe. Used by /status, the detection engine (GATE 0), and the
/// settings response.
pub async fn operating_mode(pool: &sqlx::MySqlPool, cfg: &Config) -> &'static str {
    let stored: Option<String> = match sqlx::query_scalar(
        "SELECT `value` FROM system_settings WHERE `key` = 'operating_mode'",
    )
    .fetch_optional(pool)
    .await
    {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(event_type = "operating_mode_read_failed", error = %e, "could not read operating mode; failing closed to observe");
            return "observe";
        }
    };
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

/// Read a boolean setting (`"true"`/`"false"`), defaulting to `default` when
/// absent. Read failures fail closed: maintenance is active and other gates are
/// disabled.
pub async fn bool_setting(pool: &sqlx::MySqlPool, key: &str, default: bool) -> bool {
    let stored: Option<String> = match sqlx::query_scalar(
        "SELECT `value` FROM system_settings WHERE `key` = ?",
    )
    .bind(key)
    .fetch_optional(pool)
    .await
    {
        Ok(value) => value,
        Err(e) => {
            tracing::error!(event_type = "safety_setting_read_failed", setting = key, error = %e, "could not read safety setting; using its fail-closed value");
            return key == "global_maintenance_lock";
        }
    };
    match stored.as_deref() {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}

/// Load every system_settings row into a string map.
async fn all_settings(pool: &sqlx::MySqlPool) -> anyhow::Result<BTreeMap<String, String>> {
    Ok(
        sqlx::query_as::<_, (String, String)>("SELECT `key`, `value` FROM system_settings")
            .fetch_all(pool)
            .await?
            .into_iter()
            .collect(),
    )
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
        .unwrap_or(cfg.safety.automatic_actions_enabled);
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
    match all_settings(&state.pool).await {
        Ok(map) => (StatusCode::OK, Json(settings_json(&map, &state.config))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

struct SettingChange {
    key: &'static str,
    event: &'static str,
    before: String,
    after: String,
    severity: &'static str,
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

    let before = match all_settings(pool).await {
        Ok(settings) => settings,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let resolved_before = settings_json(&before, &state.config);
    let before_mode = resolved_before
        .get("operating_mode")
        .and_then(Value::as_str)
        .unwrap_or("observe");
    let before_auto = resolved_before
        .get("automatic_actions_enabled")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Step-up re-auth for the ARMING changes: turning operating_mode to "enforce"
    // or automatic_actions_enabled to true arms the whole system, so require a
    // fresh password + live TOTP right now — a stolen/hijacked admin session must
    // not be enough on its own. Turning either OFF, or the global maintenance
    // lock, is a safe direction and needs no step-up.
    let arming_enforce = body.get("operating_mode").and_then(Value::as_str) == Some("enforce")
        && before_mode != "enforce";
    let arming_auto = body
        .get("automatic_actions_enabled")
        .and_then(Value::as_bool)
        == Some(true)
        && !before_auto;
    if arming_enforce || arming_auto {
        if crate::auth::ip_throttled(
            pool,
            &ip,
            state.config.auth.lockout_threshold,
            state.config.auth.lockout_minutes as i64,
        )
        .await
        {
            return err(StatusCode::TOO_MANY_REQUESTS, "too_many_attempts");
        }
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
                audit_reauth_failure(
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

    let mut changes = Vec::new();

    // Validate the full patch before writing any of it.
    if let Some(raw) = body.get("operating_mode") {
        let Some(v) = raw.as_str() else {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "operating_mode must be a string",
            );
        };
        if v != "observe" && v != "enforce" {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "operating_mode must be observe or enforce",
            );
        }
        if before_mode != v {
            changes.push(SettingChange {
                key: "operating_mode",
                event: "operating_mode_changed",
                before: before_mode.to_string(),
                after: v.to_string(),
                severity: if v == "enforce" {
                    "critical"
                } else {
                    "warning"
                },
            });
        }
    }

    if let Some(raw) = body.get("automatic_actions_enabled") {
        let Some(b) = raw.as_bool() else {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "automatic_actions_enabled must be boolean",
            );
        };
        let v = if b { "true" } else { "false" };
        if before_auto != b {
            changes.push(SettingChange {
                key: "automatic_actions_enabled",
                event: "automatic_actions_changed",
                before: before_auto.to_string(),
                after: v.to_string(),
                severity: if b { "critical" } else { "warning" },
            });
        }
    }

    if let Some(raw) = body.get("global_lock") {
        let Some(b) = raw.as_bool() else {
            return err(
                StatusCode::UNPROCESSABLE_ENTITY,
                "global_lock must be boolean",
            );
        };
        let v = if b { "true" } else { "false" };
        let was_locked = resolved_before
            .get("global_lock")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if was_locked != b {
            changes.push(SettingChange {
                key: "global_maintenance_lock",
                event: "global_lock_changed",
                before: was_locked.to_string(),
                after: v.to_string(),
                severity: "warning",
            });
        }
    }

    if !changes.is_empty() {
        let actor = crate::alerts::actor_json(pool, Some(session.user_id)).await;
        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
        for change in &changes {
            let message = format!(
                "{} changed from {} to {}",
                change.key, change.before, change.after
            );
            let payload = json!({
                "actor": actor.clone(),
                "before": change.before,
                "after": change.after,
                "message": message,
            });
            let write = async {
                sqlx::query(
                    "INSERT INTO system_settings (`key`, `value`, updated_by) VALUES (?, ?, ?) \
                     ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), updated_by = VALUES(updated_by)",
                )
                .bind(change.key)
                .bind(&change.after)
                .bind(session.user_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO audit_logs \
                     (actor_type, actor_user_id, event_type, message, ip_address, user_agent) \
                     VALUES ('user', ?, ?, ?, ?, ?)",
                )
                .bind(session.user_id)
                .bind(change.event)
                .bind(&message)
                .bind(&ip)
                .bind(&ua)
                .execute(&mut *tx)
                .await?;
                sqlx::query(
                    "INSERT INTO alerts (event_type, severity, payload_json, dedup_key) \
                     VALUES (?, ?, ?, ?)",
                )
                .bind(change.event)
                .bind(change.severity)
                .bind(sqlx::types::Json(payload))
                .bind(format!("{}:{}->{}", change.event, change.before, change.after))
                .execute(&mut *tx)
                .await?;
                Ok::<(), sqlx::Error>(())
            }
            .await;
            if write.is_err() {
                return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
            }
        }
        if tx.commit().await.is_err() {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
        }
    }

    match all_settings(pool).await {
        Ok(after) => (StatusCode::OK, Json(settings_json(&after, &state.config))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

async fn audit_reauth_failure(
    pool: &sqlx::MySqlPool,
    user_id: u64,
    event: &str,
    ip: &str,
    ua: &str,
    message: &str,
) {
    if let Err(e) = sqlx::query(
        "INSERT INTO audit_logs \
         (actor_type, actor_user_id, event_type, message, ip_address, user_agent) \
         VALUES ('user', ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(event)
    .bind(message)
    .bind(ip)
    .bind(ua)
    .execute(pool)
    .await
    {
        tracing::error!(event_type = "settings_reauth_audit_failed", error = %e, "could not audit failed settings re-authentication");
    }
}
