//! Notification settings: email recipients + Teams webhook endpoints, with
//! per-event routing and a test-send. All write paths require `manage_alerts`.
//!
//! Teams webhook URLs are encrypted at rest (AES-256-GCM, `crypto::seal`) and
//! never returned to the client or logged. Subscriptions mirror the dispatcher's
//! routing model: a row with NULL `event_type` = all events; one row per chosen
//! event type otherwise (empty list from the UI = "all events").

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

/// Event types an operator can route on (kept in sync with the producers).
pub const EVENT_TYPES: &[&str] = &[
    "rule_fired",
    "reroute_planned",
    "reroute_started",
    "reroute_succeeded",
    "reroute_failed",
    "reroute_uncertain",
    "operating_mode_changed",
    "automatic_actions_changed",
    "global_lock_changed",
    "device_unreachable",
    "telemetry_stale",
    "lock_created",
    "lock_cleared",
    "account_locked",
    "2fa_recovery_used",
];

/// GET /api/notifications/event-types — the routable event-type vocabulary.
pub async fn event_types(_g: RequirePermission<markers::ManageAlerts>) -> JsonResp {
    (StatusCode::OK, Json(json!(EVENT_TYPES)))
}

// ---- Email recipients ----------------------------------------------------------

/// GET /api/notifications/recipients — email recipients + their routed events.
pub async fn list_recipients(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
) -> JsonResp {
    let rows = sqlx::query_as::<_, (u64, String, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT id, email, verified_at FROM alert_recipients \
         WHERE email <> 'unrouted@rerouter.local' ORDER BY email",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for (id, email, verified_at) in rows {
        let events = subscription_events(&state.pool, "recipient_id", id).await;
        out.push(json!({
            "id": id,
            "email": email,
            "verified": verified_at.is_some(),
            "event_types": events,
        }));
    }
    (StatusCode::OK, Json(json!(out)))
}

#[derive(Debug, Deserialize)]
pub struct RecipientBody {
    email: String,
    /// Empty = all events (a single NULL subscription).
    #[serde(default)]
    event_types: Vec<String>,
}

/// POST /api/notifications/recipients — add an email recipient. Admin-added, so
/// it is auto-verified (no confirmation email in v1).
pub async fn add_recipient(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Json(body): Json<RecipientBody>,
) -> JsonResp {
    let email = body.email.trim().to_string();
    if !email.contains('@') || email.len() > 191 {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "a valid email is required");
    }
    if let Some(bad) = invalid_event(&body.event_types) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, &bad);
    }
    let res = sqlx::query(
        "INSERT INTO alert_recipients (email, verified_at) VALUES (?, UTC_TIMESTAMP()) \
         ON DUPLICATE KEY UPDATE verified_at = UTC_TIMESTAMP()",
    )
    .bind(&email)
    .execute(&state.pool)
    .await;
    let recipient_id = match res {
        Ok(r) if r.last_insert_id() > 0 => r.last_insert_id(),
        Ok(_) => sqlx::query_scalar::<_, u64>("SELECT id FROM alert_recipients WHERE email = ?")
            .bind(&email)
            .fetch_one(&state.pool)
            .await
            .unwrap_or(0),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    replace_subscriptions(
        &state.pool,
        "alert_subscriptions",
        "recipient_id",
        recipient_id,
        &body.event_types,
    )
    .await;
    (StatusCode::CREATED, Json(json!({ "id": recipient_id })))
}

/// DELETE /api/notifications/recipients/{id}.
pub async fn remove_recipient(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match sqlx::query("DELETE FROM alert_recipients WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({ "ok": true }))),
        Ok(_) => err(StatusCode::NOT_FOUND, "recipient not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// POST /api/notifications/recipients/{id}/test — send a sample email.
pub async fn test_recipient(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let email: Option<String> =
        sqlx::query_scalar("SELECT email FROM alert_recipients WHERE id = ?")
            .bind(id)
            .fetch_optional(&state.pool)
            .await
            .unwrap_or(None);
    let Some(email) = email else {
        return err(StatusCode::NOT_FOUND, "recipient not found");
    };
    let mailer = match crate::alerts::mailer::Mailer::from_env() {
        Ok(m) => m,
        Err(_) => return err(StatusCode::BAD_GATEWAY, "SMTP is not configured"),
    };
    match mailer
        .send(
            &email,
            "[Rerouter] Test alert",
            "This is a test notification from Rerouter. Email delivery is working.".to_string(),
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => err(StatusCode::BAD_GATEWAY, &format!("send failed: {e}")),
    }
}

// ---- Teams webhook endpoints ---------------------------------------------------

/// GET /api/notifications/webhooks — Teams endpoints (URLs are never returned).
pub async fn list_webhooks(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
) -> JsonResp {
    let rows = sqlx::query_as::<_, (u64, String, bool)>(
        "SELECT id, name, enabled FROM webhook_endpoints ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default();

    let mut out = Vec::with_capacity(rows.len());
    for (id, name, enabled) in rows {
        let events = subscription_events(&state.pool, "endpoint_id", id).await;
        out.push(json!({
            "id": id,
            "name": name,
            "enabled": enabled,
            "event_types": events,
        }));
    }
    (StatusCode::OK, Json(json!(out)))
}

#[derive(Debug, Deserialize)]
pub struct WebhookBody {
    name: String,
    /// The Teams incoming-webhook URL (stored encrypted; never returned).
    url: String,
    #[serde(default)]
    event_types: Vec<String>,
}

/// POST /api/notifications/webhooks — register a Teams endpoint.
pub async fn add_webhook(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Json(body): Json<WebhookBody>,
) -> JsonResp {
    let name = body.name.trim().to_string();
    let url = body.url.trim().to_string();
    if name.is_empty() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "name is required");
    }
    // A Teams incoming webhook is an HTTPS URL; reject anything else early.
    if !url.starts_with("https://") {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "url must be an https:// webhook");
    }
    if let Some(bad) = invalid_event(&body.event_types) {
        return err(StatusCode::UNPROCESSABLE_ENTITY, &bad);
    }
    if !crate::crypto::is_configured() {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "secrets key not configured");
    }
    let blob = match crate::crypto::seal_str(&url) {
        Ok(b) => b,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "could not encrypt url"),
    };
    let res = sqlx::query(
        "INSERT INTO webhook_endpoints (kind, name, url_encrypted) VALUES ('teams', ?, ?)",
    )
    .bind(&name)
    .bind(&blob)
    .execute(&state.pool)
    .await;
    let endpoint_id = match res {
        Ok(r) => r.last_insert_id(),
        Err(_) => return err(StatusCode::UNPROCESSABLE_ENTITY, "a webhook with that name exists"),
    };
    replace_subscriptions(
        &state.pool,
        "webhook_subscriptions",
        "endpoint_id",
        endpoint_id,
        &body.event_types,
    )
    .await;
    (StatusCode::CREATED, Json(json!({ "id": endpoint_id })))
}

/// DELETE /api/notifications/webhooks/{id}.
pub async fn remove_webhook(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match sqlx::query("DELETE FROM webhook_endpoints WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await
    {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({ "ok": true }))),
        Ok(_) => err(StatusCode::NOT_FOUND, "webhook not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// POST /api/notifications/webhooks/{id}/test — post a sample card to the endpoint.
pub async fn test_webhook(
    _g: RequirePermission<markers::ManageAlerts>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let endpoint = match crate::alerts::webhook::load_one(&state.pool, id).await {
        Ok(Some(e)) => e,
        Ok(None) => return err(StatusCode::NOT_FOUND, "webhook not found"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    match crate::alerts::webhook::post_teams(
        &endpoint.url,
        "[Rerouter] Test alert",
        "info",
        "This is a test notification from Rerouter. Teams delivery is working.",
    )
    .await
    {
        Ok(()) => (StatusCode::OK, Json(json!({ "ok": true }))),
        Err(e) => err(StatusCode::BAD_GATEWAY, &format!("post failed: {e}")),
    }
}

// ---- helpers -------------------------------------------------------------------

/// Validate an event-type list against the known vocabulary. Returns an error
/// message for the first unknown event, or None if all are valid.
fn invalid_event(events: &[String]) -> Option<String> {
    events
        .iter()
        .find(|e| !EVENT_TYPES.contains(&e.as_str()))
        .map(|e| format!("unknown event_type '{e}'"))
}

/// The routed event types for a recipient/endpoint. Returns `["*"]` when the
/// subscription is "all events" (a NULL event_type row).
async fn subscription_events(pool: &sqlx::MySqlPool, fk_col: &str, id: u64) -> Vec<String> {
    let table = if fk_col == "recipient_id" {
        "alert_subscriptions"
    } else {
        "webhook_subscriptions"
    };
    let rows = sqlx::query_as::<_, (Option<String>,)>(&format!(
        "SELECT event_type FROM {table} WHERE {fk_col} = ? AND enabled = 1"
    ))
    .bind(id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();
    if rows.iter().any(|(e,)| e.is_none()) || rows.is_empty() {
        return vec!["*".to_string()];
    }
    rows.into_iter().filter_map(|(e,)| e).collect()
}

/// Replace a recipient/endpoint's subscriptions: clear existing, then insert one
/// NULL row (all events) when the list is empty, else one row per event type.
async fn replace_subscriptions(
    pool: &sqlx::MySqlPool,
    table: &str,
    fk_col: &str,
    id: u64,
    events: &[String],
) {
    let _ = sqlx::query(&format!("DELETE FROM {table} WHERE {fk_col} = ?"))
        .bind(id)
        .execute(pool)
        .await;
    if events.is_empty() {
        let _ = sqlx::query(&format!(
            "INSERT INTO {table} ({fk_col}, event_type) VALUES (?, NULL)"
        ))
        .bind(id)
        .execute(pool)
        .await;
    } else {
        for e in events {
            let _ = sqlx::query(&format!(
                "INSERT INTO {table} ({fk_col}, event_type) VALUES (?, ?)"
            ))
            .bind(id)
            .bind(e)
            .execute(pool)
            .await;
        }
    }
}
