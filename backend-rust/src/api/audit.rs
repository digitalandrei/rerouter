//! GET /api/audit — append-only audit log (view_audit). Field names are pinned
//! by the frontend contract (../../frontend/src/lib/api.ts: AuditEntry).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    /// Optional event_type filter (uses the (event_type, created_at) index).
    event_type: Option<String>,
}

/// An `audit_logs` row joined to the actor's email.
#[derive(sqlx::FromRow)]
struct AuditRow {
    id: u64,
    actor_type: String,
    actor_email: Option<String>,
    event_type: String,
    entity_type: Option<String>,
    entity_id: Option<u64>,
    message: Option<String>,
    ip_address: Option<String>,
    user_agent: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

/// GET /api/audit — most recent first, optionally filtered by event_type.
pub async fn list(
    _g: RequirePermission<markers::ViewAudit>,
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> JsonResp {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);

    let rows = if let Some(ev) = q.event_type.as_deref() {
        sqlx::query_as::<_, AuditRow>(
            "SELECT a.id, a.actor_type, u.email AS actor_email, a.event_type, a.entity_type, \
                    a.entity_id, a.message, a.ip_address, a.user_agent, a.created_at \
             FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id \
             WHERE a.event_type = ? ORDER BY a.id DESC LIMIT ?",
        )
        .bind(ev)
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    } else {
        sqlx::query_as::<_, AuditRow>(
            "SELECT a.id, a.actor_type, u.email AS actor_email, a.event_type, a.entity_type, \
                    a.entity_id, a.message, a.ip_address, a.user_agent, a.created_at \
             FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id \
             ORDER BY a.id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&state.pool)
        .await
    };

    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    let actor = r.actor_email.clone().unwrap_or_else(|| r.actor_type.clone());
                    let subject = match (&r.entity_type, r.entity_id) {
                        (Some(t), Some(id)) => format!("{t}#{id}"),
                        (Some(t), None) => t.clone(),
                        _ => r.message.clone().unwrap_or_default(),
                    };
                    json!({
                        "id": r.id,
                        "actor": actor,
                        "action": r.event_type,
                        "subject": subject,
                        "ip": r.ip_address.clone().unwrap_or_default(),
                        "created_at": r.created_at.to_rfc3339(),
                        "details": {
                            "message": r.message,
                            "actor_type": r.actor_type,
                            "user_agent": r.user_agent,
                        },
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
