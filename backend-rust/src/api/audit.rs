//! GET /api/audit — append-only audit log (view_audit). Field names are pinned
//! by the frontend contract (../../frontend/src/lib/api.ts: AuditEntry).

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{MySql, QueryBuilder};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    limit: Option<i64>,
    /// Optional event_type filter (uses the (event_type, created_at) index).
    event_type: Option<String>,
    actor: Option<String>,
    action: Option<String>,
    entity: Option<String>,
    after: Option<String>,
    before: Option<String>,
    page: Option<u64>,
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
    let limit = q.limit.unwrap_or(100).clamp(1, 200);
    let page = q.page.unwrap_or(1).clamp(1, 10_000);
    let filtered = q.actor.is_some()
        || q.action.is_some()
        || q.entity.is_some()
        || q.after.is_some()
        || q.before.is_some()
        || q.page.is_some();

    let mut query = QueryBuilder::<MySql>::new(
        "SELECT a.id, a.actor_type, u.email AS actor_email, a.event_type, a.entity_type, \
         a.entity_id, a.message, a.ip_address, a.user_agent, a.created_at \
         FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id WHERE 1=1",
    );
    if let Some(ev) = q.action.as_deref().or(q.event_type.as_deref()) {
        query.push(" AND a.event_type = ").push_bind(ev);
    }
    if let Some(actor) = q.actor.as_deref().filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", actor.trim());
        query
            .push(" AND (u.email LIKE ")
            .push_bind(pattern.clone())
            .push(" OR a.actor_type LIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(entity) = q.entity.as_deref().filter(|value| !value.trim().is_empty()) {
        let pattern = format!("%{}%", entity.trim());
        query
            .push(" AND (a.entity_type LIKE ")
            .push_bind(pattern.clone())
            .push(" OR CAST(a.entity_id AS CHAR) LIKE ")
            .push_bind(pattern)
            .push(")");
    }
    if let Some(after) = q.after {
        query.push(" AND a.created_at >= ").push_bind(after);
    }
    if let Some(before) = q.before {
        query.push(" AND a.created_at <= ").push_bind(before);
    }
    query
        .push(" ORDER BY a.id DESC LIMIT ")
        .push_bind(limit + 1)
        .push(" OFFSET ")
        .push_bind(((page - 1) * limit as u64) as i64);
    let rows = query
        .build_query_as::<AuditRow>()
        .fetch_all(&state.pool)
        .await;

    match rows {
        Ok(mut rows) => {
            let has_more = rows.len() > limit as usize;
            rows.truncate(limit as usize);
            let out: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    let actor = r
                        .actor_email
                        .clone()
                        .unwrap_or_else(|| r.actor_type.clone());
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
            if filtered {
                (
                    StatusCode::OK,
                    Json(json!({
                        "rows": out, "page": page, "limit": limit, "has_more": has_more
                    })),
                )
            } else {
                (StatusCode::OK, Json(json!(out)))
            }
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
