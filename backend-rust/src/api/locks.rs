//! Safety locks API. The global maintenance lock blocks ALL reroutes while
//! active; device locks are raised automatically (crash / uncertain) and cleared
//! by acknowledging the reroute. Creating/clearing is always audited.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::reroute::locks;

type JsonResp = (StatusCode, Json<Value>);

/// GET /api/locks — the active (uncleared) locks.
pub async fn list(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>) -> JsonResp {
    match locks::list_active(&state.pool).await {
        Ok(v) => (StatusCode::OK, Json(json!(v))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct GlobalLockBody {
    #[serde(default)]
    reason: Option<String>,
}

/// POST /api/locks/global — raise the global maintenance lock.
pub async fn create_global(
    g: RequirePermission<markers::ManageLocks>,
    State(state): State<AppState>,
    Json(body): Json<GlobalLockBody>,
) -> JsonResp {
    let reason = body.reason.unwrap_or_else(|| "global maintenance lock".into());
    if locks::create(&state.pool, "global", None, "manual", &reason, Some(g.session.user_id))
        .await
        .is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }
    audit(&state.pool, g.session.user_id, "global_lock_created", &reason).await;
    (StatusCode::OK, Json(json!({ "ok": true })))
}

/// DELETE /api/locks/global — clear the global maintenance lock(s).
pub async fn clear_global(g: RequirePermission<markers::ManageLocks>, State(state): State<AppState>) -> JsonResp {
    let n = locks::clear(&state.pool, "global", None, Some(g.session.user_id))
        .await
        .unwrap_or(0);
    audit(&state.pool, g.session.user_id, "global_lock_cleared", &format!("cleared {n} global lock(s)")).await;
    (StatusCode::OK, Json(json!({ "ok": true, "cleared": n })))
}

async fn audit(pool: &sqlx::MySqlPool, user_id: u64, event: &str, message: &str) {
    let _ = sqlx::query(
        "INSERT INTO audit_logs (actor_type, actor_user_id, event_type, message) VALUES ('user', ?, ?, ?)",
    )
    .bind(user_id)
    .bind(event)
    .bind(message)
    .execute(pool)
    .await;
}
