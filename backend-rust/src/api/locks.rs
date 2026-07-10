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
pub async fn list(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
) -> JsonResp {
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
    let reason = body
        .reason
        .unwrap_or_else(|| "global maintenance lock".into());
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let lock_id = match locks::create_on(
        &mut tx,
        "global",
        None,
        None,
        "manual",
        &reason,
        Some(g.session.user_id),
    )
    .await
    {
        Ok(id) => id,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "global_lock_created",
        "lock",
        lock_id,
        &reason,
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error");
    }
    (StatusCode::OK, Json(json!({ "ok": true })))
}

/// DELETE /api/locks/global — clear the global maintenance lock(s).
pub async fn clear_global(
    g: RequirePermission<markers::ManageLocks>,
    State(state): State<AppState>,
) -> JsonResp {
    let mut tx = match state.pool.begin().await {
        Ok(tx) => tx,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    let cleared = sqlx::query(
        "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
         WHERE scope = 'global' AND scope_ref IS NULL AND cleared_at IS NULL",
    )
    .bind(g.session.user_id)
    .execute(&mut *tx)
    .await;
    let n = match cleared {
        Ok(result) => result.rows_affected(),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    if super::audit_mutation_on(
        &mut tx,
        &g.session,
        "global_lock_cleared",
        "lock",
        0,
        &format!("cleared {n} global lock(s)"),
    )
    .await
    .is_err()
        || tx.commit().await.is_err()
    {
        return err(StatusCode::INTERNAL_SERVER_ERROR, "audit_write_failed");
    }
    (StatusCode::OK, Json(json!({ "ok": true, "cleared": n })))
}
