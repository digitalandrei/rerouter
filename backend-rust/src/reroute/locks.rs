//! Safety locks — a locked scope blocks all reroutes touching it until cleared.
//! Device-scoped locks gate device_cli actions; crash recovery and uncertain
//! actions create auto locks that an admin must acknowledge before reroutes can
//! resume on that device. See ../docs/reroute-engine.md and state-recovery.md.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sqlx::MySqlPool;

/// Is there an active (uncleared) lock on this scope/ref, OR any global lock?
pub async fn is_blocked(pool: &MySqlPool, scope: &str, scope_ref: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM locks \
         WHERE cleared_at IS NULL AND (scope = 'global' OR (scope = ? AND scope_ref = ?))",
    )
    .bind(scope)
    .bind(scope_ref)
    .fetch_one(pool)
    .await
    .context("checking locks")?;
    Ok(count > 0)
}

/// Create a lock. Callers usually check [`is_blocked`] first.
pub async fn create(
    pool: &MySqlPool,
    scope: &str,
    scope_ref: Option<&str>,
    kind: &str,
    reason: &str,
    by: Option<u64>,
) -> Result<u64> {
    let res = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reason, kind, created_by) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(scope)
    .bind(scope_ref)
    .bind(reason)
    .bind(kind)
    .bind(by)
    .execute(pool)
    .await
    .context("creating lock")?;
    Ok(res.last_insert_id())
}

/// Clear all active locks for a scope/ref. Returns the number cleared.
pub async fn clear(
    pool: &MySqlPool,
    scope: &str,
    scope_ref: Option<&str>,
    by: Option<u64>,
) -> Result<u64> {
    let res = match scope_ref {
        Some(r) => {
            sqlx::query(
                "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
                 WHERE scope = ? AND scope_ref = ? AND cleared_at IS NULL",
            )
            .bind(by)
            .bind(scope)
            .bind(r)
            .execute(pool)
            .await
        }
        None => {
            sqlx::query(
                "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
                 WHERE scope = ? AND scope_ref IS NULL AND cleared_at IS NULL",
            )
            .bind(by)
            .bind(scope)
            .execute(pool)
            .await
        }
    }
    .context("clearing lock")?;
    Ok(res.rows_affected())
}

/// Active locks as JSON (for the locks / settings API).
pub async fn list_active(pool: &MySqlPool) -> Result<Vec<Value>> {
    let rows = sqlx::query_as::<_, (u64, String, Option<String>, Option<String>, String, chrono::DateTime<chrono::Utc>)>(
        "SELECT id, scope, scope_ref, reason, kind, created_at FROM locks WHERE cleared_at IS NULL ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .context("listing locks")?;
    Ok(rows
        .into_iter()
        .map(|(id, scope, scope_ref, reason, kind, created_at)| {
            json!({
                "id": id,
                "scope": scope,
                "scope_ref": scope_ref,
                "reason": reason,
                "kind": kind,
                "created_at": created_at.to_rfc3339(),
            })
        })
        .collect())
}
