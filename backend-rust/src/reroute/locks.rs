//! Safety locks — a locked scope blocks all reroutes touching it until cleared.
//! Device-scoped locks gate device_cli actions; crash recovery and uncertain
//! actions create auto locks that an admin must acknowledge before reroutes can
//! resume on that device. See ../docs/reroute-engine.md and state-recovery.md.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use sqlx::MySqlPool;

/// Durable ownership of a device configuration channel. Unlike MySQL advisory
/// locks this survives a controller crash, so an ambiguous write cannot silently
/// become available to another activation after reconnect.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ChangeWindow {
    pub device_id: u64,
    pub bundle_id: Option<u64>,
    pub reroute_id: Option<u64>,
    pub owner_token: String,
    pub phase: String,
}

/// Atomically acquire every device needed by a bundle. Sorted acquisition makes
/// concurrent overlapping bundles deterministic; any foreign owner rolls the
/// whole transaction back, so execution never begins with a partial lock set.
pub async fn acquire_bundle_change_windows(
    pool: &MySqlPool,
    bundle_id: u64,
    owner_token: &str,
    device_ids: &[u64],
) -> Result<()> {
    anyhow::ensure!(
        !owner_token.trim().is_empty(),
        "empty change-window owner token"
    );
    let mut devices = device_ids.to_vec();
    devices.sort_unstable();
    devices.dedup();
    let mut tx = pool.begin().await?;
    let recovery_child: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(bundle_id)
    .fetch_one(&mut *tx)
    .await?;
    for device_id in devices {
        if recovery_child == 0 {
            let quarantined:i64=sqlx::query_scalar("SELECT COUNT(*) FROM device_change_window_sources WHERE device_id=? AND source_bundle_id<>?")
                .bind(device_id).bind(bundle_id).fetch_one(&mut *tx).await?;
            anyhow::ensure!(
                quarantined == 0,
                "device {device_id} retains recovery ownership from another activation"
            );
        }
        let existing = sqlx::query_as::<_, ChangeWindow>(
            "SELECT device_id, bundle_id, reroute_id, owner_token, phase \
             FROM device_change_windows WHERE device_id = ? FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;
        match existing {
            Some(window)
                if window.owner_token == owner_token && window.bundle_id == Some(bundle_id) => {}
            Some(window) => anyhow::bail!(
                "device {} config is owned by another activation ({})",
                window.device_id,
                window.owner_token
            ),
            None => {
                sqlx::query(
                    "INSERT INTO device_change_windows \
                        (device_id, bundle_id, owner_token, phase) \
                     VALUES (?, ?, ?, 'prepared')",
                )
                .bind(device_id)
                .bind(bundle_id)
                .bind(owner_token)
                .execute(&mut *tx)
                .await?;
            }
        }
        if recovery_child == 0 {
            sqlx::query("INSERT IGNORE INTO device_change_window_sources(device_id,source_bundle_id) VALUES(?,?)")
                .bind(device_id).bind(bundle_id).execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(())
}

/// True when the device has no change window or it belongs to `owner_token`.
/// Read failures propagate so callers can fail closed.
pub async fn change_window_allows(
    pool: &MySqlPool,
    device_id: u64,
    owner_token: Option<&str>,
) -> Result<bool> {
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_token FROM device_change_windows WHERE device_id = ?")
            .bind(device_id)
            .fetch_optional(pool)
            .await?;
    Ok(match owner {
        None => true,
        Some(owner) => owner_token.is_some_and(|candidate| candidate == owner),
    })
}

pub async fn set_bundle_change_window_phase(
    pool: &MySqlPool,
    bundle_id: u64,
    owner_token: &str,
    phase: &str,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            phase,
            "prepared" | "applying" | "compensating" | "uncertain"
        ),
        "invalid change-window phase"
    );
    sqlx::query(
        "UPDATE device_change_windows SET phase = ? \
         WHERE bundle_id = ? AND owner_token = ?",
    )
    .bind(phase)
    .bind(bundle_id)
    .bind(owner_token)
    .execute(pool)
    .await?;
    Ok(())
}

/// Release only the exact bundle owner. Unknown/uncertain outcomes never call
/// this; their rows intentionally survive until reconciliation.
pub async fn release_bundle_change_windows(
    pool: &MySqlPool,
    bundle_id: u64,
    owner_token: &str,
) -> Result<u64> {
    let result =
        sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ? AND owner_token = ?")
            .bind(bundle_id)
            .bind(owner_token)
            .execute(pool)
            .await?;
    Ok(result.rows_affected())
}

/// Transfer quarantined windows to an explicitly authorized recovery bundle.
/// Every original must be a reconciled owned mutation from one interrupted
/// source bundle; any remaining unknown sibling keeps the transfer fail-closed.
pub async fn claim_change_windows_for_recovery(
    pool: &MySqlPool,
    recovery_bundle_id: u64,
    owner_token: &str,
    original_reroute_ids: &[u64],
) -> Result<()> {
    anyhow::ensure!(
        !original_reroute_ids.is_empty(),
        "recovery has no originals"
    );
    let mut ids = original_reroute_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    anyhow::ensure!(
        ids.len() == original_reroute_ids.len(),
        "duplicate recovery original"
    );
    let mut tx = pool.begin().await?;
    let mut sources: Vec<u64> = Vec::new();
    for original_id in &ids {
        let source: Option<u64> = sqlx::query_scalar(
            "SELECT bundle_id FROM reroutes WHERE id=? AND rollback_of_reroute_id IS NULL FOR UPDATE",
        ).bind(original_id).fetch_optional(&mut *tx).await?.flatten();
        sources.push(
            source
                .ok_or_else(|| anyhow::anyhow!("original #{original_id} has no source bundle"))?,
        );
    }
    sources.sort_unstable();
    sources.dedup();
    let ownership = super::recovery::ownership_for_sources_on(&mut tx, &sources).await?;
    let mut owned = ownership.original_reroute_ids;
    owned.sort_unstable();
    anyhow::ensure!(
        owned == ids,
        "recovery originals no longer equal the complete owned set"
    );
    for source_id in &sources {
        let mapped: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM recovery_attempt_sources ras JOIN reroute_bundles source ON source.id=ras.source_bundle_id \
             WHERE ras.recovery_bundle_id=? AND ras.source_bundle_id=? AND ras.settlement='active' \
               AND source.recovery_claim_token=ras.claim_token",
        ).bind(recovery_bundle_id).bind(source_id).fetch_one(&mut *tx).await?;
        anyhow::ensure!(
            mapped == 1,
            "source bundle #{source_id} is not claimed by this recovery child"
        );
    }
    let devices: Vec<u64> = sqlx::query_scalar(
        "SELECT DISTINCT device_id FROM reroutes WHERE id IN (SELECT original_reroute_id FROM reroute_bundle_actions WHERE bundle_id=?) ORDER BY device_id FOR UPDATE",
    ).bind(recovery_bundle_id).fetch_all(&mut *tx).await?;
    for device_id in devices {
        let foreign: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM device_change_window_sources membership \
             LEFT JOIN recovery_attempt_sources ras ON ras.recovery_bundle_id=? AND ras.source_bundle_id=membership.source_bundle_id AND ras.settlement='active' \
             WHERE membership.device_id=? AND ras.source_bundle_id IS NULL",
        ).bind(recovery_bundle_id).bind(device_id).fetch_one(&mut *tx).await?;
        anyhow::ensure!(
            foreign == 0,
            "device {device_id} also quarantines an unclaimed source activation"
        );
        let existing: Option<(Option<u64>, String)> = sqlx::query_as(
            "SELECT bundle_id,owner_token FROM device_change_windows WHERE device_id=? FOR UPDATE",
        )
        .bind(device_id)
        .fetch_optional(&mut *tx)
        .await?;
        match existing {
            Some((Some(bundle), _))
                if sources.contains(&bundle) || bundle == recovery_bundle_id =>
            {
                sqlx::query("UPDATE device_change_windows SET bundle_id=?,reroute_id=NULL,owner_token=?,phase='prepared' WHERE device_id=?")
                    .bind(recovery_bundle_id).bind(owner_token).bind(device_id).execute(&mut *tx).await?;
            }
            Some((None, _)) => {
                sqlx::query("UPDATE device_change_windows SET bundle_id=?,reroute_id=NULL,owner_token=?,phase='prepared' WHERE device_id=?")
                    .bind(recovery_bundle_id).bind(owner_token).bind(device_id).execute(&mut *tx).await?;
            }
            Some(_) => anyhow::bail!("device {device_id} has a foreign live change-window owner"),
            None => {
                sqlx::query("INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase) VALUES(?,?,?,'prepared')")
                    .bind(device_id).bind(recovery_bundle_id).bind(owner_token).execute(&mut *tx).await?;
            }
        }
    }
    let started = sqlx::query(
        "UPDATE reroute_bundles source JOIN recovery_attempt_sources ras ON ras.source_bundle_id=source.id \
         SET source.lifecycle_state='recovery_running',source.recovery_started_at=COALESCE(source.recovery_started_at,UTC_TIMESTAMP()) \
         WHERE ras.recovery_bundle_id=? AND ras.settlement='active' AND source.recovery_claim_token=ras.claim_token",
    ).bind(recovery_bundle_id).execute(&mut *tx).await?;
    anyhow::ensure!(
        started.rows_affected() == sources.len() as u64,
        "not every source claim transferred at recovery start"
    );
    tx.commit().await?;
    Ok(())
}

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
    reroute_id: Option<u64>,
    kind: &str,
    reason: &str,
    by: Option<u64>,
) -> Result<u64> {
    let res = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reroute_id, reason, kind, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(scope)
    .bind(scope_ref)
    .bind(reroute_id)
    .bind(reason)
    .bind(kind)
    .bind(by)
    .execute(pool)
    .await
    .context("creating lock")?;
    Ok(res.last_insert_id())
}

/// Transaction-scoped variant used by crash recovery so state, lock, alert, and
/// audit either all commit or all remain retryable on the next startup.
pub async fn create_on(
    conn: &mut sqlx::MySqlConnection,
    scope: &str,
    scope_ref: Option<&str>,
    reroute_id: Option<u64>,
    kind: &str,
    reason: &str,
    by: Option<u64>,
) -> Result<u64> {
    let res = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reroute_id, reason, kind, created_by) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(scope)
    .bind(scope_ref)
    .bind(reroute_id)
    .bind(reason)
    .bind(kind)
    .bind(by)
    .execute(conn)
    .await
    .context("creating transaction-scoped lock")?;
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
    let rows = sqlx::query_as::<
        _,
        (
            u64,
            String,
            Option<String>,
            Option<u64>,
            Option<String>,
            String,
            chrono::DateTime<chrono::Utc>,
        ),
    >(
        "SELECT id, scope, scope_ref, reroute_id, reason, kind, created_at \
         FROM locks WHERE cleared_at IS NULL ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .context("listing locks")?;
    Ok(rows
        .into_iter()
        .map(
            |(id, scope, scope_ref, reroute_id, reason, kind, created_at)| {
                json!({
                    "id": id,
                    "scope": scope,
                    "scope_ref": scope_ref,
                    "reroute_id": reroute_id,
                    "reason": reason,
                    "kind": kind,
                    "created_at": created_at.to_rfc3339(),
                })
            },
        )
        .collect())
}
