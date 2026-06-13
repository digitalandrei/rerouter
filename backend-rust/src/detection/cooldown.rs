//! Cooldown bookkeeping — throttles repeated actions (per-rule, per-device,
//! per-asset, global). A cooldown is a `cooldowns` row with an `until` in the
//! future. See ../docs/reroute-engine.md.

use anyhow::{Context, Result};
use sqlx::MySqlPool;

/// The active cooldown's `until` instant, if this scope/ref is currently
/// throttled (a row with `until` in the future); else `None`.
pub async fn active_until(
    pool: &MySqlPool,
    scope: &str,
    scope_ref: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let until = sqlx::query_scalar::<_, chrono::DateTime<chrono::Utc>>(
        "SELECT until FROM cooldowns \
         WHERE scope = ? AND scope_ref = ? AND until > UTC_TIMESTAMP() \
         ORDER BY until DESC LIMIT 1",
    )
    .bind(scope)
    .bind(scope_ref)
    .fetch_optional(pool)
    .await
    .context("checking cooldown")?;
    Ok(until)
}

/// Record a cooldown window of `seconds` from now for a scope/ref.
pub async fn record(pool: &MySqlPool, scope: &str, scope_ref: &str, seconds: i64, reason: &str) -> Result<()> {
    sqlx::query(
        "INSERT INTO cooldowns (scope, scope_ref, until, reason) \
         VALUES (?, ?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND), ?)",
    )
    .bind(scope)
    .bind(scope_ref)
    .bind(seconds)
    .bind(reason)
    .execute(pool)
    .await
    .context("recording cooldown")?;
    Ok(())
}
