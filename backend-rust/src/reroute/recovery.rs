//! Durable ownership and whole-run recovery helpers.

use serde_json::json;
use sqlx::MySqlPool;

use crate::config::Config;

pub async fn claim_source_bundles(
    pool: &MySqlPool,
    bundle_ids: &[u64],
    token: &str,
) -> anyhow::Result<()> {
    let mut ids = bundle_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    let mut tx = pool.begin().await?;
    for id in ids {
        let changed=sqlx::query("UPDATE reroute_bundles SET recovery_claim_token=?,recovery_claimed_at=UTC_TIMESTAMP(),lifecycle_state='recovery_claimed' WHERE id=? AND recovery_claim_token IS NULL AND automatic_recovery_cancelled_at IS NULL")
            .bind(token).bind(id).execute(&mut *tx).await?;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "source bundle #{id} recovery was claimed or cancelled"
        );
    }
    tx.commit().await?;
    Ok(())
}

pub async fn release_unstarted_source_claims(
    pool: &MySqlPool,
    bundle_ids: &[u64],
    token: &str,
    reason: &str,
) -> anyhow::Result<()> {
    for id in bundle_ids {
        sqlx::query("UPDATE reroute_bundles SET recovery_claim_token=NULL,recovery_claimed_at=NULL,lifecycle_state=IF(remaining_mutations>0,'active','inactive'),automatic_recovery_block_reason=? WHERE id=? AND recovery_claim_token=? AND recovery_bundle_id IS NULL")
        .bind(reason).bind(id).bind(token).execute(pool).await?;
    }
    Ok(())
}

/// Original changed actions still owned by an activation, newest first so the
/// inverse sequence restores the run in strict reverse order.
pub async fn owned_original_ids(pool: &MySqlPool, bundle_id: u64) -> anyhow::Result<Vec<u64>> {
    let uncertain: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND rollback_of_reroute_id IS NULL \
        AND (state='uncertain' OR mutation_effect IN ('unknown','pending'))",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    anyhow::ensure!(
        uncertain == 0,
        "run has uncertain or unreconciled actions; whole-run recovery is frozen"
    );
    Ok(sqlx::query_scalar(
        "SELECT r.id FROM reroutes r WHERE r.bundle_id=? \
           AND r.rollback_of_reroute_id IS NULL \
           AND r.mutation_effect='changed' AND r.state IN ('succeeded','failed') \
           AND NOT EXISTS (SELECT 1 FROM reroutes inverse \
             WHERE inverse.rollback_of_reroute_id=r.id AND inverse.state='succeeded' \
               AND inverse.mutation_effect IN ('changed','noop')) \
         ORDER BY r.bundle_position DESC,r.id DESC",
    )
    .bind(bundle_id)
    .fetch_all(pool)
    .await?)
}

/// Recompute lifecycle from immutable action ownership. Execution result and
/// lifecycle deliberately remain separate dimensions.
pub async fn refresh(pool: &MySqlPool, bundle_id: u64) -> anyhow::Result<u32> {
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes r WHERE r.bundle_id=? \
           AND r.rollback_of_reroute_id IS NULL \
           AND r.mutation_effect IN ('changed','unknown') \
           AND NOT EXISTS (SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=r.id \
             AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop'))",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    let uncertain: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND (state='uncertain' OR mutation_effect='unknown')",
    )
    .bind(bundle_id)
    .fetch_one(pool)
    .await?;
    let lifecycle = if uncertain > 0 {
        "recovery_blocked"
    } else if remaining > 0 {
        "active"
    } else {
        "inactive"
    };
    sqlx::query("UPDATE reroute_bundles SET remaining_mutations=?, lifecycle_state= \
        IF(lifecycle_state IN ('recovery_scheduled','recovery_claimed','recovery_running'),lifecycle_state,?) WHERE id=?")
        .bind(remaining)
        .bind(lifecycle)
        .bind(bundle_id)
        .execute(pool)
        .await?;
    Ok(remaining as u32)
}

/// Start the optional timer only after a fully successful activation owns a
/// mutation. No-op, partial, failed and uncertain runs never get a deadline.
pub async fn schedule_if_eligible(pool: &MySqlPool, bundle_id: u64) -> anyhow::Result<()> {
    let remaining = refresh(pool, bundle_id).await?;
    if remaining == 0 {
        return Ok(());
    }
    sqlx::query(
        "UPDATE reroute_bundles SET recovery_deadline=DATE_ADD(finished_at, INTERVAL \
           CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) AS UNSIGNED) SECOND), \
           lifecycle_state='recovery_scheduled' \
         WHERE id=? AND state='succeeded' AND trigger_type='manual' \
           AND recovery_deadline IS NULL \
           AND automatic_recovery_cancelled_at IS NULL \
           AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')<>'configuration_only' \
           AND JSON_EXTRACT(source_json,'$.revert_after_seconds') IS NOT NULL",
    ).bind(bundle_id).execute(pool).await?;
    Ok(())
}

/// Claim and execute at most one due timer. The durable claim prevents another
/// scheduler/restart from starting the same recovery; failures remain visible
/// and require operator takeover/reconciliation rather than blind retry.
pub async fn process_one_due(pool: &MySqlPool, cfg: &Config) -> anyhow::Result<bool> {
    let Some((source_id, token)) = claim_one_due(pool, cfg).await? else {
        return Ok(false);
    };
    let result = async {
        let originals=owned_original_ids(pool,source_id).await?;
        anyhow::ensure!(!originals.is_empty(),"run owns no remaining invertible mutations");
        let reason=format!("scheduled recovery of mitigation run #{source_id}");
        let actions=crate::reroute::preparation::prepare_rollbacks(pool,&originals,&reason,true).await?;
        let device_ids=actions.iter().map(|a|a.device_id).collect::<Vec<_>>();
        let identities=crate::ssh::RusshExecutor::new(pool.clone()).transport_identities(&device_ids).await?;
        let policy=super::bundle::FailurePolicy::AbortAndCompensate;
        let recovery_id=super::bundle::create(pool,None,None,"automatic",None,&reason,policy,actions.len() as u32).await?;
        sqlx::query("UPDATE reroute_bundles SET parent_bundle_id=?,source_json=?,lifecycle_state='recovery_running',recovery_started_at=UTC_TIMESTAMP() WHERE id=?")
            .bind(source_id).bind(sqlx::types::Json(json!({"kind":"recovery","original_bundle_id":source_id,"original_reroute_ids":originals,"transport_identities":identities})))
            .bind(recovery_id).execute(pool).await?;
        sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=?,lifecycle_state='recovery_running',recovery_started_at=UTC_TIMESTAMP() WHERE id=? AND recovery_claim_token=?")
            .bind(recovery_id).bind(source_id).bind(&token).execute(pool).await?;
        super::bundle::persist_actions(pool,recovery_id,&actions).await?;
        let outcome=super::bundle::run(pool,cfg,super::bundle::BundleRun::scheduled_recovery(recovery_id,policy),actions).await;
        anyhow::ensure!(outcome.state=="succeeded","scheduled recovery ended {}",outcome.state);
        refresh(pool,source_id).await?;
        Ok::<(),anyhow::Error>(())
    }.await;
    if let Err(e) = result {
        let reason = format!("{e:#}");
        if !release_claim_if_proven_no_write(pool, source_id, None, &reason).await? {
            sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_blocked',automatic_recovery_block_reason=? WHERE id=? AND recovery_claim_token=?")
                .bind(reason).bind(source_id).bind(&token).execute(pool).await?;
        }
    }
    Ok(true)
}

/// Release a recovery claim only when durable evidence proves that no child
/// write started. Unknown or in-flight effects keep the source quarantined.
pub async fn release_claim_if_proven_no_write(
    pool: &MySqlPool,
    source_id: u64,
    child_id: Option<u64>,
    reason: &str,
) -> anyhow::Result<bool> {
    let child = match child_id {
        Some(id) => Some(id),
        None => sqlx::query_scalar("SELECT recovery_bundle_id FROM reroute_bundles WHERE id=?")
            .bind(source_id)
            .fetch_optional(pool)
            .await?
            .flatten(),
    };
    let unsafe_count: i64 = if let Some(id) = child {
        sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND (state IN ('pending','running','verifying','uncertain') OR mutation_effect IN ('changed','unknown'))").bind(id).fetch_one(pool).await?
    } else {
        0
    };
    if unsafe_count > 0 {
        return Ok(false);
    }
    sqlx::query("UPDATE reroute_bundles SET recovery_claim_token=NULL,recovery_claimed_at=NULL,recovery_started_at=NULL,recovery_bundle_id=NULL,recovery_deadline=NULL,lifecycle_state=IF(remaining_mutations>0,'active','inactive'),automatic_recovery_block_reason=? WHERE id=?")
        .bind(reason).bind(source_id).execute(pool).await?;
    Ok(true)
}

pub async fn settle_failed_recovery_sources(
    pool: &MySqlPool,
    source_ids: &[u64],
    child_id: u64,
    reason: &str,
) -> anyhow::Result<()> {
    for source_id in source_ids {
        if !release_claim_if_proven_no_write(pool, *source_id, Some(child_id), reason).await? {
            sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_blocked',automatic_recovery_block_reason=? WHERE id=?")
                .bind(reason).bind(source_id).execute(pool).await?;
        }
    }
    Ok(())
}

/// Admission seam used by the scheduler and concurrency tests. It performs no
/// device read or write; one durable row claim is its only state transition.
#[doc(hidden)]
pub async fn claim_one_due(
    pool: &MySqlPool,
    cfg: &Config,
) -> anyhow::Result<Option<(u64, String)>> {
    // A crash before a child recovery is created made no router write. Release
    // only those pre-start claims; started recoveries remain frozen for startup
    // reconciliation and are never resumed blindly.
    sqlx::query("UPDATE reroute_bundles SET recovery_claim_token=NULL,recovery_claimed_at=NULL,lifecycle_state='recovery_scheduled' \
        WHERE lifecycle_state='recovery_claimed' AND recovery_started_at IS NULL AND recovery_bundle_id IS NULL \
          AND recovery_claimed_at < DATE_SUB(UTC_TIMESTAMP(),INTERVAL 5 MINUTE)")
        .execute(pool).await?;
    let fence = crate::reroute::guard::policy_fence(pool).await?;
    if crate::api::settings::operating_mode(pool, cfg).await != "enforce"
        || !crate::api::settings::bool_setting(
            pool,
            "automatic_actions_enabled",
            cfg.safety.automatic_actions_enabled,
        )
        .await
    {
        fence.release().await?;
        return Ok(None);
    }
    let token = crate::auth::sessions::generate_token();
    let mut tx = pool.begin().await?;
    let candidate: Option<u64> = sqlx::query_scalar(
        "SELECT id FROM reroute_bundles WHERE lifecycle_state='recovery_scheduled' \
         AND recovery_deadline<=UTC_TIMESTAMP() AND recovery_claim_token IS NULL \
         AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')<>'configuration_only' \
         AND automatic_recovery_cancelled_at IS NULL ORDER BY recovery_deadline,id LIMIT 1 FOR UPDATE",
    ).fetch_optional(&mut *tx).await?;
    let Some(source_id) = candidate else {
        tx.commit().await?;
        fence.release().await?;
        return Ok(None);
    };
    let claimed = sqlx::query(
        "UPDATE reroute_bundles SET recovery_claim_token=?,recovery_claimed_at=UTC_TIMESTAMP(), \
        lifecycle_state='recovery_claimed' WHERE id=? AND recovery_claim_token IS NULL",
    )
    .bind(&token)
    .bind(source_id)
    .execute(&mut *tx)
    .await?;
    anyhow::ensure!(claimed.rows_affected() == 1, "timer claim conflict");
    tx.commit().await?;
    fence.release().await?;
    Ok(Some((source_id, token)))
}
