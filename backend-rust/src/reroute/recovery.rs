//! Durable ownership and whole-run recovery helpers.

use serde_json::json;
use sqlx::{MySql, MySqlPool, Transaction};

use crate::config::Config;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryOwnership {
    pub source_bundle_ids: Vec<u64>,
    pub original_reroute_ids: Vec<u64>,
}

#[derive(Debug, Clone, Copy)]
struct SourceProof {
    root_originals: i64,
    complete_activation_coverage: bool,
    ambiguous_effects: i64,
}

impl SourceProof {
    fn has_activation_coverage(self) -> bool {
        self.complete_activation_coverage
    }
}

async fn source_proof_on(
    tx: &mut Transaction<'_, MySql>,
    source_id: u64,
) -> anyhow::Result<SourceProof> {
    let (state, total_actions): (String, u32) =
        sqlx::query_as("SELECT state,total_actions FROM reroute_bundles WHERE id=? FOR UPDATE")
            .bind(source_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(|| anyhow::anyhow!("source bundle #{source_id} does not exist"))?;
    let root_originals: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND rollback_of_reroute_id IS NULL",
    )
    .bind(source_id)
    .fetch_one(&mut **tx)
    .await?;
    let ambiguous_effects: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes original WHERE original.bundle_id=? \
         AND original.rollback_of_reroute_id IS NULL AND (original.state IN ('planned','pending','running','verifying','uncertain') \
           OR original.mutation_effect IN ('pending','unknown') \
           OR EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
             AND (inverse.state IN ('planned','pending','running','verifying','uncertain') \
               OR inverse.mutation_effect IN ('pending','unknown','changed') AND inverse.state<>'succeeded')))",
    )
    .bind(source_id)
    .fetch_one(&mut **tx)
    .await?;
    let (ledger_slots, invalid_slots, linked_root_slots): (i64, i64, i64) = sqlx::query_as(
        "SELECT COUNT(*), \
           CAST(COALESCE(SUM(position>=? OR NOT ( \
             EXISTS(SELECT 1 FROM reroutes original WHERE original.id=action.reroute_id \
               AND original.bundle_id=action.bundle_id AND original.bundle_position=action.position \
               AND original.rollback_of_reroute_id IS NULL) \
             OR (action.reroute_id IS NULL AND action.state IN ('queued','noop','failed','compensated') \
               AND action.mutation_effect IN ('pending','noop')))),0) AS SIGNED), \
           CAST(COALESCE(SUM(EXISTS(SELECT 1 FROM reroutes original WHERE original.id=action.reroute_id \
             AND original.bundle_id=action.bundle_id AND original.bundle_position=action.position \
             AND original.rollback_of_reroute_id IS NULL)),0) AS SIGNED) \
         FROM reroute_bundle_actions action WHERE bundle_id=?",
    )
    .bind(total_actions)
    .bind(source_id)
    .fetch_one(&mut **tx)
    .await?;
    let source_is_terminal = !matches!(state.as_str(), "planned" | "running" | "compensating");
    let complete_activation_coverage = if total_actions == 0 {
        source_is_terminal && root_originals > 0
    } else {
        source_is_terminal
            && ((ledger_slots == i64::from(total_actions)
                && invalid_slots == 0
                && linked_root_slots == root_originals)
                || (ledger_slots == 0 && root_originals == i64::from(total_actions)))
    };
    Ok(SourceProof {
        root_originals,
        complete_activation_coverage,
        ambiguous_effects,
    })
}

/// One ownership definition used by preview, admission, execution and repair.
/// Callers that already hold source rows use the transaction variant so claims
/// and the exact remaining-id comparison share one connection and snapshot.
pub async fn ownership_for_sources_on(
    tx: &mut Transaction<'_, MySql>,
    source_ids: &[u64],
) -> anyhow::Result<RecoveryOwnership> {
    let mut sources = source_ids.to_vec();
    sources.sort_unstable();
    sources.dedup();
    anyhow::ensure!(!sources.is_empty(), "recovery has no source activations");
    let mut originals = Vec::new();
    for source_id in &sources {
        let proof = source_proof_on(tx, *source_id).await?;
        anyhow::ensure!(
            proof.has_activation_coverage(),
            "source bundle #{source_id} has no durable activation coverage"
        );
        anyhow::ensure!(
            proof.ambiguous_effects == 0,
            "source bundle #{source_id} has in-flight or ambiguous recovery evidence"
        );
        let mut ids: Vec<u64> = sqlx::query_scalar(
            "SELECT original.id FROM reroutes original WHERE original.bundle_id=? \
             AND original.rollback_of_reroute_id IS NULL \
             AND original.state IN ('succeeded','failed') AND original.mutation_effect='changed' \
             AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
               AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop')) \
             ORDER BY original.bundle_position DESC,original.id DESC",
        ).bind(source_id).fetch_all(&mut **tx).await?;
        originals.append(&mut ids);
    }
    originals.sort_unstable_by(|a, b| b.cmp(a));
    Ok(RecoveryOwnership {
        source_bundle_ids: sources,
        original_reroute_ids: originals,
    })
}

pub async fn ownership_for_sources(
    pool: &MySqlPool,
    source_ids: &[u64],
) -> anyhow::Result<RecoveryOwnership> {
    let mut tx = pool.begin().await?;
    let ownership = ownership_for_sources_on(&mut tx, source_ids).await?;
    tx.commit().await?;
    Ok(ownership)
}

pub async fn repair_legacy_associations(pool: &MySqlPool) -> anyhow::Result<()> {
    let plans: Vec<(u64, sqlx::types::Json<serde_json::Value>)> = sqlx::query_as(
        "SELECT bundle_id,snapshot_json FROM execution_plans WHERE bundle_id IS NOT NULL AND consumed_at IS NOT NULL \
         AND NOT EXISTS(SELECT 1 FROM recovery_attempt_sources ras WHERE ras.recovery_bundle_id=execution_plans.bundle_id)",
    ).fetch_all(pool).await?;
    for (child_id, snapshot) in plans {
        let mut originals = snapshot
            .0
            .get("source")
            .and_then(|source| source.get("original_reroute_ids"))
            .and_then(|value| value.as_array())
            .map(|ids| ids.iter().filter_map(|id| id.as_u64()).collect::<Vec<_>>())
            .unwrap_or_default();
        if originals.is_empty() {
            originals = snapshot
                .0
                .get("actions")
                .and_then(|value| value.as_array())
                .map(|actions| {
                    actions
                        .iter()
                        .filter_map(|action| {
                            action.get("original_reroute_id").and_then(|id| id.as_u64())
                        })
                        .collect()
                })
                .unwrap_or_default();
        }
        if originals.is_empty() {
            continue;
        }
        let mut tx = pool.begin().await?;
        for original_id in originals {
            let source:Option<u64>=sqlx::query_scalar("SELECT bundle_id FROM reroutes WHERE id=? AND rollback_of_reroute_id IS NULL FOR UPDATE")
                .bind(original_id).fetch_optional(&mut *tx).await?.flatten();
            if let Some(source_id) = source {
                sqlx::query("INSERT IGNORE INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token) VALUES(?,?,?)")
                    .bind(child_id).bind(source_id).bind(format!("legacy:child:{child_id}")).execute(&mut *tx).await?;
            }
        }
        tx.commit().await?;
    }
    Ok(())
}

pub async fn claim_sources_for_child_on(
    tx: &mut Transaction<'_, MySql>,
    child_id: u64,
    source_ids: &[u64],
    expected_original_ids: &[u64],
    token: &str,
    manual: bool,
) -> anyhow::Result<RecoveryOwnership> {
    let ownership = ownership_for_sources_on(tx, source_ids).await?;
    let mut expected = expected_original_ids.to_vec();
    expected.sort_unstable_by(|a, b| b.cmp(a));
    anyhow::ensure!(
        ownership.original_reroute_ids == expected,
        "recovery ownership changed; prepare a fresh preview"
    );
    for source_id in &ownership.source_bundle_ids {
        let changed = sqlx::query(
            "UPDATE reroute_bundles SET recovery_claim_token=?,recovery_claimed_at=UTC_TIMESTAMP(), \
             recovery_bundle_id=IF(?,recovery_bundle_id,?),lifecycle_state='recovery_claimed', \
             automatic_recovery_block_reason=IF(?,NULL,automatic_recovery_block_reason) \
             WHERE id=? AND (recovery_claim_token IS NULL OR recovery_claim_token=?) \
               AND (? OR automatic_recovery_cancelled_at IS NULL)"
        ).bind(token).bind(manual).bind(child_id).bind(manual).bind(source_id).bind(token).bind(manual).execute(&mut **tx).await?;
        anyhow::ensure!(
            changed.rows_affected() == 1,
            "source bundle #{source_id} recovery was already claimed or cancelled"
        );
        sqlx::query("INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token) VALUES(?,?,?)")
            .bind(child_id).bind(source_id).bind(token).execute(&mut **tx).await?;
    }
    for original_id in &ownership.original_reroute_ids {
        sqlx::query(
            "INSERT IGNORE INTO device_change_window_sources(device_id,source_bundle_id) \
            SELECT device_id,bundle_id FROM reroutes WHERE id=? AND bundle_id IS NOT NULL",
        )
        .bind(original_id)
        .execute(&mut **tx)
        .await?;
    }
    Ok(ownership)
}

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
    Ok(ownership_for_sources(pool, &[bundle_id])
        .await?
        .original_reroute_ids)
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
           AND JSON_TYPE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) = 'INTEGER' \
           AND CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) AS UNSIGNED) BETWEEN 60 AND 604800",
    ).bind(bundle_id).execute(pool).await?;
    Ok(())
}

/// Claim and execute at most one due timer. The durable claim prevents another
/// scheduler/restart from starting the same recovery; failures remain visible
/// and require operator takeover/reconciliation rather than blind retry.
pub async fn process_one_due(pool: &MySqlPool, cfg: &Config) -> anyhow::Result<bool> {
    let runtime = cfg.advisory_runtime(pool).await?;
    crate::db::advisory::background_scope(runtime, Box::pin(process_one_due_inner(pool, cfg)))
        .await?
}

async fn process_one_due_inner(pool: &MySqlPool, cfg: &Config) -> anyhow::Result<bool> {
    let Some(recovery_id) = admit_one_due_with_failure(pool, cfg, false).await? else {
        return Ok(false);
    };
    if let Err(error) =
        crate::detection::engine::submit_scheduled_recovery_worker(pool, cfg, recovery_id).await
    {
        finalize_recovery_child(
            pool,
            recovery_id,
            "failed",
            Some(&format!("worker submission failed: {error:#}")),
            &format!("recovery:bundle:{recovery_id}"),
        )
        .await?;
    }
    Ok(true)
}

#[doc(hidden)]
pub async fn admit_one_due_with_failure(
    pool: &MySqlPool,
    cfg: &Config,
    fail_before_commit: bool,
) -> anyhow::Result<Option<u64>> {
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
    let mut tx = pool.begin().await?;
    let candidate:Option<u64>=sqlx::query_scalar("SELECT id FROM reroute_bundles WHERE lifecycle_state='recovery_scheduled' AND recovery_deadline<=UTC_TIMESTAMP() AND recovery_claim_token IS NULL AND JSON_TYPE(JSON_EXTRACT(source_json,'$.revert_after_seconds'))='INTEGER' AND CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) AS UNSIGNED) BETWEEN 60 AND 604800 AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.verification_mode')),'routing')<>'configuration_only' AND automatic_recovery_cancelled_at IS NULL ORDER BY recovery_deadline,id LIMIT 1 FOR UPDATE")
        .fetch_optional(&mut *tx).await?;
    let Some(source_id) = candidate else {
        tx.commit().await?;
        fence.release().await?;
        return Ok(None);
    };
    let ownership = ownership_for_sources_on(&mut tx, &[source_id]).await?;
    anyhow::ensure!(
        !ownership.original_reroute_ids.is_empty(),
        "run owns no remaining invertible mutations"
    );
    let originals = ownership.original_reroute_ids;
    let token = format!("timer-recovery:{}", crate::auth::sessions::generate_token());
    let reason = format!("scheduled recovery of mitigation run #{source_id}");
    let recovery_id=sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,reason,state,failure_policy,total_actions,source_json) VALUES(?,'automatic',?,'planned','abort_and_compensate',?,?)")
        .bind(source_id).bind(&reason).bind(originals.len() as u32)
        .bind(sqlx::types::Json(json!({"kind":"recovery","original_bundle_id":source_id,"original_reroute_ids":originals,"reason":reason,"preparation_phase":"published"})))
        .execute(&mut *tx).await?.last_insert_id();
    claim_sources_for_child_on(
        &mut tx,
        recovery_id,
        &[source_id],
        &originals,
        &token,
        false,
    )
    .await?;
    if fail_before_commit {
        tx.rollback().await?;
        fence.release().await?;
        anyhow::bail!("injected timer admission failure")
    }
    tx.commit().await?;
    fence.release().await?;
    Ok(Some(recovery_id))
}

/// Persist the full immutable ledger before exposing a child association. This
/// is a public fault-test seam and the production scheduled-recovery path.
#[doc(hidden)]
pub async fn persist_and_associate_scheduled_child(
    pool: &MySqlPool,
    child_id: u64,
    source_id: u64,
    originals: &[u64],
    token: &str,
    actions: &[super::bundle::BundleAction],
    source_json: serde_json::Value,
) -> anyhow::Result<()> {
    super::bundle::persist_actions(pool, child_id, actions).await?;
    let mut tx = pool.begin().await?;
    claim_sources_for_child_on(&mut tx, child_id, &[source_id], originals, token, false).await?;
    sqlx::query("UPDATE reroute_bundles SET parent_bundle_id=?,source_json=?,lifecycle_state='recovery_running',recovery_started_at=UTC_TIMESTAMP() WHERE id=?")
        .bind(source_id)
        .bind(sqlx::types::Json(source_json))
        .bind(child_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
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
    if let Some(id) = child {
        let mapped: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=? AND source_bundle_id=?")
            .bind(id).bind(source_id).fetch_one(pool).await?;
        if mapped > 0 {
            finalize_recovery_child(
                pool,
                id,
                "failed",
                Some(reason),
                &format!("recovery:bundle:{id}"),
            )
            .await?;
            let settlement: Option<String> = sqlx::query_scalar("SELECT settlement FROM recovery_attempt_sources WHERE recovery_bundle_id=? AND source_bundle_id=?")
                .bind(id).bind(source_id).fetch_optional(pool).await?;
            return Ok(settlement.as_deref() == Some("known_no_write"));
        }
    }
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
    let mapped: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(child_id)
    .fetch_one(pool)
    .await?;
    if mapped > 0 {
        return finalize_recovery_child(
            pool,
            child_id,
            "failed",
            Some(reason),
            &format!("recovery:bundle:{child_id}"),
        )
        .await;
    }
    for source_id in source_ids {
        if !release_claim_if_proven_no_write(pool, *source_id, Some(child_id), reason).await? {
            sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_blocked',automatic_recovery_block_reason=? WHERE id=?")
                .bind(reason).bind(source_id).execute(pool).await?;
        }
    }
    Ok(())
}

/// Idempotently settle one recovery child and every source associated with the
/// claim that actually created it. Older children can never clear a newer
/// source claim because every update compares the persisted association token.
pub async fn finalize_recovery_child(
    pool: &MySqlPool,
    child_id: u64,
    terminal_state: &str,
    reason: Option<&str>,
    owner_token: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        matches!(
            terminal_state,
            "succeeded" | "failed" | "aborted" | "compensation_blocked"
        ),
        "invalid recovery terminal state"
    );
    let mut tx = pool.begin().await?;
    let child: Option<(String, u32)> =
        sqlx::query_as("SELECT state,total_actions FROM reroute_bundles WHERE id=? FOR UPDATE")
            .bind(child_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((current_state, total_actions)) = child else {
        anyhow::bail!("recovery child does not exist")
    };
    let mappings: Vec<(u64,String,String)> = sqlx::query_as(
        "SELECT source_bundle_id,claim_token,settlement FROM recovery_attempt_sources WHERE recovery_bundle_id=? ORDER BY source_bundle_id FOR UPDATE",
    ).bind(child_id).fetch_all(&mut *tx).await?;
    anyhow::ensure!(
        !mappings.is_empty(),
        "recovery child has no durable source association"
    );
    sqlx::query(
        "UPDATE reroute_bundles source JOIN recovery_attempt_sources ras ON ras.source_bundle_id=source.id \
         SET source.recovery_claim_token=ras.claim_token,source.recovery_bundle_id=ras.recovery_bundle_id, \
             source.recovery_claimed_at=COALESCE(source.recovery_claimed_at,UTC_TIMESTAMP()) \
         WHERE ras.recovery_bundle_id=? AND ras.settlement IN ('active','blocked') AND ras.claim_token LIKE 'legacy:child:%' \
           AND source.recovery_claim_token IS NULL",
    ).bind(child_id).execute(&mut *tx).await?;
    let source_claims: Vec<(u64, Option<String>)> = sqlx::query_as(
        "SELECT source.id,source.recovery_claim_token FROM reroute_bundles source \
         JOIN recovery_attempt_sources ras ON ras.source_bundle_id=source.id \
         WHERE ras.recovery_bundle_id=? ORDER BY source.id FOR UPDATE",
    )
    .bind(child_id)
    .fetch_all(&mut *tx)
    .await?;
    let stale_claims = mappings.iter().any(|mapping| {
        !matches!(mapping.2.as_str(), "restored" | "known_no_write")
            && source_claims
                .iter()
                .find(|source| source.0 == mapping.0)
                .is_none_or(|source| source.1.as_deref() != Some(mapping.1.as_str()))
    });
    let dangerous: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND (state IN ('pending','running','verifying','uncertain') \
           OR mutation_effect IN ('pending','unknown') OR (state='failed' AND mutation_effect='changed'))",
    ).bind(child_id).fetch_one(&mut *tx).await?;
    let ledger_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=?")
            .bind(child_id)
            .fetch_one(&mut *tx)
            .await?;
    let immutable_plan: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM execution_plans WHERE bundle_id=? AND consumed_at IS NOT NULL AND JSON_LENGTH(JSON_EXTRACT(snapshot_json,'$.actions'))=?",
    ).bind(child_id).bind(total_actions).fetch_one(&mut *tx).await?;
    let published_prewrite_marker:i64=sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundles WHERE id=? AND state='planned' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.kind'))='recovery' AND JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.preparation_phase')) IN ('published','preparing') AND NOT EXISTS(SELECT 1 FROM reroutes WHERE bundle_id=?)")
        .bind(child_id).bind(child_id).fetch_one(&mut *tx).await?;
    let complete_plan = ledger_count == i64::from(total_actions)
        || (current_state == "planned" && (immutable_plan == 1 || published_prewrite_marker == 1));
    let mut source_proofs = std::collections::BTreeMap::new();
    for (source_id, _, _) in &mappings {
        source_proofs.insert(*source_id, source_proof_on(&mut tx, *source_id).await?);
    }
    let missing_source_coverage = source_proofs
        .values()
        .any(|proof| !proof.has_activation_coverage());
    let ambiguous_source_evidence = source_proofs
        .values()
        .any(|proof| proof.ambiguous_effects > 0);
    let freeze_all = stale_claims
        || dangerous > 0
        || !complete_plan
        || missing_source_coverage
        || ambiguous_source_evidence;
    let mut restored = 0usize;
    let mut retryable = 0usize;
    let mut blocked = 0usize;
    for (source_id, claim_token, prior_settlement) in &mappings {
        let proof = source_proofs[source_id];
        let claim_matches = source_claims
            .iter()
            .find(|source| source.0 == *source_id)
            .is_some_and(|source| source.1.as_deref() == Some(claim_token.as_str()));
        let remaining: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM reroutes original WHERE original.bundle_id=? \
             AND original.rollback_of_reroute_id IS NULL AND original.mutation_effect IN ('changed','unknown') \
             AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
               AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop'))",
        )
        .bind(source_id)
        .fetch_one(&mut *tx)
        .await?;
        let claim_is_ours =
            matches!(prior_settlement.as_str(), "restored" | "known_no_write") || claim_matches;
        let settlement =
            if freeze_all || !claim_is_ours || (terminal_state == "succeeded" && remaining > 0) {
                "blocked"
            } else if remaining == 0 && proof.root_originals > 0 {
                "restored"
            } else {
                "known_no_write"
            };
        let settlement_unchanged = prior_settlement == settlement;
        sqlx::query("UPDATE recovery_attempt_sources SET settled_at=IF(?,settled_at,UTC_TIMESTAMP()),settlement=? WHERE recovery_bundle_id=? AND source_bundle_id=?")
            .bind(settlement_unchanged).bind(settlement).bind(child_id).bind(source_id).execute(&mut *tx).await?;
        match settlement {
            "restored" => {
                restored += 1;
                if claim_matches {
                    sqlx::query("UPDATE reroute_bundles SET state=IF(state IN ('aborted','compensation_blocked'),'compensated',state),lifecycle_state='inactive',remaining_mutations=0,recovery_claim_token=NULL,recovery_claimed_at=NULL,recovery_started_at=NULL,recovery_bundle_id=NULL,recovery_deadline=NULL,automatic_recovery_block_reason=NULL WHERE id=? AND recovery_claim_token=?")
                        .bind(source_id).bind(claim_token).execute(&mut *tx).await?;
                }
                sqlx::query("DELETE FROM device_change_window_sources WHERE source_bundle_id=?")
                    .bind(source_id)
                    .execute(&mut *tx)
                    .await?;
                // A frozen activation can reserve devices whose siblings never
                // started. Those windows are not transferred by an inverse
                // ledger, but must be released once the entire source is
                // proved restored. Foreign quarantine membership still wins.
                sqlx::query("DELETE w FROM device_change_windows AS w WHERE w.bundle_id=? AND NOT EXISTS(SELECT 1 FROM device_change_window_sources membership WHERE membership.device_id=w.device_id)")
                    .bind(source_id).execute(&mut *tx).await?;
            }
            "known_no_write" => {
                retryable += 1;
                if claim_matches {
                    sqlx::query("UPDATE reroute_bundles SET lifecycle_state=IF(remaining_mutations>0,'active','inactive'),recovery_claim_token=NULL,recovery_claimed_at=NULL,recovery_started_at=NULL,recovery_bundle_id=NULL,recovery_deadline=NULL,automatic_recovery_block_reason=? WHERE id=? AND recovery_claim_token=?")
                        .bind(reason.unwrap_or("recovery failed before any router write")).bind(source_id).bind(claim_token).execute(&mut *tx).await?;
                }
            }
            _ => {
                blocked += 1;
                if claim_matches {
                    sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_blocked',automatic_recovery_block_reason=? WHERE id=? AND recovery_claim_token=?")
                        .bind(reason.unwrap_or("recovery outcome is unproven")).bind(source_id).bind(claim_token).execute(&mut *tx).await?;
                }
            }
        }
    }
    let final_state = if blocked > 0 {
        "compensation_blocked"
    } else if restored == mappings.len() {
        "succeeded"
    } else {
        terminal_state
    };
    let terminal_state_unchanged = current_state == final_state;
    sqlx::query("UPDATE reroute_bundles SET failure_reason=IF(?,failure_reason,?),state=?,finished_at=COALESCE(finished_at,UTC_TIMESTAMP()),rate_reserved_actions=0 WHERE id=? AND state IN ('planned','running','compensating','succeeded','failed','aborted','compensation_blocked')")
        .bind(terminal_state_unchanged).bind(reason).bind(final_state).bind(child_id).execute(&mut *tx).await?;
    if blocked == 0 && retryable == 0 {
        sqlx::query("DELETE w FROM device_change_windows AS w WHERE NOT EXISTS(SELECT 1 FROM device_change_window_sources membership WHERE membership.device_id=w.device_id) AND (w.bundle_id=? OR (w.bundle_id IS NULL AND w.owner_token=CONCAT('quarantine:device:',w.device_id))) AND EXISTS(SELECT 1 FROM reroute_bundle_actions action WHERE action.bundle_id=? AND action.device_id=w.device_id)")
            .bind(child_id).bind(child_id).execute(&mut *tx).await?;
    } else if blocked == 0 {
        sqlx::query("UPDATE device_change_windows SET bundle_id=NULL,reroute_id=NULL,owner_token=CONCAT('quarantine:device:',device_id),phase='prepared' WHERE bundle_id=? AND owner_token=?")
            .bind(child_id).bind(owner_token).execute(&mut *tx).await?;
    } else {
        sqlx::query("UPDATE device_change_windows SET bundle_id=NULL,reroute_id=NULL,owner_token=CONCAT('quarantine:device:',device_id),phase='uncertain' WHERE bundle_id=?")
            .bind(child_id).execute(&mut *tx).await?;
    }
    let event = if blocked == 0 && retryable == 0 {
        "recovery_settled"
    } else if blocked == 0 {
        "recovery_retryable"
    } else {
        "recovery_blocked"
    };
    sqlx::query("INSERT INTO audit_logs(actor_type,event_type,entity_type,entity_id,message) SELECT 'system',?,'reroute_bundle',?,? WHERE NOT EXISTS(SELECT 1 FROM audit_logs WHERE event_type=? AND entity_type='reroute_bundle' AND entity_id=?)")
        .bind(event).bind(child_id).bind(reason.unwrap_or(event)).bind(event).bind(child_id).execute(&mut *tx).await?;
    if blocked > 0 {
        let dedup_key = format!("recovery_degraded:child:{child_id}");
        sqlx::query("INSERT INTO alerts(event_type,severity,payload_json,dedup_key) SELECT 'recovery_degraded','critical',?,? WHERE NOT EXISTS(SELECT 1 FROM alerts WHERE dedup_key=?)")
            .bind(sqlx::types::Json(json!({"bundle_id":child_id,"source_bundle_ids":mappings.iter().map(|row|row.0).collect::<Vec<_>>(),"blocked_sources":blocked,"remaining_sources":retryable,"reason":reason,"operator_action":"reconcile every ambiguous inverse before retrying recovery"})))
            .bind(&dedup_key).bind(&dedup_key).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Admission seam used by the scheduler and concurrency tests. It performs no
/// device read or write; one durable row claim is its only state transition.
#[doc(hidden)]
pub async fn claim_one_due(
    pool: &MySqlPool,
    cfg: &Config,
) -> anyhow::Result<Option<(u64, String)>> {
    let runtime = cfg.advisory_runtime(pool).await?;
    crate::db::advisory::background_scope(runtime, Box::pin(claim_one_due_inner(pool, cfg))).await?
}

async fn claim_one_due_inner(
    pool: &MySqlPool,
    cfg: &Config,
) -> anyhow::Result<Option<(u64, String)>> {
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
         AND JSON_TYPE(JSON_EXTRACT(source_json,'$.revert_after_seconds'))='INTEGER' \
         AND CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) AS UNSIGNED) BETWEEN 60 AND 604800 \
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
