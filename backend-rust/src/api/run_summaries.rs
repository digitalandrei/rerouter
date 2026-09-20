//! Read model for one logical mitigation run.
//!
//! `reroute_bundles` is the lifecycle owner. Individual `reroutes` are action
//! evidence beneath that run and recovery bundles are children of their source
//! run. Keep this representation shared by list, detail and saved-definition
//! callers so operators never have to infer lifecycle from action events.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::{MySql, MySqlPool, QueryBuilder};

#[derive(Debug, sqlx::FromRow)]
pub(crate) struct RunSummaryRow {
    pub id: u64,
    pub parent_bundle_id: Option<u64>,
    pub recovery_bundle_id: Option<u64>,
    pub rule_id: Option<u64>,
    pub trigger_type: String,
    pub state: String,
    pub failure_policy: String,
    pub reason: Option<String>,
    pub total_actions: u32,
    pub completed_actions: u32,
    pub failure_reason: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub source_json: Option<sqlx::types::Json<Value>>,
    pub triggered_by_user_id: Option<u64>,
    pub triggered_by: Option<String>,
    pub lifecycle_state: String,
    pub remaining_mutations: u32,
    pub recovery_deadline: Option<DateTime<Utc>>,
    pub recovery_claim_token: Option<String>,
    pub automatic_recovery_cancelled_at: Option<DateTime<Utc>>,
    pub automatic_recovery_block_reason: Option<String>,
    pub automatic_recovery_possible: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use sqlx::{mysql::MySqlPoolOptions, Execute};
    use std::time::Instant;

    #[test]
    fn substring_filters_use_literal_locate_not_like_wildcards() {
        let mut query = QueryBuilder::<MySql>::new(
            "SELECT b.id FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id",
        );
        push_filters(
            &mut query,
            &RunSummaryFilter {
                q: Some("100%_\\"),
                device: Some("edge_%\\"),
                ..Default::default()
            },
        );
        let built = query.build();
        let sql = built.sql();
        assert!(sql.contains("LOCATE("));
        assert!(!sql.contains(" LIKE "));
    }

    async fn session_selects(pool: &MySqlPool) -> anyhow::Result<u64> {
        let (_, value): (String, String) = sqlx::query_as("SHOW SESSION STATUS LIKE 'Com_select'")
            .fetch_one(pool)
            .await?;
        Ok(value.parse()?)
    }

    fn process_rss_kib() -> Option<u64> {
        std::fs::read_to_string("/proc/self/status")
            .ok()?
            .lines()
            .find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
    }

    #[tokio::test]
    async fn manual_recovery_does_not_offer_automatic_recovery_cancellation() {
        let database = crate::db::connect_test_database().await;
        let bundle_id = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations) VALUES('manual','succeeded','abort_and_compensate',1,1,'active',1)")
            .execute(database.pool()).await.unwrap().last_insert_id();

        let manual = one(database.pool(), bundle_id).await.unwrap().unwrap();
        assert_eq!(manual["take_control"]["available"], false);
        assert_eq!(
            manual["take_control"]["block_reasons"][0],
            "run has no automatic recovery to cancel"
        );

        sqlx::query("UPDATE reroute_bundles SET lifecycle_state='recovery_scheduled',recovery_deadline=DATE_ADD(UTC_TIMESTAMP(),INTERVAL 1 HOUR) WHERE id=?")
            .bind(bundle_id).execute(database.pool()).await.unwrap();
        let timed = one(database.pool(), bundle_id).await.unwrap().unwrap();
        assert_eq!(timed["take_control"]["available"], true);

        sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
            .bind(bundle_id)
            .execute(database.pool())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn active_run_pages_keep_a_constant_real_query_budget() {
        const PAGE_SIZE: u32 = 25;
        const PAGES: u64 = 6;
        const SELECTS_PER_PAGE: u64 = 5;

        let database = crate::db::connect_test_database().await;
        // A single physical connection makes the session counter authoritative:
        // every count/list/enrichment query and both status reads use this same
        // server session.
        let options = database.pool().connect_options().as_ref().clone();
        let measured = MySqlPoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .expect("connect measured one-connection pool");

        let token = uuid::Uuid::new_v4().simple().to_string();
        let literal = format!("load-{token}-%_\\source");
        let device_name = format!("edge-{token}-%_\\device");
        let device_id = sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,?,0)")
            .bind(&device_name)
            .bind(format!("{token}.invalid"))
            .execute(&measured)
            .await
            .expect("insert load fixture device")
            .last_insert_id();
        let lower = Utc::now() - Duration::hours(1);
        let upper = Utc::now() + Duration::hours(1);
        let mut bundle_ids = Vec::with_capacity((PAGE_SIZE as u64 * PAGES) as usize);
        let mut action_ids = Vec::with_capacity(bundle_ids.capacity() / 2);
        let mut reroute_ids = Vec::with_capacity(bundle_ids.capacity() / 2);

        let outcome: anyhow::Result<(u64, usize, u128, Option<u64>)> = async {
            for position in 0..PAGE_SIZE as u64 * PAGES {
                let source_name = format!("{literal}-{position:03}");
                let bundle_id = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,failure_policy,total_actions,completed_actions,source_json,lifecycle_state,remaining_mutations,created_at) VALUES('manual','succeeded','abort_and_compensate',1,1,?,'active',1,UTC_TIMESTAMP())")
                    .bind(sqlx::types::Json(json!({"kind":"manual","name":source_name})))
                    .execute(&measured).await?.last_insert_id();
                bundle_ids.push(bundle_id);
                if position % 2 == 0 {
                    let action_id = sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,state,mutation_effect) VALUES(?,0,?,'{}','{}','{}','succeeded','changed')")
                        .bind(bundle_id).bind(device_id).execute(&measured).await?.last_insert_id();
                    action_ids.push(action_id);
                } else {
                    let reroute_id = sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect) VALUES(?,0,?,'manual','succeeded','changed')")
                        .bind(bundle_id).bind(device_id).execute(&measured).await?.last_insert_id();
                    reroute_ids.push(reroute_id);
                }
            }

            let started = Instant::now();
            let rss_before = process_rss_kib();
            let mut total_selects = 0u64;
            let mut response_bytes = 0usize;
            for page in 0..PAGES {
                let filter = RunSummaryFilter {
                    q: Some(&literal),
                    source_kind: Some("manual"),
                    device: Some(&device_name),
                    created_from: Some(lower),
                    created_to: Some(upper),
                    original_only: true,
                    ..Default::default()
                };
                let before = session_selects(&measured).await?;
                let total = count(&measured, &filter).await?;
                anyhow::ensure!(total == (PAGE_SIZE as u64 * PAGES) as i64, "literal/date filters lost fixtures: {total}");
                let rows = list(&measured, &filter, PAGE_SIZE, page * PAGE_SIZE as u64).await?;
                anyhow::ensure!(rows.len() == PAGE_SIZE as usize, "page {page} returned {} rows", rows.len());
                response_bytes += serde_json::to_vec(&rows)?.len();
                let used = session_selects(&measured).await?.saturating_sub(before);
                anyhow::ensure!(used <= SELECTS_PER_PAGE, "page {page} used {used} SELECTs; expected count + list + three enrichments");
                total_selects += used;
            }
            Ok((total_selects, response_bytes, started.elapsed().as_millis(), rss_before.zip(process_rss_kib()).map(|(before, after)| after.saturating_sub(before))))
        }
        .await;

        for id in action_ids {
            let _ = sqlx::query("DELETE FROM reroute_bundle_actions WHERE id=?")
                .bind(id)
                .execute(&measured)
                .await;
        }
        for id in reroute_ids {
            let _ = sqlx::query("DELETE FROM reroutes WHERE id=?")
                .bind(id)
                .execute(&measured)
                .await;
        }
        for id in bundle_ids {
            let _ = sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
                .bind(id)
                .execute(&measured)
                .await;
        }
        let _ = sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device_id)
            .execute(&measured)
            .await;

        let (query_count, response_bytes, elapsed_ms, rss_delta_kib) =
            outcome.expect("bounded active-runs load regression");
        eprintln!(
            "HARDENING_ACTIVE_RUNS_LOAD {}",
            json!({
                "fixtures": PAGE_SIZE as u64 * PAGES,
                "pages": PAGES,
                "page_size": PAGE_SIZE,
                "selects": query_count,
                "max_selects_per_page": SELECTS_PER_PAGE,
                "elapsed_ms": elapsed_ms,
                "response_bytes": response_bytes,
                "rss_delta_kib": rss_delta_kib,
            })
        );
    }
}

const SELECT: &str =
    "SELECT b.id,b.parent_bundle_id,b.recovery_bundle_id,b.rule_id,b.trigger_type,\
    b.state,b.failure_policy,b.reason,b.total_actions,b.completed_actions,b.failure_reason,\
    b.started_at,b.finished_at,b.created_at,b.source_json,b.triggered_by_user_id,\
    u.email AS triggered_by,b.lifecycle_state,b.remaining_mutations,b.recovery_deadline,\
    b.recovery_claim_token,b.automatic_recovery_cancelled_at,b.automatic_recovery_block_reason,\
    (b.recovery_deadline IS NOT NULL OR (b.trigger_type='automatic' AND EXISTS(\
      SELECT 1 FROM rules recovery_rule WHERE recovery_rule.id=b.rule_id \
      AND recovery_rule.enabled=1 AND recovery_rule.automatic_revert_enabled=1))) AS automatic_recovery_possible \
    FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id";

#[derive(Default)]
pub(crate) struct RunSummaryFilter<'a> {
    pub lifecycle: Option<&'a str>,
    pub trigger_type: Option<&'a str>,
    pub rule_id: Option<u64>,
    pub preset_id: Option<u64>,
    pub original_only: bool,
    pub q: Option<&'a str>,
    pub source_kind: Option<&'a str>,
    pub device: Option<&'a str>,
    pub created_from: Option<DateTime<Utc>>,
    pub created_to: Option<DateTime<Utc>>,
}

fn push_filters<'a>(query: &mut QueryBuilder<'a, MySql>, filter: &RunSummaryFilter<'a>) {
    query.push(" WHERE 1=1");
    if filter.original_only {
        query.push(" AND b.parent_bundle_id IS NULL");
    }
    if let Some(lifecycle) = filter.lifecycle.filter(|value| *value != "all") {
        match lifecycle {
            "active" => {
                // A recovery child is evidence beneath its source mitigation,
                // never a second active mitigation of its own.
                query.push(" AND b.parent_bundle_id IS NULL AND (b.remaining_mutations>0 OR b.state IN ('planned','running','compensating') OR b.lifecycle_state<>'inactive')");
            }
            "inactive" => {
                query.push(" AND b.remaining_mutations=0 AND b.state NOT IN ('planned','running','compensating') AND b.lifecycle_state='inactive'");
            }
            other => {
                query.push(" AND b.lifecycle_state=").push_bind(other);
            }
        }
    }
    if let Some(trigger_type) = filter.trigger_type {
        query.push(" AND b.trigger_type=").push_bind(trigger_type);
    }
    if let Some(rule_id) = filter.rule_id {
        query.push(" AND b.rule_id=").push_bind(rule_id);
    }
    if let Some(preset_id) = filter.preset_id {
        query
            .push(" AND JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.preset_id'))=")
            .push_bind(preset_id.to_string());
    }
    if let Some(source_kind) = filter.source_kind.filter(|v| !v.is_empty()) {
        query
            .push(
                " AND COALESCE(JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.kind')),b.trigger_type)=",
            )
            .push_bind(source_kind);
    }
    if let Some(from) = filter.created_from.as_ref() {
        query.push(" AND b.created_at>=").push_bind(from.to_owned());
    }
    if let Some(to) = filter.created_to.as_ref() {
        query.push(" AND b.created_at<").push_bind(to.to_owned());
    }
    if let Some(device) = filter.device.filter(|v| !v.trim().is_empty()) {
        let value = device.trim();
        let numeric = value.parse::<u64>().ok();
        let needle = value.to_lowercase();
        query.push(" AND (EXISTS(SELECT 1 FROM reroute_bundle_actions fba JOIN devices fd ON fd.id=fba.device_id WHERE fba.bundle_id=b.id AND (");
        if let Some(id) = numeric {
            query.push("fba.device_id=").push_bind(id).push(" OR ");
        }
        query
            .push("LOCATE(").push_bind(needle.clone()).push(",LOWER(fd.name))>0")
            .push(")) OR EXISTS(SELECT 1 FROM reroutes fr JOIN devices fd ON fd.id=fr.device_id WHERE fr.bundle_id=b.id AND (");
        if let Some(id) = numeric {
            query.push("fr.device_id=").push_bind(id).push(" OR ");
        }
        query
            .push("LOCATE(")
            .push_bind(needle)
            .push(",LOWER(fd.name))>0)))");
    }
    if let Some(q) = filter.q.filter(|v| !v.trim().is_empty()) {
        let needle = q.trim().to_lowercase();
        query.push(" AND (LOCATE(").push_bind(needle.clone()).push(",CAST(b.id AS CHAR))>0")
            .push(" OR LOCATE(").push_bind(needle.clone()).push(",LOWER(COALESCE(JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.preset_name')),JSON_UNQUOTE(JSON_EXTRACT(b.source_json,'$.name')),'')))>0")
            .push(" OR LOCATE(").push_bind(needle.clone()).push(",LOWER(b.trigger_type))>0")
            .push(" OR LOCATE(").push_bind(needle.clone()).push(",LOWER(b.lifecycle_state))>0")
            .push(" OR LOCATE(").push_bind(needle).push(",LOWER(COALESCE(u.email,'')))>0)");
    }
}

pub(crate) async fn count(pool: &MySqlPool, filter: &RunSummaryFilter<'_>) -> anyhow::Result<i64> {
    let mut query = QueryBuilder::<MySql>::new(
        "SELECT COUNT(*) FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id",
    );
    push_filters(&mut query, filter);
    Ok(query.build_query_scalar().fetch_one(pool).await?)
}

pub(crate) async fn list(
    pool: &MySqlPool,
    filter: &RunSummaryFilter<'_>,
    limit: u32,
    offset: u64,
) -> anyhow::Result<Vec<Value>> {
    let mut query = QueryBuilder::<MySql>::new(SELECT);
    push_filters(&mut query, filter);
    query
        .push(" ORDER BY b.id DESC LIMIT ")
        .push_bind(limit)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = query
        .build_query_as::<RunSummaryRow>()
        .fetch_all(pool)
        .await?;
    enrich(pool, rows).await
}

pub(crate) async fn one(pool: &MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, RunSummaryRow>(&format!("{SELECT} WHERE b.id=?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(enrich(pool, vec![row]).await?.pop())
}

pub(crate) async fn recent_for_preset(
    pool: &MySqlPool,
    preset_id: u64,
    limit: u32,
) -> anyhow::Result<Vec<Value>> {
    list(
        pool,
        &RunSummaryFilter {
            preset_id: Some(preset_id),
            original_only: true,
            ..Default::default()
        },
        limit,
        0,
    )
    .await
}

/// Every currently active original run for a saved definition. This is kept
/// separate from the bounded recent-history slice: an applied run can remain
/// active while many newer no-op, failed, or already-reverted runs accumulate.
pub(crate) async fn active_for_preset(
    pool: &MySqlPool,
    preset_id: u64,
) -> anyhow::Result<Vec<Value>> {
    list(
        pool,
        &RunSummaryFilter {
            lifecycle: Some("active"),
            preset_id: Some(preset_id),
            original_only: true,
            ..Default::default()
        },
        256,
        0,
    )
    .await
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    bundle_id: u64,
    device_id: u64,
    device_name: String,
}

#[derive(sqlx::FromRow)]
struct UnknownRow {
    bundle_id: u64,
    unknown_effects: i64,
}

#[derive(sqlx::FromRow)]
struct RecoveryRow {
    parent_bundle_id: u64,
    id: u64,
    state: String,
    total_actions: u32,
    completed_actions: u32,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    failure_reason: Option<String>,
}

fn push_ids(query: &mut QueryBuilder<'_, MySql>, ids: &[u64]) {
    let mut separated = query.separated(",");
    for id in ids {
        separated.push_bind(*id);
    }
}

async fn enrich(pool: &MySqlPool, rows: Vec<RunSummaryRow>) -> anyhow::Result<Vec<Value>> {
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let ids = rows.iter().map(|row| row.id).collect::<Vec<_>>();

    // The immutable action ledger is authoritative. The UNION keeps legacy
    // bundles visible if they predate that ledger.
    let mut devices_query = QueryBuilder::<MySql>::new(
        "SELECT x.bundle_id,x.device_id,d.name AS device_name FROM (\
         SELECT bundle_id,device_id FROM reroute_bundle_actions WHERE bundle_id IN (",
    );
    push_ids(&mut devices_query, &ids);
    devices_query.push(") UNION SELECT bundle_id,device_id FROM reroutes WHERE bundle_id IN (");
    push_ids(&mut devices_query, &ids);
    devices_query.push(") AND bundle_id NOT IN (SELECT DISTINCT bundle_id FROM reroute_bundle_actions)) x JOIN devices d ON d.id=x.device_id ORDER BY x.bundle_id,x.device_id");
    let device_rows = devices_query
        .build_query_as::<DeviceRow>()
        .fetch_all(pool)
        .await?;
    let mut devices: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for row in device_rows {
        if seen.insert((row.bundle_id, row.device_id)) {
            devices.entry(row.bundle_id).or_default().push(json!({
                "id":row.device_id,"name":row.device_name,
                "device_id":row.device_id,"device_name":row.device_name,
            }));
        }
    }

    let mut unknown_query = QueryBuilder::<MySql>::new(
        "SELECT original.bundle_id,COUNT(*) AS unknown_effects FROM reroutes original \
         WHERE original.bundle_id IN (",
    );
    push_ids(&mut unknown_query, &ids);
    unknown_query.push(") AND original.rollback_of_reroute_id IS NULL AND original.mutation_effect='unknown' \
        AND NOT EXISTS(SELECT 1 FROM reroutes inverse WHERE inverse.rollback_of_reroute_id=original.id \
        AND inverse.state='succeeded' AND inverse.mutation_effect IN ('changed','noop')) GROUP BY original.bundle_id");
    let unknown_rows = unknown_query
        .build_query_as::<UnknownRow>()
        .fetch_all(pool)
        .await?;
    let unknown = unknown_rows
        .into_iter()
        .map(|row| (row.bundle_id, row.unknown_effects.max(0) as u32))
        .collect::<BTreeMap<_, _>>();

    // The association ledger covers current manual, scheduled and multi-source
    // children. Older runs are associated only by a durable direct parent or an
    // inverse linked to one of the source's root actions. Any explicit mapping
    // wins as a group, even when a newer legacy-looking child exists.
    let mut recovery_query = QueryBuilder::<MySql>::new(
        "SELECT latest.source_bundle_id AS parent_bundle_id,child.id,child.state,child.total_actions,child.completed_actions,\
         child.started_at,child.finished_at,child.failure_reason FROM reroute_bundles child \
         JOIN (SELECT candidates.source_bundle_id,\
         COALESCE(MAX(CASE WHEN candidates.explicit_assoc=1 THEN candidates.child_id END),\
                  MAX(CASE WHEN candidates.explicit_assoc=0 THEN candidates.child_id END)) AS id \
         FROM (SELECT source_bundle_id,recovery_bundle_id AS child_id,1 AS explicit_assoc \
         FROM recovery_attempt_sources WHERE source_bundle_id IN (",
    );
    push_ids(&mut recovery_query, &ids);
    recovery_query.push(
        ") UNION ALL SELECT legacy_child.parent_bundle_id AS source_bundle_id,legacy_child.id AS child_id,0 AS explicit_assoc \
         FROM reroute_bundles legacy_child WHERE legacy_child.parent_bundle_id IN (",
    );
    push_ids(&mut recovery_query, &ids);
    recovery_query.push(
        ") AND NOT EXISTS(SELECT 1 FROM recovery_attempt_sources explicit_child \
         WHERE explicit_child.recovery_bundle_id=legacy_child.id) \
         UNION ALL SELECT original.bundle_id AS source_bundle_id,inverse.bundle_id AS child_id,0 AS explicit_assoc \
         FROM reroutes inverse JOIN reroutes original ON original.id=inverse.rollback_of_reroute_id \
         WHERE original.rollback_of_reroute_id IS NULL AND original.bundle_id IN (",
    );
    push_ids(&mut recovery_query, &ids);
    recovery_query.push(
        ") AND inverse.bundle_id IS NOT NULL AND inverse.bundle_id<>original.bundle_id \
         AND NOT EXISTS(SELECT 1 FROM recovery_attempt_sources explicit_child \
         WHERE explicit_child.recovery_bundle_id=inverse.bundle_id)) candidates \
         GROUP BY candidates.source_bundle_id) latest ON latest.id=child.id",
    );
    let recovery_rows = recovery_query
        .build_query_as::<RecoveryRow>()
        .fetch_all(pool)
        .await?;
    let latest_recoveries = recovery_rows
        .into_iter()
        .map(|recovery| {
            let parent = recovery.parent_bundle_id;
            (
                parent,
                json!({
                    "id":recovery.id,"parent_bundle_id":recovery.parent_bundle_id,
                    "state":recovery.state,"total_actions":recovery.total_actions,
                    "completed_actions":recovery.completed_actions,"started_at":recovery.started_at,
                    "finished_at":recovery.finished_at,"failure_reason":recovery.failure_reason,
                }),
            )
        })
        .collect::<BTreeMap<_, _>>();

    Ok(rows
        .into_iter()
        .map(|row| {
            let source = row.source_json.map(|value| value.0).unwrap_or(Value::Null);
            let affected_devices = devices.remove(&row.id).unwrap_or_default();
            let latest_recovery = if row.parent_bundle_id.is_none() {
                latest_recoveries.get(&row.id).cloned()
            } else {
                None
            };
            let latest_recovery_bundle_id = latest_recovery
                .as_ref()
                .and_then(|recovery| recovery.get("id"))
                .and_then(Value::as_u64);
            let unknown_effects = unknown.get(&row.id).copied().unwrap_or(0);
            let remaining_changes = row.remaining_mutations.saturating_sub(unknown_effects);
            let mut block_reasons = Vec::new();
            if row.parent_bundle_id.is_some() {
                block_reasons.push("recovery runs are evidence beneath their source mitigation".to_string());
            }
            if row.recovery_claim_token.is_some()
                || matches!(row.lifecycle_state.as_str(), "recovery_claimed" | "recovery_running")
            {
                block_reasons.push("recovery is already claimed or running".to_string());
            }
            if row.remaining_mutations == 0 {
                block_reasons.push("no owned mutations remain".to_string());
            }
            if unknown_effects > 0 {
                block_reasons.push("one or more action effects are unknown; reconcile them before recovery".to_string());
            }
            if latest_recovery.as_ref().and_then(|r|r.get("state")).and_then(Value::as_str)
                .is_some_and(|state| matches!(state,"planned"|"pending"|"running"|"verifying"|"compensating")) {
                block_reasons.push("a recovery run is already in flight".to_string());
            }
            let revert_available = block_reasons.is_empty();
            let mut take_control_reasons=Vec::new();
            if !row.automatic_recovery_possible { take_control_reasons.push("run has no automatic recovery to cancel".to_string()); }
            if !matches!(row.lifecycle_state.as_str(),"active"|"recovery_scheduled") { take_control_reasons.push("run has no cancellable automatic recovery".to_string()); }
            if row.recovery_claim_token.is_some() { take_control_reasons.push("recovery is already claimed or running".to_string()); }
            let take_control_available=take_control_reasons.is_empty();
            let verification_mode = source
                .get("verification_mode")
                .cloned()
                .unwrap_or_else(|| json!("routing"));
            let routing_verified = source.get("routing_verified").cloned();
            json!({
                "id":row.id,"parent_bundle_id":row.parent_bundle_id,"recovery_bundle_id":row.recovery_bundle_id,
                "latest_recovery_bundle_id":latest_recovery_bundle_id,"latest_recovery":latest_recovery,
                "rule_id":row.rule_id,"trigger_type":row.trigger_type,"state":row.state,
                "execution_state":row.state,"failure_policy":row.failure_policy,"reason":row.reason,
                "total_actions":row.total_actions,"completed_actions":row.completed_actions,
                "failure_reason":row.failure_reason,"started_at":row.started_at,"finished_at":row.finished_at,
                "created_at":row.created_at,"source":source,
                "triggered_by_user_id":row.triggered_by_user_id,"triggered_by":row.triggered_by,
                "lifecycle_state":row.lifecycle_state,"remaining_mutations":row.remaining_mutations,
                "remaining_changes":remaining_changes,"unknown_effects":unknown_effects,
                "active":row.remaining_mutations>0,"affected_devices":affected_devices,
                "recovery_deadline":row.recovery_deadline,
                "automatic_recovery_cancelled_at":row.automatic_recovery_cancelled_at,
                "automatic_recovery_block_reason":row.automatic_recovery_block_reason,
                "revert":{"available":revert_available,"block_reasons":block_reasons,"noop":row.remaining_mutations==0},
                "take_control":{"available":take_control_available,"block_reasons":take_control_reasons},
                "verification_mode":verification_mode,"routing_verified":routing_verified,
            })
        })
        .collect())
}
