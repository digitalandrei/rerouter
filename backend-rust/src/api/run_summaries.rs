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
}

const SELECT: &str =
    "SELECT b.id,b.parent_bundle_id,b.recovery_bundle_id,b.rule_id,b.trigger_type,\
    b.state,b.failure_policy,b.reason,b.total_actions,b.completed_actions,b.failure_reason,\
    b.started_at,b.finished_at,b.created_at,b.source_json,b.triggered_by_user_id,\
    u.email AS triggered_by,b.lifecycle_state,b.remaining_mutations,b.recovery_deadline,\
    b.recovery_claim_token,b.automatic_recovery_cancelled_at,b.automatic_recovery_block_reason \
    FROM reroute_bundles b LEFT JOIN users u ON u.id=b.triggered_by_user_id";

#[derive(Default)]
pub(crate) struct RunSummaryFilter<'a> {
    pub lifecycle: Option<&'a str>,
    pub trigger_type: Option<&'a str>,
    pub rule_id: Option<u64>,
    pub preset_id: Option<u64>,
    pub original_only: bool,
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
}

pub(crate) async fn count(pool: &MySqlPool, filter: &RunSummaryFilter<'_>) -> anyhow::Result<i64> {
    let mut query = QueryBuilder::<MySql>::new("SELECT COUNT(*) FROM reroute_bundles b");
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

    Ok(rows
        .into_iter()
        .map(|row| {
            let source = row.source_json.map(|value| value.0).unwrap_or(Value::Null);
            let affected_devices = devices.remove(&row.id).unwrap_or_default();
            let unknown_effects = unknown.get(&row.id).copied().unwrap_or(0);
            let remaining_changes = row.remaining_mutations.saturating_sub(unknown_effects);
            let mut block_reasons = Vec::new();
            if row.parent_bundle_id.is_some() {
                block_reasons.push("recovery runs are evidence beneath their source mitigation".to_string());
            }
            if let Some(reason) = row.automatic_recovery_block_reason.as_ref() {
                block_reasons.push(reason.clone());
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
            let revert_available = block_reasons.is_empty();
            let verification_mode = source
                .get("verification_mode")
                .cloned()
                .unwrap_or_else(|| json!("routing"));
            let routing_verified = source.get("routing_verified").cloned();
            json!({
                "id":row.id,"parent_bundle_id":row.parent_bundle_id,"recovery_bundle_id":row.recovery_bundle_id,
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
                "verification_mode":verification_mode,"routing_verified":routing_verified,
            })
        })
        .collect())
}
