//! Flow telemetry read API: per-device top-N (talkers / ports / interface
//! traffic) over a recent window, plus exporter health. Read-only — the flow
//! collector ([`crate::telemetry::flow`]) is a second telemetry source and
//! executes nothing. See ../../../docs/flow-telemetry.md.
//!
//! Reads require `view_asset`. Counts are stored RAW (sampled); these handlers
//! return both the raw sum and the sampling-scaled ESTIMATE (SUM(x * rate)) plus
//! flags so the UI can badge estimated / low-confidence values.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{MySql, QueryBuilder};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};

type JsonResp = (StatusCode, Json<Value>);

#[derive(sqlx::FromRow)]
struct ExporterHealthRow {
    id: u64,
    source_addr: String,
    observation_domain: u32,
    configured_sampling_rate: Option<u32>,
    reported_sampling_rate: Option<u32>,
    snmp_derived_rate: Option<u32>,
    effective_sampling_rate: u32,
    sampling_source: String,
    sampling_confidence: String,
    snmp_xcal_ratio: Option<f64>,
    last_packet_at: Option<chrono::DateTime<chrono::Utc>>,
    template_count: u32,
    datagrams_total: u64,
    dropped_no_template: u64,
    dropped_malformed: u64,
    dropped_bucket_backlog: u64,
    quality_bucket_ts: Option<chrono::DateTime<chrono::Utc>>,
    iface_complete: Option<bool>,
    port_complete: Option<bool>,
    asn_complete: Option<bool>,
    talker_complete: Option<bool>,
    iface_dropped: Option<u64>,
    port_dropped: Option<u64>,
    asn_dropped: Option<u64>,
    talker_dropped: Option<u64>,
}

/// Tuple shape for an aggregated talker row (search + top_talkers share it):
/// src, dst, src_port, dst_port, protocol, direction, then the six agg columns.
type TalkerAggRow = (
    String,
    String,
    Option<u16>,
    Option<u16>,
    u16,
    String,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
);

fn talker_json(r: TalkerAggRow) -> Value {
    let (src, dst, sp, dp, protocol, direction, eb, ep, rb, rp, mr, lc) = r;
    let mut v = agg_json(eb, ep, rb, rp, mr, lc);
    v["src_addr"] = json!(src);
    v["dst_addr"] = json!(dst);
    v["src_port"] = json!(sp);
    v["dst_port"] = json!(dp);
    v["protocol"] = json!(protocol);
    v["direction"] = json!(direction);
    v
}

#[derive(Debug, Deserialize)]
pub struct TopQuery {
    /// talkers | ports | as | traffic. Defaults to traffic.
    dimension: Option<String>,
    /// Restrict to one interface (device_interfaces.id).
    interface_id: Option<u64>,
    /// Window in minutes (default 60, clamped to the 48-hour retention window).
    minutes: Option<i64>,
    /// Order by estimated bytes (default) or pkts — pkts surfaces high-pps,
    /// low-bitrate floods (e.g. UDP/53).
    metric: Option<String>,
    /// For dimension=ports: src | dst (default dst).
    port_kind: Option<String>,
    /// For dimension=as: src | dst (default src — "top speakers").
    as_kind: Option<String>,
}

async fn device_exists(pool: &sqlx::MySqlPool, id: u64) -> bool {
    sqlx::query_scalar::<_, u64>("SELECT id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// GET /api/devices/{id}/flows/top — ranked top-10 for the chosen dimension.
pub async fn top(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(device_id): Path<u64>,
    Query(q): Query<TopQuery>,
) -> JsonResp {
    if !device_exists(&state.pool, device_id).await {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    let minutes = q.minutes.unwrap_or(60).clamp(1, 48 * 60);
    // Whitelist the ordering metric (interpolated into SQL — must never be raw input).
    let order = match q.metric.as_deref() {
        Some("pkts") => "est_pkts",
        _ => "est_bytes",
    };
    let dimension = q.dimension.as_deref().unwrap_or("traffic");
    let iface_filter = q.interface_id.is_some();

    let rows = match dimension {
        "talkers" => top_talkers(&state.pool, device_id, q.interface_id, minutes, order).await,
        "ports" => {
            let kind = match q.port_kind.as_deref() {
                Some("src") => "src",
                _ => "dst",
            };
            top_ports(&state.pool, device_id, q.interface_id, minutes, order, kind).await
        }
        "as" => {
            let kind = match q.as_kind.as_deref() {
                Some("dst") => "dst",
                _ => "src",
            };
            top_as(&state.pool, device_id, q.interface_id, minutes, order, kind).await
        }
        "traffic" => top_traffic(&state.pool, device_id, q.interface_id, minutes, order).await,
        _ => {
            return err(
                StatusCode::BAD_REQUEST,
                "dimension must be talkers, ports, as, or traffic",
            )
        }
    };

    match rows {
        Ok(out) => (
            StatusCode::OK,
            Json(
                json!({ "dimension": dimension, "minutes": minutes, "interface_filtered": iface_filter, "rows": out }),
            ),
        ),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// Common WHERE: device, time window, optional interface. Returns the SQL
/// fragment; binds are applied by the caller in the same order.
fn window_clause(table: &str, iface: bool) -> String {
    let mut w = format!(
        "FROM {table} WHERE device_id = ? AND bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)"
    );
    if iface {
        w.push_str(" AND interface_id = ?");
    }
    w
}

// Aggregate columns, in the order the per-dimension tuples place them last:
// est_bytes, est_pkts, raw_bytes, raw_pkts, max_rate, low_conf.
//
// low_conf here is DISPLAY-ONLY and VOLUME-WEIGHTED: the row is flagged low only
// when low-confidence buckets carry more than 10% of the raw sampled bytes in the
// window. A brief blip — e.g. the ~1-minute NetFlow-template re-learn after a
// controller restart writes a few default-rate (low) buckets — is a negligible
// share of an hour's bytes and no longer flags an otherwise fully-verified
// interface. This is deliberately LOOSER than the automatic-action gate, which
// stays strict/fail-safe: detection::engine and reroute::flow_target use
// MAX(sampling_confidence='low') so ANY unverified bucket blocks auto-reroute.
// Do NOT "align" them by loosening the engine gate — that would weaken the
// doctrine "low sampling confidence blocks flow-driven automatic actions".
fn agg_select() -> &'static str {
    "CAST(SUM(bytes * effective_sampling_rate) AS UNSIGNED) AS est_bytes, \
     CAST(SUM(pkts  * effective_sampling_rate) AS UNSIGNED) AS est_pkts, \
     CAST(SUM(bytes) AS UNSIGNED) AS raw_bytes, \
     CAST(SUM(pkts)  AS UNSIGNED) AS raw_pkts, \
     CAST(MAX(effective_sampling_rate) AS UNSIGNED) AS max_rate, \
     CAST(SUM(CASE WHEN sampling_confidence = 'low' THEN bytes ELSE 0 END) \
          > 0.10 * SUM(bytes) AS UNSIGNED) AS low_conf"
}

fn agg_json(
    est_bytes: u64,
    est_pkts: u64,
    raw_bytes: u64,
    raw_pkts: u64,
    max_rate: u64,
    low_conf: u64,
) -> Value {
    json!({
        "est_bytes": est_bytes,
        "est_pkts": est_pkts,
        "raw_bytes": raw_bytes,
        "raw_pkts": raw_pkts,
        "sampling_rate": max_rate,
        "estimated": max_rate > 1,
        "low_confidence": low_conf != 0,
    })
}

async fn top_traffic(
    pool: &sqlx::MySqlPool,
    device_id: u64,
    interface_id: Option<u64>,
    minutes: i64,
    order: &str,
) -> anyhow::Result<Vec<Value>> {
    let sql = format!(
        "SELECT if_index, interface_id, direction, {agg} {where_} \
         GROUP BY if_index, interface_id, direction ORDER BY {order} DESC LIMIT 10",
        agg = agg_select(),
        where_ = window_clause("flow_iface_buckets", interface_id.is_some()),
    );
    let mut query =
        sqlx::query_as::<_, (u32, Option<u64>, String, u64, u64, u64, u64, u64, u64)>(&sql)
            .bind(device_id)
            .bind(minutes);
    if let Some(i) = interface_id {
        query = query.bind(i);
    }
    let rows = query.fetch_all(pool).await?;

    // Resolve if_index -> a human label (if_name, falling back to if_descr) so
    // the UI shows "TenGigabitEthernet1/1" instead of a raw ifIndex. Keyed by
    // if_index (always present on a flow bucket); the bucket's interface_id FK is
    // often NULL when the exporter's ifIndex wasn't mapped to an enrolled row.
    let names: std::collections::HashMap<u32, String> =
        sqlx::query_as::<_, (u32, Option<String>, Option<String>)>(
            "SELECT if_index, if_name, if_descr FROM device_interfaces WHERE device_id = ?",
        )
        .bind(device_id)
        .fetch_all(pool)
        .await?
        .into_iter()
        .filter_map(|(idx, name, descr)| name.or(descr).map(|n| (idx, n)))
        .collect();

    Ok(rows
        .into_iter()
        .map(|(if_index, iface_id, direction, eb, ep, rb, rp, mr, lc)| {
            let mut v = agg_json(eb, ep, rb, rp, mr, lc);
            v["if_index"] = json!(if_index);
            v["interface_id"] = json!(iface_id);
            if let Some(name) = names.get(&if_index) {
                v["if_name"] = json!(name);
            }
            v["direction"] = json!(direction);
            v
        })
        .collect())
}

async fn top_ports(
    pool: &sqlx::MySqlPool,
    device_id: u64,
    interface_id: Option<u64>,
    minutes: i64,
    order: &str,
    port_kind: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut where_ = window_clause("flow_port_buckets", interface_id.is_some());
    where_.push_str(" AND port_kind = ?");
    let sql = format!(
        "SELECT protocol, port, direction, {agg} {where_} \
         GROUP BY protocol, port, direction ORDER BY {order} DESC LIMIT 10",
        agg = agg_select(),
    );
    let mut query = sqlx::query_as::<_, (u16, u16, String, u64, u64, u64, u64, u64, u64)>(&sql)
        .bind(device_id)
        .bind(minutes);
    if let Some(i) = interface_id {
        query = query.bind(i);
    }
    query = query.bind(port_kind);
    let rows = query.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(protocol, port, direction, eb, ep, rb, rp, mr, lc)| {
            let mut v = agg_json(eb, ep, rb, rp, mr, lc);
            v["protocol"] = json!(protocol);
            v["port"] = json!(port);
            v["port_kind"] = json!(port_kind);
            v["direction"] = json!(direction);
            v
        })
        .collect())
}

async fn top_as(
    pool: &sqlx::MySqlPool,
    device_id: u64,
    interface_id: Option<u64>,
    minutes: i64,
    order: &str,
    as_kind: &str,
) -> anyhow::Result<Vec<Value>> {
    let mut where_ = window_clause("flow_as_buckets", interface_id.is_some());
    where_.push_str(" AND as_kind = ?");
    let sql = format!(
        "SELECT asn, direction, {agg} {where_} \
         GROUP BY asn, direction ORDER BY {order} DESC LIMIT 10",
        agg = agg_select(),
    );
    let mut query = sqlx::query_as::<_, (u32, String, u64, u64, u64, u64, u64, u64)>(&sql)
        .bind(device_id)
        .bind(minutes);
    if let Some(i) = interface_id {
        query = query.bind(i);
    }
    query = query.bind(as_kind);
    let rows = query.fetch_all(pool).await?;
    Ok(rows
        .into_iter()
        .map(|(asn, direction, eb, ep, rb, rp, mr, lc)| {
            let mut v = agg_json(eb, ep, rb, rp, mr, lc);
            v["asn"] = json!(asn);
            v["as_kind"] = json!(as_kind);
            v["direction"] = json!(direction);
            v
        })
        .collect())
}

async fn top_talkers(
    pool: &sqlx::MySqlPool,
    device_id: u64,
    interface_id: Option<u64>,
    minutes: i64,
    order: &str,
) -> anyhow::Result<Vec<Value>> {
    let sql = format!(
        "SELECT src_addr, dst_addr, src_port, dst_port, protocol, direction, {agg} {where_} \
         GROUP BY src_addr, dst_addr, src_port, dst_port, protocol, direction \
         ORDER BY {order} DESC LIMIT 10",
        agg = agg_select(),
        where_ = window_clause("flow_talker_buckets", interface_id.is_some()),
    );
    let mut query = sqlx::query_as::<_, TalkerAggRow>(&sql)
        .bind(device_id)
        .bind(minutes);
    if let Some(i) = interface_id {
        query = query.bind(i);
    }
    let rows = query.fetch_all(pool).await?;
    Ok(rows.into_iter().map(talker_json).collect())
}

// --- search + autocomplete -------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    device_id: Option<u64>,
    /// Prefix match on source / destination address.
    src: Option<String>,
    dst: Option<String>,
    /// Exact match on a port appearing as EITHER the source or destination port.
    port: Option<u16>,
    /// Exact match on the IP protocol number (6=TCP, 17=UDP, …).
    protocol: Option<u16>,
    /// Restrict to one interface by its SNMP ifIndex (the searchable interface
    /// dropdown sends this; always populated on a bucket, unlike interface_id).
    if_index: Option<u32>,
    minutes: Option<i64>,
    metric: Option<String>,
    limit: Option<i64>,
}

/// Trim a filter to a non-empty value, or None.
fn clean(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|v| !v.is_empty())
}

/// GET /api/flows/search — aggregated 5-tuples matching device/src/dst/port over
/// the window. All filters optional; with none set it returns the top matches.
pub async fn search(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(q): Query<SearchQuery>,
) -> JsonResp {
    let minutes = q.minutes.unwrap_or(60).clamp(1, 1440);
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let order = match q.metric.as_deref() {
        Some("pkts") => "est_pkts",
        _ => "est_bytes",
    };

    let mut qb: QueryBuilder<MySql> =
        QueryBuilder::new("SELECT src_addr, dst_addr, src_port, dst_port, protocol, direction, ");
    qb.push(agg_select());
    qb.push(" FROM flow_talker_buckets WHERE bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ");
    qb.push_bind(minutes);
    qb.push(" MINUTE)");
    if let Some(d) = q.device_id {
        qb.push(" AND device_id = ").push_bind(d);
    }
    if let Some(idx) = q.if_index {
        qb.push(" AND if_index = ").push_bind(idx);
    }
    if let Some(s) = clean(&q.src) {
        qb.push(" AND src_addr LIKE CONCAT(")
            .push_bind(s.to_string())
            .push(", '%')");
    }
    if let Some(d) = clean(&q.dst) {
        qb.push(" AND dst_addr LIKE CONCAT(")
            .push_bind(d.to_string())
            .push(", '%')");
    }
    if let Some(p) = q.port {
        qb.push(" AND (src_port = ")
            .push_bind(p)
            .push(" OR dst_port = ")
            .push_bind(p)
            .push(")");
    }
    if let Some(proto) = q.protocol {
        qb.push(" AND protocol = ").push_bind(proto);
    }
    qb.push(" GROUP BY src_addr, dst_addr, src_port, dst_port, protocol, direction ORDER BY ");
    qb.push(order);
    qb.push(" DESC LIMIT ").push_bind(limit);

    match qb
        .build_query_as::<TalkerAggRow>()
        .fetch_all(&state.pool)
        .await
    {
        Ok(rows) => {
            let out: Vec<Value> = rows.into_iter().map(talker_json).collect();
            (
                StatusCode::OK,
                Json(json!({ "minutes": minutes, "rows": out })),
            )
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct DetailQuery {
    device_id: Option<u64>,
    src: String,
    dst: String,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    protocol: u16,
    minutes: Option<i64>,
}

/// Per-interface detail row: if_index, direction, device_id, if_name, the six
/// agg columns, then first/last-seen (pre-formatted as RFC3339-ish UTC strings
/// to avoid TIMESTAMP/DATETIME decode ambiguity on MIN/MAX).
type DetailRow = (
    u32,
    String,
    u64,
    Option<String>,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    String,
    String,
);

/// GET /api/flows/detail — full breakdown of ONE 5-tuple over the window: every
/// (interface, direction) it was observed on (the "in/out" interfaces, names
/// resolved by device+ifIndex), each with its own est/raw totals, sampling, and
/// first/last-seen. Read-only.
pub async fn detail(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(q): Query<DetailQuery>,
) -> JsonResp {
    let minutes = q.minutes.unwrap_or(60).clamp(1, 1440);

    let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
        "SELECT t.if_index, t.direction, t.device_id, \
         MAX(COALESCE(di.if_name, di.if_descr)) AS if_name, ",
    );
    qb.push(agg_select());
    qb.push(
        ", DATE_FORMAT(MIN(t.bucket_ts), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
           DATE_FORMAT(MAX(t.bucket_ts), '%Y-%m-%dT%H:%i:%sZ') AS last_seen \
         FROM flow_talker_buckets t \
         LEFT JOIN device_interfaces di \
             ON di.device_id = t.device_id AND di.if_index = t.if_index \
         WHERE t.bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ",
    );
    qb.push_bind(minutes);
    qb.push(" MINUTE)");
    qb.push(" AND t.src_addr = ").push_bind(q.src.clone());
    qb.push(" AND t.dst_addr = ").push_bind(q.dst.clone());
    // Null-safe port match (`<=>`) so non-port protocols (NULL ports) compare ok.
    qb.push(" AND t.src_port <=> ").push_bind(q.src_port);
    qb.push(" AND t.dst_port <=> ").push_bind(q.dst_port);
    qb.push(" AND t.protocol = ").push_bind(q.protocol);
    if let Some(d) = q.device_id {
        qb.push(" AND t.device_id = ").push_bind(d);
    }
    qb.push(" GROUP BY t.if_index, t.direction, t.device_id ORDER BY est_bytes DESC");

    let rows = match qb
        .build_query_as::<DetailRow>()
        .fetch_all(&state.pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };

    let interfaces: Vec<Value> = rows
        .into_iter()
        .map(
            |(if_index, direction, device_id, if_name, eb, ep, rb, rp, mr, lc, first, last)| {
                let mut v = agg_json(eb, ep, rb, rp, mr, lc);
                v["if_index"] = json!(if_index);
                v["if_name"] = json!(if_name);
                v["direction"] = json!(direction);
                v["device_id"] = json!(device_id);
                v["first_seen"] = json!(first);
                v["last_seen"] = json!(last);
                v
            },
        )
        .collect();

    (
        StatusCode::OK,
        Json(json!({
            "minutes": minutes,
            "src_addr": q.src,
            "dst_addr": q.dst,
            "src_port": q.src_port,
            "dst_port": q.dst_port,
            "protocol": q.protocol,
            "interfaces": interfaces,
        })),
    )
}

#[derive(Debug, Deserialize)]
pub struct SuggestQuery {
    /// src | dst | port.
    field: String,
    /// Prefix the value must start with (may be empty → most common values).
    q: Option<String>,
    device_id: Option<u64>,
    minutes: Option<i64>,
}

/// GET /api/flows/suggest — distinct values for an autocomplete field, prefix-
/// matched, scoped to a device + window. Returns at most 15 values.
pub async fn suggest(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Query(q): Query<SuggestQuery>,
) -> JsonResp {
    let minutes = q.minutes.unwrap_or(60).clamp(1, 1440);
    let prefix = q.q.as_deref().map(str::trim).unwrap_or("").to_string();
    const LIMIT: i64 = 15;

    // Whitelist the column; never interpolate the field name from raw input.
    let column = match q.field.as_str() {
        "src" => "src_addr",
        "dst" => "dst_addr",
        "port" => "port", // special-cased below (union of src/dst ports)
        _ => return err(StatusCode::BAD_REQUEST, "field must be src, dst, or port"),
    };

    let values: Result<Vec<String>, _> = if column == "port" {
        // Ports live in two columns; union them, prefix-match the numeric text.
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new(
            "SELECT p FROM ( \
               SELECT DISTINCT src_port AS p FROM flow_talker_buckets \
                 WHERE src_port IS NOT NULL AND bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ",
        );
        qb.push_bind(minutes).push(" MINUTE)");
        if let Some(d) = q.device_id {
            qb.push(" AND device_id = ").push_bind(d);
        }
        qb.push(" AND CAST(src_port AS CHAR) LIKE CONCAT(")
            .push_bind(prefix.clone())
            .push(", '%') ");
        qb.push(
            "UNION SELECT DISTINCT dst_port AS p FROM flow_talker_buckets \
               WHERE dst_port IS NOT NULL AND bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ",
        );
        qb.push_bind(minutes).push(" MINUTE)");
        if let Some(d) = q.device_id {
            qb.push(" AND device_id = ").push_bind(d);
        }
        qb.push(" AND CAST(dst_port AS CHAR) LIKE CONCAT(")
            .push_bind(prefix.clone())
            .push(", '%') ");
        qb.push(") t ORDER BY p ASC LIMIT ").push_bind(LIMIT);
        qb.build_query_scalar::<u32>()
            .fetch_all(&state.pool)
            .await
            .map(|ports| ports.into_iter().map(|p| p.to_string()).collect())
    } else {
        let mut qb: QueryBuilder<MySql> = QueryBuilder::new("SELECT DISTINCT ");
        qb.push(column); // whitelisted above
        qb.push(" FROM flow_talker_buckets WHERE bucket_ts >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL ");
        qb.push_bind(minutes).push(" MINUTE)");
        if let Some(d) = q.device_id {
            qb.push(" AND device_id = ").push_bind(d);
        }
        qb.push(" AND ")
            .push(column)
            .push(" LIKE CONCAT(")
            .push_bind(prefix.clone())
            .push(", '%') ");
        qb.push("ORDER BY ")
            .push(column)
            .push(" ASC LIMIT ")
            .push_bind(LIMIT);
        qb.build_query_scalar::<String>()
            .fetch_all(&state.pool)
            .await
    };

    match values {
        Ok(v) => (StatusCode::OK, Json(json!(v))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/devices/{id}/flow-exporters — exporter health for the device.
pub async fn exporters(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(device_id): Path<u64>,
) -> JsonResp {
    if !device_exists(&state.pool, device_id).await {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    let rows = sqlx::query_as::<_, ExporterHealthRow>(
        "SELECT e.id, e.source_addr, e.observation_domain, e.configured_sampling_rate, \
                e.reported_sampling_rate, e.snmp_derived_rate, e.effective_sampling_rate, \
                e.sampling_source, e.sampling_confidence, e.snmp_xcal_ratio, e.last_packet_at, \
                e.template_count, e.datagrams_total, e.dropped_no_template, e.dropped_malformed, \
                e.dropped_bucket_backlog, q.bucket_ts AS quality_bucket_ts, q.iface_complete, \
                q.port_complete, q.asn_complete, q.talker_complete, q.iface_dropped, \
                q.port_dropped, q.asn_dropped, q.talker_dropped \
         FROM flow_exporters e \
         LEFT JOIN flow_publication_barrier publication ON publication.id=1 AND publication.registry_ready=1 \
         LEFT JOIN flow_bucket_quality q ON publication.id IS NOT NULL AND q.exporter_id = e.id \
              AND q.bucket_ts = (SELECT MAX(q2.bucket_ts) FROM flow_bucket_quality q2 \
                                 WHERE q2.exporter_id = e.id) \
         WHERE e.device_id = ? ORDER BY e.source_addr",
    )
    .bind(device_id)
    .fetch_all(&state.pool)
    .await;

    match rows {
        Ok(rows) => {
            let out: Vec<Value> = rows
                .into_iter()
                .map(|r| {
                    json!({
                        "id": r.id,
                        "source_addr": r.source_addr,
                        "observation_domain": r.observation_domain,
                        "configured_sampling_rate": r.configured_sampling_rate,
                        "reported_sampling_rate": r.reported_sampling_rate,
                        "snmp_derived_rate": r.snmp_derived_rate,
                        "effective_sampling_rate": r.effective_sampling_rate,
                        "sampling_source": r.sampling_source,
                        "sampling_confidence": r.sampling_confidence,
                        "snmp_xcal_ratio": r.snmp_xcal_ratio,
                        "last_packet_at": r.last_packet_at.map(|t| t.to_rfc3339()),
                        "template_count": r.template_count,
                        "datagrams_total": r.datagrams_total,
                        "dropped_no_template": r.dropped_no_template,
                        "dropped_malformed": r.dropped_malformed,
                        "dropped_bucket_backlog": r.dropped_bucket_backlog,
                        "quality_bucket_ts": r.quality_bucket_ts.map(|t| t.to_rfc3339()),
                        "iface_complete": r.iface_complete,
                        "port_complete": r.port_complete,
                        "asn_complete": r.asn_complete,
                        "talker_complete": r.talker_complete,
                        "iface_dropped": r.iface_dropped,
                        "port_dropped": r.port_dropped,
                        "asn_dropped": r.asn_dropped,
                        "talker_dropped": r.talker_dropped,
                    })
                })
                .collect();
            (StatusCode::OK, Json(json!(out)))
        }
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}
