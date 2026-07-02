//! NetFlow flow collector: UDP listener -> decode -> aggregate into time buckets
//! -> flush to DB -> prune. See ../../../docs/flow-telemetry.md.
//!
//! Hot path (recv loop) does NO database I/O and holds no lock across an await:
//! it parses (pure CPU) and folds records into in-memory per-bucket accumulators.
//! All DB work happens in the periodic flush + prune tasks. This keeps a flood of
//! datagrams from ever blocking on the DB, and bounds memory (the long tail of
//! 5-tuples is truncated to `top_k_talkers` at flush — surfaced, never silent).
//!
//! Source-IP allowlist: only datagrams from enrolled devices are parsed (the
//! default). Unknown sources are counted and dropped without allocating any
//! per-exporter state — a spoofed-source flood cannot grow our tables.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use sqlx::MySqlPool;
use tokio::net::UdpSocket;

use super::v9::{self, TemplateCache};
use super::{resolve_sampling, sflow, Direction, FlowRecord, PortKind};
use crate::config::Config;
use crate::telemetry::snmp;

/// Which wire protocol a listener decodes. A datagram's protocol is fixed by the
/// socket it arrived on (NetFlow and sFlow bind separate ports), so the recv loop
/// never has to sniff the version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    NetflowV9,
    Sflow,
}

impl Protocol {
    /// The `flow_exporters.version` value recorded for this protocol
    /// (9 = NetFlow v9, 5 = sFlow v5).
    fn version(self) -> u16 {
        match self {
            Protocol::NetflowV9 => 9,
            Protocol::Sflow => 5,
        }
    }
}

/// Largest UDP payload we will read. NetFlow datagrams are well under this.
const RECV_BUF: usize = 65_535;
/// How often to flush closed buckets + exporter health to the DB.
const FLUSH_INTERVAL: Duration = Duration::from_secs(10);
/// How often to prune expired buckets.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);
/// How often to refresh the device -> source-IP allowlist.
const ALLOWLIST_INTERVAL: Duration = Duration::from_secs(30);
/// Hard cap on distinct exporters held in memory. The allowlist normally keeps
/// this tiny, but with `allowlist_enrolled_only = false` a spoofed-source flood
/// could otherwise grow the map without bound (memory-exhaustion DoS). When full,
/// a datagram from a *new* source evicts the least-recently-seen exporter.
const MAX_EXPORTERS: usize = 10_000;

/// Running counts for a single aggregation key.
#[derive(Debug, Default, Clone, Copy)]
struct Counts {
    pkts: u64,
    bytes: u64,
    flows: u64,
}

impl Counts {
    fn add(&mut self, pkts: u64, bytes: u64) {
        // Attacker-controlled wire values accumulated across a bucket window:
        // saturate rather than panic (debug) / wrap (release) on overflow.
        self.pkts = self.pkts.saturating_add(pkts);
        self.bytes = self.bytes.saturating_add(bytes);
        self.flows = self.flows.saturating_add(1);
    }
}

type IfaceKey = (u32, Direction);
type PortKey = (u32, Direction, u8, PortKind, u16);
// PortKind is reused as the src/dst discriminator for the AS dimension.
type AsKey = (u32, Direction, PortKind, u32);
type TalkerKey = (u32, Direction, IpAddr, IpAddr, Option<u16>, Option<u16>, u8);

/// Hard cap on distinct talker 5-tuples held per bucket. Under a real spoofed-
/// source flood (millions of tiny distinct flows — the exact DDoS this tool
/// watches for) the talker map would otherwise grow until OOM before the
/// flush-time top-K trim. The iface/port/AS rollups still count every flow, and
/// the tail beyond top-K is dropped at flush regardless, so capping loses no
/// aggregate signal — only the identity of tail tuples past the cap. Well above
/// top_k_talkers so the retained top-K stays accurate.
const MAX_TALKER_KEYS: usize = 65_536;

/// One bucket's aggregation across the reporting dimensions.
#[derive(Debug, Default)]
struct Accum {
    iface: HashMap<IfaceKey, Counts>,
    port: HashMap<PortKey, Counts>,
    as_: HashMap<AsKey, Counts>,
    talker: HashMap<TalkerKey, Counts>,
    /// Distinct talker tuples refused this bucket after hitting MAX_TALKER_KEYS
    /// (surfaced at flush; never silent).
    talker_dropped: u64,
}

impl Accum {
    /// Fold one decoded flow into all three dimensions. `bucket` counts every
    /// distinct flow at interface scope (including the tail later truncated out
    /// of the talker table) so the UI can show "top K of N".
    fn fold(&mut self, fr: &FlowRecord) {
        let (dir, ifindex) = fr.attribution();
        let ifindex = match ifindex {
            Some(i) => i,
            None => return, // no interface to attribute to.
        };
        self.iface
            .entry((ifindex, dir))
            .or_default()
            .add(fr.pkts, fr.bytes);

        if fr.has_ports() {
            if let Some(sp) = fr.src_port {
                self.port
                    .entry((ifindex, dir, fr.protocol, PortKind::Src, sp))
                    .or_default()
                    .add(fr.pkts, fr.bytes);
            }
            if let Some(dp) = fr.dst_port {
                self.port
                    .entry((ifindex, dir, fr.protocol, PortKind::Dst, dp))
                    .or_default()
                    .add(fr.pkts, fr.bytes);
            }
        }

        // AS dimension — only when the exporter collects AS and it's a real ASN
        // (0 = unknown / no BGP route).
        if let Some(asn) = fr.src_as.filter(|a| *a != 0) {
            self.as_
                .entry((ifindex, dir, PortKind::Src, asn))
                .or_default()
                .add(fr.pkts, fr.bytes);
        }
        if let Some(asn) = fr.dst_as.filter(|a| *a != 0) {
            self.as_
                .entry((ifindex, dir, PortKind::Dst, asn))
                .or_default()
                .add(fr.pkts, fr.bytes);
        }

        // Bounded talker accumulation (see MAX_TALKER_KEYS): always update an
        // existing tuple, but refuse NEW tuples once at the cap (counted, logged
        // at flush) so attacker-controlled 5-tuple cardinality can't OOM us.
        let talker_key = (
            ifindex,
            dir,
            fr.src_addr,
            fr.dst_addr,
            fr.src_port,
            fr.dst_port,
            fr.protocol,
        );
        if let Some(c) = self.talker.get_mut(&talker_key) {
            c.add(fr.pkts, fr.bytes);
        } else if self.talker.len() < MAX_TALKER_KEYS {
            self.talker
                .entry(talker_key)
                .or_default()
                .add(fr.pkts, fr.bytes);
        } else {
            self.talker_dropped = self.talker_dropped.saturating_add(1);
        }
    }
}

/// In-memory per-exporter state. Keyed by source IP in [`State::exporters`].
#[derive(Debug)]
struct Exporter {
    /// DB `flow_exporters.id`; 0 until first persisted.
    db_id: u64,
    device_id: Option<u64>,
    /// Wire protocol of the most recent datagram from this source (9 / 5).
    version: u16,
    observation_domain: u32,
    /// NetFlow-only template cache; unused (always empty) for sFlow exporters.
    templates: TemplateCache,
    buckets: HashMap<i64, Accum>,
    // resolved sampling inputs (configured is read from the DB at flush time —
    // the operator may set it via the exporter row — so it lives only there).
    reported_rate: Option<u32>,
    snmp_derived_rate: Option<u32>,
    snmp_xcal_ratio: Option<f64>,
    // health
    datagrams_total: u64,
    dropped_no_template: u64,
    dropped_malformed: u64,
    last_sequence: Option<u32>,
    /// Unix seconds of the most recent datagram — drives LRU eviction when the
    /// exporter map hits [`MAX_EXPORTERS`].
    last_seen: i64,
}

impl Exporter {
    fn new(device_id: Option<u64>, version: u16) -> Self {
        Self {
            db_id: 0,
            device_id,
            version,
            observation_domain: 0,
            templates: TemplateCache::new(),
            buckets: HashMap::new(),
            reported_rate: None,
            snmp_derived_rate: None,
            snmp_xcal_ratio: None,
            datagrams_total: 0,
            dropped_no_template: 0,
            dropped_malformed: 0,
            last_sequence: None,
            last_seen: 0,
        }
    }
}

/// Shared collector state. Guarded by a std Mutex — never held across an await.
#[derive(Default)]
struct State {
    /// source IP -> per-exporter state.
    exporters: HashMap<IpAddr, Exporter>,
    /// source IP -> enrolled device id (the allowlist).
    allow: HashMap<IpAddr, u64>,
    /// datagrams dropped because the source is not an enrolled device.
    dropped_not_allowlisted: u64,
    /// exporters evicted because the map reached [`MAX_EXPORTERS`].
    evicted_exporters: u64,
}

/// Spawn the collector (listener + flush + prune + allowlist refresh) when
/// `[flow].enabled`. Best-effort: a bind failure is logged and the collector
/// simply does not run (the rest of the controller is unaffected).
pub async fn run(pool: MySqlPool, cfg: Arc<Config>) {
    if !cfg.flow.enabled {
        return;
    }

    // Bind the NetFlow v9 listener (always, when the collector is enabled).
    let nf_bind = format!("{}:{}", cfg.flow.bind_addr, cfg.flow.bind_port);
    let nf_socket = match UdpSocket::bind(&nf_bind).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::error!(event_type = "flow_bind_failed", bind = %nf_bind, proto = "netflow_v9", error = %e, "flow collector could not bind UDP — not running");
            return;
        }
    };
    tracing::warn!(
        event_type = "flow_listener_up",
        bind = %nf_bind,
        proto = "netflow_v9",
        allowlist_enrolled_only = cfg.flow.allowlist_enrolled_only,
        "NetFlow v9 collector listening (deliberate non-loopback UDP exposure — see docs/flow-telemetry.md)"
    );

    // Optionally bind the sFlow v5 listener (a second decoder on its own port,
    // feeding the same buckets). A bind failure here is non-fatal: NetFlow keeps
    // running and only sFlow is unavailable.
    let sflow_socket = if cfg.flow.sflow_enabled {
        let sf_bind = format!("{}:{}", cfg.flow.bind_addr, cfg.flow.sflow_port);
        match UdpSocket::bind(&sf_bind).await {
            Ok(s) => {
                tracing::warn!(
                    event_type = "flow_listener_up",
                    bind = %sf_bind,
                    proto = "sflow_v5",
                    allowlist_enrolled_only = cfg.flow.allowlist_enrolled_only,
                    "sFlow v5 collector listening (deliberate non-loopback UDP exposure — see docs/flow-telemetry.md)"
                );
                Some(Arc::new(s))
            }
            Err(e) => {
                tracing::error!(event_type = "flow_bind_failed", bind = %sf_bind, proto = "sflow_v5", error = %e, "sFlow listener could not bind UDP — sFlow not running");
                None
            }
        }
    } else {
        None
    };

    let state = Arc::new(Mutex::new(State::default()));

    tokio::spawn(refresh_allowlist(pool.clone(), state.clone()));
    tokio::spawn(flush_loop(pool.clone(), cfg.clone(), state.clone()));
    tokio::spawn(prune_loop(pool.clone(), cfg.clone()));

    // Both listeners share the same in-memory State (exporter map, allowlist),
    // so their flows aggregate into the same buckets and exporter-health rows.
    if let Some(sf) = sflow_socket {
        tokio::spawn(recv_loop(
            sf,
            Protocol::Sflow,
            cfg.clone(),
            state.clone(),
        ));
    }
    recv_loop(nf_socket, Protocol::NetflowV9, cfg, state).await;
}

/// The UDP receive loop. Parses each datagram and folds its flows into the
/// in-memory buckets. Pure CPU work under a brief lock; no DB, no await held.
async fn recv_loop(
    socket: Arc<UdpSocket>,
    proto: Protocol,
    cfg: Arc<Config>,
    state: Arc<Mutex<State>>,
) {
    let bucket_secs = cfg.flow.bucket_seconds.max(1) as i64;
    let mut buf = vec![0u8; RECV_BUF];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(event_type = "flow_recv_failed", error = %e, "flow recv_from failed");
                continue;
            }
        };
        let src_ip = peer.ip();
        let now = Utc::now().timestamp();
        let bucket_ts = (now / bucket_secs) * bucket_secs;

        let mut st = match state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(), // poisoned: recover; we never panic with the lock held.
        };

        // Allowlist gate: unknown sources are counted and dropped with NO state
        // allocation, so a spoofed flood cannot grow our maps or tables.
        let device_id = st.allow.get(&src_ip).copied();
        if cfg.flow.allowlist_enrolled_only && device_id.is_none() {
            st.dropped_not_allowlisted += 1;
            continue;
        }

        // Bound the exporter map: if this is a new source and we are at capacity,
        // evict the least-recently-seen exporter so a high-entropy spoofed flood
        // cannot grow memory without limit.
        if !st.exporters.contains_key(&src_ip) && st.exporters.len() >= MAX_EXPORTERS {
            if let Some(victim) = st
                .exporters
                .iter()
                .min_by_key(|(_, ex)| ex.last_seen)
                .map(|(ip, _)| *ip)
            {
                st.exporters.remove(&victim);
                st.evicted_exporters += 1;
                tracing::warn!(
                    event_type = "flow_exporter_evicted",
                    evicted = %victim,
                    incoming = %src_ip,
                    cap = MAX_EXPORTERS,
                    "exporter map full — evicted least-recently-seen exporter"
                );
            }
        }

        let exporter = st
            .exporters
            .entry(src_ip)
            .or_insert_with(|| Exporter::new(device_id, proto.version()));
        // Keep the device mapping fresh if the allowlist learned it later.
        if exporter.device_id.is_none() {
            exporter.device_id = device_id;
        }
        exporter.version = proto.version();
        exporter.datagrams_total += 1;
        exporter.last_seen = now;

        // Decode against the right wire protocol, normalizing both to the same
        // FlowRecord. NetFlow is template-stateful (per-exporter cache); sFlow is
        // stateless. Either way, a malformed datagram is counted and dropped —
        // never fatal (doctrine: parsers never panic).
        // Normalize each decoder's structured error to a String so the two
        // protocol arms share one result type.
        let decoded = match proto {
            Protocol::NetflowV9 => v9::decode(&buf[..len], &mut exporter.templates)
                .map(|d| {
                    exporter.observation_domain = d.source_id;
                    exporter.dropped_no_template += d.data_without_template as u64;
                    (d.sequence, d.reported_sampling, d.records)
                })
                .map_err(|e| e.to_string()),
            Protocol::Sflow => sflow::decode(&buf[..len])
                .map(|d| {
                    exporter.observation_domain = d.sub_agent_id;
                    (d.sequence, d.reported_sampling, d.records)
                })
                .map_err(|e| e.to_string()),
        };

        match decoded {
            Ok((sequence, reported_sampling, records)) => {
                exporter.last_sequence = Some(sequence);
                if let Some(rate) = reported_sampling {
                    exporter.reported_rate = Some(rate);
                }
                if !records.is_empty() {
                    let accum = exporter.buckets.entry(bucket_ts).or_default();
                    for fr in &records {
                        accum.fold(fr);
                    }
                }
            }
            Err(e) => {
                exporter.dropped_malformed += 1;
                tracing::debug!(event_type = "flow_decode_failed", source = %src_ip, proto = ?proto, error = %e, "dropped malformed flow datagram");
            }
        }
    }
}

/// Periodically resolve enrolled-device hostnames to IPs and rebuild the
/// allowlist. A hostname that does not resolve is skipped (logged at debug).
async fn refresh_allowlist(pool: MySqlPool, state: Arc<Mutex<State>>) {
    loop {
        let mut allow: HashMap<IpAddr, u64> = HashMap::new();
        match snmp::load_enabled_devices(&pool).await {
            Ok(devices) => {
                for d in devices {
                    // hostname may be a literal IP or a DNS name; resolve both.
                    let target = format!("{}:0", d.hostname);
                    match tokio::net::lookup_host(target).await {
                        Ok(addrs) => {
                            for a in addrs {
                                allow.insert(a.ip(), d.id);
                            }
                        }
                        Err(e) => {
                            tracing::debug!(event_type = "flow_allowlist_resolve_failed", device_id = d.id, host = %d.hostname, error = %e, "could not resolve device host for flow allowlist")
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(event_type = "flow_allowlist_load_failed", error = %e, "could not load devices for flow allowlist")
            }
        }
        if let Ok(mut st) = state.lock() {
            st.allow = allow;
        }
        tokio::time::sleep(ALLOWLIST_INTERVAL).await;
    }
}

/// A snapshot of one exporter's flushable state, taken under the lock and then
/// processed without it.
struct ExporterFlush {
    src_ip: IpAddr,
    device_id: Option<u64>,
    version: u16,
    observation_domain: u32,
    template_count: u32,
    reported_rate: Option<u32>,
    snmp_derived_rate: Option<u32>,
    datagrams_total: u64,
    dropped_no_template: u64,
    dropped_malformed: u64,
    last_sequence: Option<u32>,
    closed: Vec<(i64, Accum)>,
}

async fn flush_loop(pool: MySqlPool, cfg: Arc<Config>, state: Arc<Mutex<State>>) {
    let bucket_secs = cfg.flow.bucket_seconds.max(1) as i64;
    loop {
        tokio::time::sleep(FLUSH_INTERVAL).await;
        let now = Utc::now().timestamp();

        // Snapshot under the lock: pull closed buckets out of each exporter and
        // copy the health counters. A bucket is closed once its window has fully
        // elapsed.
        let mut flushes: Vec<ExporterFlush> = Vec::new();
        if let Ok(mut st) = state.lock() {
            for (ip, ex) in st.exporters.iter_mut() {
                let closed_ts: Vec<i64> = ex
                    .buckets
                    .keys()
                    .copied()
                    .filter(|ts| ts + bucket_secs <= now)
                    .collect();
                let mut closed = Vec::with_capacity(closed_ts.len());
                for ts in closed_ts {
                    if let Some(acc) = ex.buckets.remove(&ts) {
                        closed.push((ts, acc));
                    }
                }
                flushes.push(ExporterFlush {
                    src_ip: *ip,
                    device_id: ex.device_id,
                    version: ex.version,
                    observation_domain: ex.observation_domain,
                    template_count: ex.templates.len() as u32,
                    reported_rate: ex.reported_rate,
                    snmp_derived_rate: ex.snmp_derived_rate,
                    datagrams_total: ex.datagrams_total,
                    dropped_no_template: ex.dropped_no_template,
                    dropped_malformed: ex.dropped_malformed,
                    last_sequence: ex.last_sequence,
                    closed,
                });
            }
        }

        for f in flushes {
            match flush_exporter(&pool, &cfg, f).await {
                Ok(Some((ip, db_id, derived, ratio))) => {
                    // Write back DB id + values derived this flush (carried forward).
                    if let Ok(mut st) = state.lock() {
                        if let Some(ex) = st.exporters.get_mut(&ip) {
                            if ex.db_id == 0 {
                                ex.db_id = db_id;
                            }
                            if derived.is_some() {
                                ex.snmp_derived_rate = derived;
                            }
                            if ratio.is_some() {
                                ex.snmp_xcal_ratio = ratio;
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(event_type = "flow_flush_failed", error = %e, "flushing flow buckets failed")
                }
            }
        }
    }
}

/// Persist one exporter: upsert its row, resolve its sampling, write any closed
/// buckets, run SNMP cross-calibration, and update its health. Returns
/// (ip, db_id, snmp_derived_rate, snmp_xcal_ratio) to write back.
type FlushBack = (IpAddr, u64, Option<u32>, Option<f64>);

async fn flush_exporter(
    pool: &MySqlPool,
    cfg: &Config,
    f: ExporterFlush,
) -> anyhow::Result<Option<FlushBack>> {
    // Upsert the exporter row and read back operator-set sampling override + id.
    sqlx::query(
        "INSERT INTO flow_exporters (device_id, source_addr, observation_domain, version, template_count) \
         VALUES (?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE device_id = VALUES(device_id), version = VALUES(version), \
            template_count = VALUES(template_count)",
    )
    .bind(f.device_id)
    .bind(f.src_ip.to_string())
    .bind(f.observation_domain)
    .bind(f.version)
    .bind(f.template_count)
    .execute(pool)
    .await?;

    let row: Option<(u64, Option<u32>)> = sqlx::query_as(
        "SELECT id, configured_sampling_rate FROM flow_exporters WHERE source_addr = ? AND observation_domain = ?",
    )
    .bind(f.src_ip.to_string())
    .bind(f.observation_domain)
    .fetch_optional(pool)
    .await?;
    let (exporter_id, configured) = match row {
        Some((id, cfg_rate)) => (id, cfg_rate),
        None => return Ok(None),
    };

    // Cross-calibrate against SNMP from the most recent closed bucket (busiest
    // ingress interface). May produce an snmp_derived rate when nothing else set.
    let mut snmp_derived = f.snmp_derived_rate;
    let mut xcal_ratio: Option<f64> = None;

    // Sampling resolution uses the config override (authoritative), else reported,
    // else snmp_derived, else the global default.
    let sampling = resolve_sampling(
        configured,
        f.reported_rate,
        snmp_derived,
        cfg.flow.default_sampling_rate,
    );

    // Write buckets only when the exporter maps to a device (FK requires it).
    if let Some(device_id) = f.device_id {
        let mut iface_id_cache: HashMap<u32, Option<u64>> = HashMap::new();
        // newest bucket first, for the cross-cal sample.
        let mut closed = f.closed;
        closed.sort_by_key(|(ts, _)| std::cmp::Reverse(*ts));
        for (idx, (ts, acc)) in closed.iter().enumerate() {
            let bucket_ts = Utc.timestamp_opt(*ts, 0).single().unwrap_or_else(Utc::now);
            let ctx = BucketCtx {
                exporter_id,
                device_id,
                bucket_ts,
            };
            write_bucket(pool, cfg, &ctx, acc, &sampling, &mut iface_id_cache).await?;
            if idx == 0 {
                if let Some((ratio, derived)) = cross_calibrate(
                    pool,
                    cfg,
                    device_id,
                    acc,
                    &sampling,
                    configured,
                    f.reported_rate,
                )
                .await
                {
                    xcal_ratio = Some(ratio);
                    if derived.is_some() {
                        snmp_derived = derived;
                    }
                }
            }
        }
    }

    // Re-resolve with any freshly derived rate so the stored health row reflects it.
    let sampling = resolve_sampling(
        configured,
        f.reported_rate,
        snmp_derived,
        cfg.flow.default_sampling_rate,
    );

    sqlx::query(
        "UPDATE flow_exporters SET \
            reported_sampling_rate = ?, snmp_derived_rate = ?, effective_sampling_rate = ?, \
            sampling_source = ?, sampling_confidence = ?, snmp_xcal_ratio = COALESCE(?, snmp_xcal_ratio), \
            last_sequence = ?, datagrams_total = ?, dropped_no_template = ?, dropped_malformed = ?, \
            last_packet_at = UTC_TIMESTAMP() \
         WHERE id = ?",
    )
    .bind(f.reported_rate)
    .bind(snmp_derived)
    .bind(sampling.rate)
    .bind(sampling.source.as_str())
    .bind(sampling.confidence_str())
    .bind(xcal_ratio)
    .bind(f.last_sequence)
    .bind(f.datagrams_total)
    .bind(f.dropped_no_template)
    .bind(f.dropped_malformed)
    .bind(exporter_id)
    .execute(pool)
    .await?;

    Ok(Some((f.src_ip, exporter_id, snmp_derived, xcal_ratio)))
}

/// Resolve an ifIndex to a `device_interfaces.id` (cached per flush).
async fn resolve_interface_id(
    pool: &MySqlPool,
    cache: &mut HashMap<u32, Option<u64>>,
    device_id: u64,
    if_index: u32,
) -> Option<u64> {
    if let Some(v) = cache.get(&if_index) {
        return *v;
    }
    let id: Option<u64> =
        sqlx::query_scalar("SELECT id FROM device_interfaces WHERE device_id = ? AND if_index = ?")
            .bind(device_id)
            .bind(if_index)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    cache.insert(if_index, id);
    id
}

/// Identifiers naming the bucket being written.
struct BucketCtx {
    exporter_id: u64,
    device_id: u64,
    bucket_ts: DateTime<Utc>,
}

/// Write one bucket's three dimensions in a transaction. Talkers are truncated to
/// `top_k_talkers` (logged when it bites); iface.flow_count keeps the full count.
async fn write_bucket(
    pool: &MySqlPool,
    cfg: &Config,
    ctx: &BucketCtx,
    acc: &Accum,
    sampling: &super::Sampling,
    iface_cache: &mut HashMap<u32, Option<u64>>,
) -> anyhow::Result<()> {
    let BucketCtx {
        exporter_id,
        device_id,
        bucket_ts,
    } = *ctx;
    let rate = sampling.rate;
    let conf = sampling.confidence_str();
    let mut tx = pool.begin().await?;

    // Interface totals.
    for ((if_index, dir), c) in &acc.iface {
        let iface_id = resolve_interface_id(pool, iface_cache, device_id, *if_index).await;
        sqlx::query(
            "INSERT INTO flow_iface_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = pkts + VALUES(pkts), bytes = bytes + VALUES(bytes), flow_count = flow_count + VALUES(flow_count)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(c.pkts).bind(c.bytes).bind(c.flows).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    // Port rollups.
    for ((if_index, dir, proto, kind, port), c) in &acc.port {
        let iface_id = resolve_interface_id(pool, iface_cache, device_id, *if_index).await;
        sqlx::query(
            "INSERT INTO flow_port_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, protocol, port_kind, port, pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = pkts + VALUES(pkts), bytes = bytes + VALUES(bytes), flow_count = flow_count + VALUES(flow_count)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(*proto).bind(kind.as_str()).bind(*port)
        .bind(c.pkts).bind(c.bytes).bind(c.flows).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    // AS rollups (only present when the exporter collects SRC_AS/DST_AS).
    for ((if_index, dir, kind, asn), c) in &acc.as_ {
        let iface_id = resolve_interface_id(pool, iface_cache, device_id, *if_index).await;
        sqlx::query(
            "INSERT INTO flow_as_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, as_kind, asn, pkts, bytes, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = pkts + VALUES(pkts), bytes = bytes + VALUES(bytes), flow_count = flow_count + VALUES(flow_count)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(kind.as_str()).bind(*asn)
        .bind(c.pkts).bind(c.bytes).bind(c.flows).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    // Top-K talkers. Sort by bytes desc; the tail is dropped (the count of all
    // talkers survives in flow_iface_buckets.flow_count).
    let mut talkers: Vec<(&TalkerKey, &Counts)> = acc.talker.iter().collect();
    talkers.sort_by_key(|(_, c)| std::cmp::Reverse(c.bytes));
    let top_k = cfg.flow.top_k_talkers.max(1);
    if talkers.len() > top_k || acc.talker_dropped > 0 {
        tracing::debug!(
            event_type = "flow_talkers_truncated",
            kept = top_k,
            total = talkers.len(),
            dropped_over_cap = acc.talker_dropped,
            "truncated talker tail (count preserved in flow_iface_buckets)"
        );
    }
    if acc.talker_dropped > 0 {
        tracing::warn!(
            event_type = "flow_talker_cap_hit",
            dropped = acc.talker_dropped,
            cap = MAX_TALKER_KEYS,
            "talker cardinality exceeded the per-bucket cap — tail tuples dropped (aggregate totals unaffected)"
        );
    }
    for ((if_index, dir, src, dst, sport, dport, proto), c) in talkers.into_iter().take(top_k) {
        let iface_id = resolve_interface_id(pool, iface_cache, device_id, *if_index).await;
        sqlx::query(
            "INSERT INTO flow_talker_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, src_addr, dst_addr, src_port, dst_port, protocol, pkts, bytes, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = pkts + VALUES(pkts), bytes = bytes + VALUES(bytes)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(src.to_string()).bind(dst.to_string()).bind(*sport).bind(*dport).bind(*proto)
        .bind(c.pkts).bind(c.bytes).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Compare flow-estimated vs SNMP-measured ingress volume on the busiest
/// interface in this bucket. Returns (ratio = snmp/flow_estimate, derived_rate).
/// A derived rate is only proposed when no config override and no reported rate
/// exist, and only when the numbers are plausible — it is a calibrator, not a
/// hard source (SNMP and flow count slightly different things).
async fn cross_calibrate(
    pool: &MySqlPool,
    cfg: &Config,
    device_id: u64,
    acc: &Accum,
    sampling: &super::Sampling,
    configured: Option<u32>,
    reported: Option<u32>,
) -> Option<(f64, Option<u32>)> {
    let bucket_secs = cfg.flow.bucket_seconds.max(1) as f64;
    // Busiest ingress interface by bytes.
    let (&(if_index, _dir), c) = acc
        .iface
        .iter()
        .filter(|((_, d), _)| *d == Direction::Ingress)
        .max_by_key(|(_, c)| c.bytes)?;
    if c.bytes == 0 {
        return None;
    }
    let iface_id: Option<u64> =
        sqlx::query_scalar("SELECT id FROM device_interfaces WHERE device_id = ? AND if_index = ?")
            .bind(device_id)
            .bind(if_index)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    let iface_id = iface_id?;
    // SNMP's current rx rate for that interface (only trust a valid sample).
    let snmp: Option<(f64, bool)> = sqlx::query_as(
        "SELECT rx_bps, valid_sample FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(iface_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();
    let (snmp_rx_bps, valid) = snmp?;
    if !valid || snmp_rx_bps <= 0.0 {
        return None;
    }

    let flow_sampled_bps = c.bytes as f64 * 8.0 / bucket_secs;
    if flow_sampled_bps <= 0.0 {
        return None;
    }
    let flow_estimated_bps = flow_sampled_bps * sampling.rate as f64;
    let ratio = snmp_rx_bps / flow_estimated_bps;

    // Only derive a rate when we have nothing authoritative, and only if it lands
    // in a sane band (guards against transient SNMP/flow misalignment).
    let derived = if configured.is_none() && reported.is_none() {
        let r = (snmp_rx_bps / flow_sampled_bps).round();
        if (1.0..=100_000.0).contains(&r) {
            Some(r as u32)
        } else {
            None
        }
    } else {
        None
    };
    Some((ratio, derived))
}

/// Delete bucket rows older than the retention window from all three tables.
async fn prune_loop(pool: MySqlPool, cfg: Arc<Config>) {
    let minutes = cfg.flow.retention_minutes.max(1);
    loop {
        for table in [
            "flow_iface_buckets",
            "flow_port_buckets",
            "flow_as_buckets",
            "flow_talker_buckets",
        ] {
            let sql = format!("DELETE FROM {table} WHERE bucket_ts < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)");
            match sqlx::query(&sql).bind(minutes).execute(&pool).await {
                Ok(r) if r.rows_affected() > 0 => {
                    tracing::debug!(
                        event_type = "flow_buckets_pruned",
                        table,
                        rows = r.rows_affected(),
                        "pruned old flow buckets"
                    )
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(event_type = "flow_prune_failed", table, error = %e, "pruning flow buckets failed")
                }
            }
        }
        tokio::time::sleep(PRUNE_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{Accum, FlowRecord, MAX_TALKER_KEYS};
    use std::net::{IpAddr, Ipv4Addr};

    fn rec(src: u32) -> FlowRecord {
        FlowRecord {
            src_addr: IpAddr::V4(Ipv4Addr::from(src)),
            dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(1234),
            dst_port: Some(53),
            protocol: 17,
            in_if_index: Some(1),
            out_if_index: None,
            src_as: None,
            dst_as: None,
            direction: None,
            bytes: 100,
            pkts: 1,
        }
    }

    #[test]
    fn talker_accumulation_is_bounded_under_flood() {
        // A spoofed-source flood (millions of distinct 5-tuples — the exact DDoS
        // this tool watches for) must not grow the talker map without limit;
        // excess distinct tuples are refused and counted, never silently dropped.
        let mut acc = Accum::default();
        for i in 0..(MAX_TALKER_KEYS as u32 + 1000) {
            acc.fold(&rec(i));
        }
        assert!(acc.talker.len() <= MAX_TALKER_KEYS);
        assert!(
            acc.talker_dropped >= 1000,
            "expected >=1000 dropped, got {}",
            acc.talker_dropped
        );
    }
}
