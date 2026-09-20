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
use std::hash::Hash;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
/// How often to refresh the device -> source-IP allowlist.
const ALLOWLIST_INTERVAL: Duration = Duration::from_secs(30);
/// Hard cap on distinct exporters held in memory. The allowlist normally keeps
/// this tiny, but with `allowlist_enrolled_only = false` a spoofed-source flood
/// could otherwise grow the map without bound (memory-exhaustion DoS). When full,
/// a datagram from a *new* source evicts the least-recently-seen exporter.
const MAX_EXPORTERS: usize = 1_024;

/// Running counts for a single aggregation key.
#[derive(Debug, Clone, Copy)]
struct Counts {
    pkts: u64,
    bytes: u64,
    flows: u64,
    pkts_available: bool,
    bytes_available: bool,
}

impl Default for Counts {
    fn default() -> Self {
        Self {
            pkts: 0,
            bytes: 0,
            flows: 0,
            pkts_available: true,
            bytes_available: true,
        }
    }
}

impl Counts {
    fn add(&mut self, pkts: Option<u64>, bytes: Option<u64>) {
        // Attacker-controlled wire values accumulated across a bucket window:
        // saturate rather than panic (debug) / wrap (release) on overflow.
        match pkts {
            Some(value) => self.pkts = self.pkts.saturating_add(value),
            None => self.pkts_available = false,
        }
        match bytes {
            Some(value) => self.bytes = self.bytes.saturating_add(value),
            None => self.bytes_available = false,
        }
        self.flows = self.flows.saturating_add(1);
    }
}

type IfaceKey = (u32, Direction);
type PortKey = (u32, Direction, u8, PortKind, u16);
// PortKind is reused as the src/dst discriminator for the AS dimension.
type AsKey = (u32, Direction, PortKind, u32);
type TalkerKey = (u32, Direction, IpAddr, IpAddr, Option<u16>, Option<u16>, u8);
type ExporterKey = (IpAddr, Protocol, u32);

/// Hard cap on distinct talker 5-tuples held per bucket. Under a real spoofed-
/// source flood (millions of tiny distinct flows — the exact DDoS this tool
/// watches for) the talker map would otherwise grow until OOM before the
/// flush-time top-K trim. The iface/port/AS rollups still count every flow, and
/// the tail beyond top-K is dropped at flush regardless, so capping loses no
/// aggregate signal — only the identity of tail tuples past the cap. Well above
/// top_k_talkers so the retained top-K stays accurate.
const MAX_TALKER_KEYS: usize = 65_536;
const MAX_IFACE_KEYS: usize = 4_096;
const MAX_PORT_KEYS: usize = 65_536;
const MAX_AS_KEYS: usize = 65_536;

/// Hard cap on open/unflushed buckets retained per exporter. Normally 1-2 are
/// open; the map only grows when flushing fails (DB outage) and closed buckets
/// are re-queued for retry. Each retained `Accum` can hold up to
/// `MAX_TALKER_KEYS` tuples, so an unbounded backlog is an OOM path during a
/// sustained outage. When full, the OLDEST bucket is dropped: detection
/// anchors on the latest closed bucket, so old data is the least valuable,
/// and the drop is counted and logged.
const MAX_OPEN_BUCKETS: usize = 120;
const REGISTRATION_CHUNK: usize = 128;
const EXPORTER_FLUSH_CHUNK: usize = 32;
const SEQUENCE_REORDER_HALF_RANGE: u32 = u32::MAX / 2;
const UPTIME_REORDER_TOLERANCE_MS: u32 = 5 * 60 * 1000;

fn add_bounded<K: Eq + Hash>(
    map: &mut HashMap<K, Counts>,
    key: K,
    pkts: Option<u64>,
    bytes: Option<u64>,
    cap: usize,
) -> bool {
    if let Some(counts) = map.get_mut(&key) {
        counts.add(pkts, bytes);
        true
    } else if map.len() < cap {
        map.entry(key).or_default().add(pkts, bytes);
        true
    } else {
        false
    }
}

/// One bucket's aggregation across the reporting dimensions.
#[derive(Debug)]
struct Accum {
    iface: HashMap<IfaceKey, Counts>,
    port: HashMap<PortKey, Counts>,
    as_: HashMap<AsKey, Counts>,
    talker: HashMap<TalkerKey, Counts>,
    /// Distinct talker tuples refused this bucket after hitting MAX_TALKER_KEYS
    /// (surfaced at flush; never silent).
    talker_dropped: u64,
    /// Per-dimension loss is independent: talker truncation must never make an
    /// interface or port aggregate unavailable.
    iface_dropped: u64,
    port_dropped: u64,
    asn_dropped: u64,
    /// False when this exporter generation began after the bucket opened.
    base_complete: bool,
}

impl Default for Accum {
    fn default() -> Self {
        Self {
            iface: HashMap::new(),
            port: HashMap::new(),
            as_: HashMap::new(),
            talker: HashMap::new(),
            talker_dropped: 0,
            iface_dropped: 0,
            port_dropped: 0,
            asn_dropped: 0,
            base_complete: true,
        }
    }
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
        if !add_bounded(
            &mut self.iface,
            (ifindex, dir),
            fr.pkts,
            fr.bytes,
            MAX_IFACE_KEYS,
        ) {
            self.iface_dropped = self.iface_dropped.saturating_add(1);
        }

        if fr.has_ports() {
            if let Some(sp) = fr.src_port {
                if !add_bounded(
                    &mut self.port,
                    (ifindex, dir, fr.protocol, PortKind::Src, sp),
                    fr.pkts,
                    fr.bytes,
                    MAX_PORT_KEYS,
                ) {
                    self.port_dropped = self.port_dropped.saturating_add(1);
                }
            }
            if let Some(dp) = fr.dst_port {
                if !add_bounded(
                    &mut self.port,
                    (ifindex, dir, fr.protocol, PortKind::Dst, dp),
                    fr.pkts,
                    fr.bytes,
                    MAX_PORT_KEYS,
                ) {
                    self.port_dropped = self.port_dropped.saturating_add(1);
                }
            }
        }

        // AS dimension — only when the exporter collects AS and it's a real ASN
        // (0 = unknown / no BGP route).
        if let Some(asn) = fr.src_as.filter(|a| *a != 0) {
            if !add_bounded(
                &mut self.as_,
                (ifindex, dir, PortKind::Src, asn),
                fr.pkts,
                fr.bytes,
                MAX_AS_KEYS,
            ) {
                self.asn_dropped = self.asn_dropped.saturating_add(1);
            }
        }
        if let Some(asn) = fr.dst_as.filter(|a| *a != 0) {
            if !add_bounded(
                &mut self.as_,
                (ifindex, dir, PortKind::Dst, asn),
                fr.pkts,
                fr.bytes,
                MAX_AS_KEYS,
            ) {
                self.asn_dropped = self.asn_dropped.saturating_add(1);
            }
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

    fn mark_all_dropped(&mut self, count: u64) {
        self.iface_dropped = self.iface_dropped.saturating_add(count);
        self.port_dropped = self.port_dropped.saturating_add(count);
        self.asn_dropped = self.asn_dropped.saturating_add(count);
        self.talker_dropped = self.talker_dropped.saturating_add(count);
    }

    fn quality(&self, top_k: usize) -> BucketQuality {
        let talker_tail = self.talker.len().saturating_sub(top_k) as u64;
        let talker_dropped = self.talker_dropped.saturating_add(talker_tail);
        BucketQuality {
            iface_complete: self.base_complete && self.iface_dropped == 0,
            port_complete: self.base_complete && self.port_dropped == 0,
            asn_complete: self.base_complete && self.asn_dropped == 0,
            talker_complete: self.base_complete && talker_dropped == 0,
            iface_dropped: self.iface_dropped,
            port_dropped: self.port_dropped,
            asn_dropped: self.asn_dropped,
            talker_dropped,
        }
    }

    fn merge_from(&mut self, other: Accum) {
        self.base_complete &= other.base_complete;
        self.iface_dropped = self.iface_dropped.saturating_add(other.iface_dropped);
        self.port_dropped = self.port_dropped.saturating_add(other.port_dropped);
        self.asn_dropped = self.asn_dropped.saturating_add(other.asn_dropped);
        self.talker_dropped = self.talker_dropped.saturating_add(other.talker_dropped);
        merge_counts_map(
            &mut self.iface,
            other.iface,
            MAX_IFACE_KEYS,
            &mut self.iface_dropped,
        );
        merge_counts_map(
            &mut self.port,
            other.port,
            MAX_PORT_KEYS,
            &mut self.port_dropped,
        );
        merge_counts_map(&mut self.as_, other.as_, MAX_AS_KEYS, &mut self.asn_dropped);
        merge_counts_map(
            &mut self.talker,
            other.talker,
            MAX_TALKER_KEYS,
            &mut self.talker_dropped,
        );
    }
}

fn merge_counts_map<K: Eq + Hash>(
    into: &mut HashMap<K, Counts>,
    from: HashMap<K, Counts>,
    cap: usize,
    dropped: &mut u64,
) {
    for (key, counts) in from {
        if let Some(existing) = into.get_mut(&key) {
            existing.pkts = existing.pkts.saturating_add(counts.pkts);
            existing.bytes = existing.bytes.saturating_add(counts.bytes);
            existing.flows = existing.flows.saturating_add(counts.flows);
            existing.pkts_available &= counts.pkts_available;
            existing.bytes_available &= counts.bytes_available;
        } else if into.len() < cap {
            into.insert(key, counts);
        } else {
            *dropped = dropped.saturating_add(counts.flows.max(1));
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct BucketQuality {
    iface_complete: bool,
    port_complete: bool,
    asn_complete: bool,
    talker_complete: bool,
    iface_dropped: u64,
    port_dropped: u64,
    asn_dropped: u64,
    talker_dropped: u64,
}

/// In-memory per-exporter state. Keyed by source IP in [`State::exporters`].
#[derive(Debug)]
struct Exporter {
    /// DB `flow_exporters.id`; 0 until first persisted.
    db_id: u64,
    device_id: Option<u64>,
    /// Wire protocol for this exporter identity (9 / 5).
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
    /// Open buckets dropped because the per-exporter backlog hit
    /// [`MAX_OPEN_BUCKETS`] (evicted-oldest or refused-stale during a DB outage).
    dropped_bucket_backlog: u64,
    last_sequence: Option<u32>,
    last_sequence_bucket: Option<i64>,
    last_uptime: Option<u32>,
    /// Unix seconds of the most recent datagram — drives LRU eviction when the
    /// exporter map hits [`MAX_EXPORTERS`].
    last_seen: i64,
    /// Exporter-generation start time. A bucket already open when this exporter
    /// was first seen or restarted lacks its first segment.
    generation_started_at: i64,
}

impl Exporter {
    fn new(
        device_id: Option<u64>,
        version: u16,
        observation_domain: u32,
        generation_started_at: i64,
    ) -> Self {
        Self {
            db_id: 0,
            device_id,
            version,
            observation_domain,
            templates: TemplateCache::new(),
            buckets: HashMap::new(),
            reported_rate: None,
            snmp_derived_rate: None,
            snmp_xcal_ratio: None,
            datagrams_total: 0,
            dropped_no_template: 0,
            dropped_malformed: 0,
            dropped_bucket_backlog: 0,
            last_sequence: None,
            last_sequence_bucket: None,
            last_uptime: None,
            last_seen: 0,
            generation_started_at,
        }
    }

    /// Insert-or-get the bucket at `ts`, evicting the oldest bucket when the
    /// backlog cap ([`MAX_OPEN_BUCKETS`]) is reached. Returns `None` only if
    /// `ts` itself is older than (or equal to) every retained bucket in a full
    /// map — there is nothing older to evict in its favor, so the incoming
    /// bucket is refused. Every drop (evicted-oldest or refused-stale) bumps the
    /// saturating `dropped_bucket_backlog` counter.
    fn bucket_entry_bounded(&mut self, ts: i64) -> Option<&mut Accum> {
        if self.buckets.contains_key(&ts) {
            return self.buckets.get_mut(&ts);
        }
        if self.buckets.len() < MAX_OPEN_BUCKETS {
            let complete = ts >= self.generation_started_at;
            return Some(self.buckets.entry(ts).or_insert_with(|| Accum {
                base_complete: complete,
                ..Accum::default()
            }));
        }
        // Full and `ts` is not present: make room by dropping the oldest, but
        // only if `ts` is newer than it — never evict fresher data for staler.
        let oldest = match self.buckets.keys().copied().min() {
            Some(o) => o,
            // Unreachable: a full map (len >= cap >= 1) always has a min key.
            None => return Some(self.buckets.entry(ts).or_default()),
        };
        self.dropped_bucket_backlog = self.dropped_bucket_backlog.saturating_add(1);
        if ts <= oldest {
            return None;
        }
        self.buckets.remove(&oldest);
        let complete = ts >= self.generation_started_at;
        Some(self.buckets.entry(ts).or_insert_with(|| Accum {
            base_complete: complete,
            ..Accum::default()
        }))
    }

    fn reset_generation(&mut self, now: i64, bucket_ts: i64) {
        self.generation_started_at = now;
        if let Some(bucket) = self.buckets.get_mut(&bucket_ts) {
            bucket.base_complete = false;
        }
    }

    /// Observe a per-exporter datagram sequence. Forward jumps identify packet
    /// loss; wrap is handled by wrapping subtraction, while duplicates and old
    /// out-of-order datagrams do not move the watermark. Uptime reset starts a
    /// new generation instead of manufacturing a huge gap.
    fn observe_sequence(
        &mut self,
        sequence: u32,
        uptime: Option<u32>,
        explicit_restart: bool,
        now: i64,
        bucket_ts: i64,
    ) -> u64 {
        let uptime_wrapped = self
            .last_uptime
            .zip(uptime)
            .is_some_and(|(previous, current)| {
                previous > u32::MAX - UPTIME_REORDER_TOLERANCE_MS
                    && current < UPTIME_REORDER_TOLERANCE_MS
            });
        let uptime_restarted = self
            .last_uptime
            .zip(uptime)
            .is_some_and(|(previous, current)| {
                !uptime_wrapped && previous.saturating_sub(current) > UPTIME_REORDER_TOLERANCE_MS
            });
        if explicit_restart || uptime_restarted {
            self.reset_generation(now, bucket_ts);
            self.last_sequence = Some(sequence);
            self.last_sequence_bucket = Some(bucket_ts);
            self.last_uptime = uptime;
            return 0;
        }

        // A small uptime regression may be reordering or an early restart. It
        // is not enough evidence to rewind the sequence watermark, but neither
        // interpretation proves a complete bucket.
        if self
            .last_uptime
            .zip(uptime)
            .is_some_and(|(previous, current)| !uptime_wrapped && current < previous)
        {
            if let Some(bucket) = self.bucket_entry_bounded(bucket_ts) {
                bucket.base_complete = false;
            }
        }

        let missing = match self.last_sequence {
            None => 0,
            Some(previous) => {
                let delta = sequence.wrapping_sub(previous);
                if delta > 1 && delta < SEQUENCE_REORDER_HALF_RANGE {
                    u64::from(delta - 1)
                } else {
                    0
                }
            }
        };
        if missing > 0 {
            if let Some(previous_bucket) = self.last_sequence_bucket {
                if previous_bucket != bucket_ts {
                    if let Some(accum) = self.buckets.get_mut(&previous_bucket) {
                        accum.mark_all_dropped(missing);
                    }
                }
            }
        }
        let advances = self.last_sequence.is_none_or(|previous| {
            let delta = sequence.wrapping_sub(previous);
            delta > 0 && delta < SEQUENCE_REORDER_HALF_RANGE
        });
        if advances {
            self.last_sequence = Some(sequence);
            self.last_sequence_bucket = Some(bucket_ts);
            self.last_uptime = uptime.or(self.last_uptime);
        }
        missing
    }
}

/// Shared collector state. Guarded by a std Mutex — never held across an await.
#[derive(Default)]
struct State {
    /// (source IP, wire protocol, observation domain/sub-agent) -> exporter.
    exporters: HashMap<ExporterKey, Exporter>,
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

    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(refresh_allowlist(pool.clone(), state.clone()));
    tasks.spawn(flush_loop(pool.clone(), cfg.clone(), state.clone()));
    // Flow-bucket retention is enforced centrally by scheduler::retention_cleanup
    // (unified under [retention].flow_buckets_days), not here.

    // Both listeners share the same in-memory State (exporter map, allowlist),
    // so their flows aggregate into the same buckets and exporter-health rows.
    if let Some(sf) = sflow_socket {
        tasks.spawn(recv_loop(sf, Protocol::Sflow, cfg.clone(), state.clone()));
    }
    tasks.spawn(recv_loop(nf_socket, Protocol::NetflowV9, cfg, state));
    if let Some(outcome) = tasks.join_next().await {
        match outcome {
            Ok(()) => tracing::error!(
                event_type = "flow_subtask_exited",
                "flow collector subtask exited unexpectedly"
            ),
            Err(e) => {
                tracing::error!(event_type = "flow_subtask_panicked", error = %e, "flow collector subtask panicked")
            }
        }
    }
    tasks.abort_all();
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
            st.dropped_not_allowlisted = st.dropped_not_allowlisted.saturating_add(1);
            continue;
        }

        let Some(observation_domain) = wire_observation_domain(proto, &buf[..len]) else {
            tracing::debug!(event_type = "flow_header_invalid", source = %src_ip, proto = ?proto, "dropped flow datagram with an invalid protocol header");
            continue;
        };

        // Bound the exporter map: if this is a new source and we are at capacity,
        // evict the least-recently-seen exporter so a high-entropy spoofed flood
        // cannot grow memory without limit.
        let exporter_key = (src_ip, proto, observation_domain);
        if st
            .exporters
            .get(&exporter_key)
            .is_some_and(|exporter| exporter.device_id != device_id)
        {
            // An address was reassigned to a different enrolled device (or was
            // newly mapped). Drop its old templates and open buckets rather than
            // attributing them across devices.
            st.exporters.remove(&exporter_key);
            tracing::warn!(event_type = "flow_exporter_device_changed", source = %src_ip, proto = ?proto, observation_domain, new_device_id = ?device_id, "reset exporter state after its allowlist device mapping changed");
        }
        if !st.exporters.contains_key(&exporter_key) && st.exporters.len() >= MAX_EXPORTERS {
            if let Some(victim) = st
                .exporters
                .iter()
                .min_by_key(|(_, ex)| ex.last_seen)
                .map(|(key, _)| *key)
            {
                st.exporters.remove(&victim);
                st.evicted_exporters = st.evicted_exporters.saturating_add(1);
                tracing::warn!(
                    event_type = "flow_exporter_evicted",
                    evicted_source = %victim.0,
                    evicted_protocol = ?victim.1,
                    evicted_observation_domain = victim.2,
                    incoming = %src_ip,
                    cap = MAX_EXPORTERS,
                    "exporter map full — evicted least-recently-seen exporter"
                );
            }
        }

        let exporter = st
            .exporters
            .entry(exporter_key)
            .or_insert_with(|| Exporter::new(device_id, proto.version(), observation_domain, now));
        exporter.datagrams_total = exporter.datagrams_total.saturating_add(1);
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
                    if d.exporter_restarted || d.sampling_state_expired {
                        // Sampling options belong to the old exporter generation.
                        // Keep configured DB overrides, but relearn reported/derived
                        // evidence alongside the new template generation.
                        exporter.reported_rate = None;
                        exporter.snmp_derived_rate = None;
                        exporter.snmp_xcal_ratio = None;
                    }
                    exporter.dropped_no_template = exporter
                        .dropped_no_template
                        .saturating_add(d.data_without_template as u64);
                    (
                        d.sequence,
                        Some(d.sys_uptime),
                        d.exporter_restarted,
                        d.reported_sampling,
                        d.records,
                        d.data_without_template as u64,
                    )
                })
                .map_err(|e| e.to_string()),
            Protocol::Sflow => sflow::decode(&buf[..len])
                .map(|d| {
                    (
                        d.sequence,
                        Some(d.uptime),
                        false,
                        d.reported_sampling,
                        d.records,
                        0,
                    )
                })
                .map_err(|e| e.to_string()),
        };

        match decoded {
            Ok((sequence, uptime, restarted, reported_sampling, records, decode_dropped)) => {
                let previous_sequence = exporter.last_sequence;
                let previous_generation = exporter.generation_started_at;
                let sequence_dropped =
                    exporter.observe_sequence(sequence, uptime, restarted, now, bucket_ts);
                if previous_sequence.is_some()
                    && exporter.last_sequence == previous_sequence
                    && exporter.generation_started_at == previous_generation
                    && !restarted
                {
                    // Do not count a duplicate twice or attribute a reordered
                    // old datagram to its arrival bucket as fresh traffic.
                    if let Some(accum) = exporter.bucket_entry_bounded(bucket_ts) {
                        accum.mark_all_dropped(1);
                    }
                    continue;
                }
                if let Some(rate) = reported_sampling {
                    exporter.reported_rate = Some(rate);
                }
                if !records.is_empty() || decode_dropped > 0 || sequence_dropped > 0 {
                    // `None` means this datagram's bucket lost the backlog-cap
                    // eviction race during a DB outage; the drop is counted
                    // inside the helper, so just skip folding.
                    if let Some(accum) = exporter.bucket_entry_bounded(bucket_ts) {
                        accum.mark_all_dropped(decode_dropped.saturating_add(sequence_dropped));
                        for fr in &records {
                            accum.fold(fr);
                        }
                    }
                }
            }
            Err(e) => {
                exporter.dropped_malformed = exporter.dropped_malformed.saturating_add(1);
                let sequence_dropped = wire_sequence_and_uptime(proto, &buf[..len])
                    .map(|(sequence, uptime)| {
                        exporter.observe_sequence(sequence, uptime, false, now, bucket_ts)
                    })
                    .unwrap_or(0);
                if let Some(accum) = exporter.bucket_entry_bounded(bucket_ts) {
                    accum.mark_all_dropped(1u64.saturating_add(sequence_dropped));
                }
                tracing::debug!(event_type = "flow_decode_failed", source = %src_ip, proto = ?proto, error = %e, "dropped malformed flow datagram");
            }
        }
    }
}

/// Extract the exporter domain from the fixed protocol header before allocating
/// state. NetFlow template caches and buckets are domain-scoped; sFlow uses its
/// sub-agent id for the same durable identity.
fn wire_observation_domain(proto: Protocol, buf: &[u8]) -> Option<u32> {
    fn u32_at(buf: &[u8], offset: usize) -> Option<u32> {
        let bytes: [u8; 4] = buf.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
    match proto {
        Protocol::NetflowV9 => {
            let version = u16::from_be_bytes(buf.get(0..2)?.try_into().ok()?);
            (version == 9).then(|| u32_at(buf, 16)).flatten()
        }
        Protocol::Sflow => {
            if u32_at(buf, 0)? != 5 {
                return None;
            }
            let agent_len = match u32_at(buf, 4)? {
                1 => 4,
                2 => 16,
                _ => return None,
            };
            u32_at(buf, 8usize.checked_add(agent_len)?)
        }
    }
}

/// Read only the fixed sequence/uptime header fields. This remains available
/// when full decoding fails, so a malformed datagram advances the sequence
/// watermark once and the following valid packet is not counted as another gap.
fn wire_sequence_and_uptime(proto: Protocol, buf: &[u8]) -> Option<(u32, Option<u32>)> {
    fn u32_at(buf: &[u8], offset: usize) -> Option<u32> {
        let bytes: [u8; 4] = buf.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }
    match proto {
        Protocol::NetflowV9 => Some((u32_at(buf, 12)?, Some(u32_at(buf, 4)?))),
        Protocol::Sflow => {
            let agent_len = match u32_at(buf, 4)? {
                1 => 4,
                2 => 16,
                _ => return None,
            };
            Some((
                u32_at(buf, 12usize.checked_add(agent_len)?)?,
                Some(u32_at(buf, 16usize.checked_add(agent_len)?)?),
            ))
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
        match state.lock() {
            Ok(mut st) => st.allow = allow,
            Err(poisoned) => poisoned.into_inner().allow = allow,
        }
        tokio::time::sleep(ALLOWLIST_INTERVAL).await;
    }
}

/// A snapshot of one exporter's flushable state, taken under the lock and then
/// processed without it.
struct ExporterFlush {
    src_ip: IpAddr,
    protocol: Protocol,
    device_id: Option<u64>,
    version: u16,
    observation_domain: u32,
    template_count: u32,
    reported_rate: Option<u32>,
    snmp_derived_rate: Option<u32>,
    datagrams_total: u64,
    dropped_no_template: u64,
    dropped_malformed: u64,
    dropped_bucket_backlog: u64,
    last_sequence: Option<u32>,
    last_seen: i64,
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
        {
            let mut st = match state.lock() {
                Ok(st) => st,
                Err(poisoned) => poisoned.into_inner(),
            };
            for ((ip, protocol, _domain), ex) in st.exporters.iter_mut() {
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
                    protocol: *protocol,
                    device_id: ex.device_id,
                    version: ex.version,
                    observation_domain: ex.observation_domain,
                    template_count: ex.templates.len() as u32,
                    reported_rate: ex.reported_rate,
                    snmp_derived_rate: ex.snmp_derived_rate,
                    datagrams_total: ex.datagrams_total,
                    dropped_no_template: ex.dropped_no_template,
                    dropped_malformed: ex.dropped_malformed,
                    dropped_bucket_backlog: ex.dropped_bucket_backlog,
                    last_sequence: ex.last_sequence,
                    last_seen: ex.last_seen,
                    closed,
                });
            }
        }

        let publication_generation = match prepare_flush_batch(&pool, &flushes).await {
            Ok(generation) => generation,
            Err(e) => {
                let retry_count: usize = flushes.iter().map(|f| f.closed.len()).sum();
                requeue_flushes(&state, &mut flushes);
                tracing::warn!(event_type = "flow_flush_prepare_failed", retry_buckets = retry_count, error = %e, "preparing flow contributor coverage failed; no bucket quality was published");
                continue;
            }
        };

        let mut published_interfaces = std::collections::BTreeSet::new();
        for cohort in flushes.chunks_mut(EXPORTER_FLUSH_CHUNK) {
            for f in cohort {
                let mut committed = std::collections::BTreeSet::new();
                match flush_exporter(
                    &pool,
                    &cfg,
                    f,
                    &mut committed,
                    None,
                    &publication_generation,
                )
                .await
                {
                    Ok(Some((ip, protocol, db_id, derived, ratio))) => {
                        // Write back DB id + values derived this flush (carried forward).
                        let mut st = match state.lock() {
                            Ok(st) => st,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if let Some(ex) =
                            st.exporters.get_mut(&(ip, protocol, f.observation_domain))
                        {
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
                    Ok(None) => {}
                    Err(e) => {
                        let retry_count = f.closed.len();
                        requeue_flushes(&state, std::slice::from_mut(f));
                        tracing::warn!(event_type = "flow_flush_failed", retry_buckets = retry_count, error = %e, "flushing flow buckets failed; uncommitted buckets retained for retry")
                    }
                }
                published_interfaces.extend(committed);
            }
            tokio::task::yield_now().await;
        }
        if !published_interfaces.is_empty() {
            let mut ids = Vec::new();
            for (device_id, if_index) in published_interfaces {
                if let Ok(Some(id)) = sqlx::query_scalar::<_, u64>(
                    "SELECT id FROM device_interfaces WHERE device_id=? AND if_index=?",
                )
                .bind(device_id)
                .bind(if_index)
                .fetch_optional(&pool)
                .await
                {
                    ids.push(id);
                }
            }
            if !ids.is_empty() {
                cfg.flow_wake.mark_interfaces(ids);
            }
        }
    }
}

fn requeue_flushes(state: &Arc<Mutex<State>>, flushes: &mut [ExporterFlush]) {
    let mut st = match state.lock() {
        Ok(st) => st,
        Err(poisoned) => poisoned.into_inner(),
    };
    for f in flushes {
        let Some(ex) = st
            .exporters
            .get_mut(&(f.src_ip, f.protocol, f.observation_domain))
        else {
            continue;
        };
        let dropped_before = ex.dropped_bucket_backlog;
        for (ts, acc) in f.closed.drain(..) {
            if let Some(current) = ex.buckets.get_mut(&ts) {
                current.merge_from(acc);
            } else if let Some(slot) = ex.bucket_entry_bounded(ts) {
                *slot = acc;
            }
        }
        if ex.dropped_bucket_backlog != dropped_before {
            tracing::warn!(event_type = "flow_bucket_backlog_capped", source = %f.src_ip, proto = ?f.protocol, dropped_bucket_backlog = ex.dropped_bucket_backlog, open_buckets = ex.buckets.len(), "open-bucket backlog cap reached during flush retry; oldest/excess buckets dropped")
        }
    }
}

/// Establish every contributor in the snapshot before any bucket quality row
/// becomes visible. If a later exporter write fails, its membership remains and
/// the missing exact interface row makes already-written peers unavailable.
async fn prepare_flush_batch(
    pool: &MySqlPool,
    flushes: &[ExporterFlush],
) -> anyhow::Result<String> {
    if flushes.iter().all(|flush| flush.closed.is_empty()) {
        return Ok("no-buckets".into());
    }
    prepare_flush_batch_inner(pool, flushes, None)
        .await
        .map(|(_, generation)| generation)
}

#[derive(Debug, Default)]
struct RegistrationStats {
    rows: usize,
    chunks: usize,
}

async fn prepare_flush_batch_inner(
    pool: &MySqlPool,
    flushes: &[ExporterFlush],
    fail_after_chunks_for_test: Option<usize>,
) -> anyhow::Result<(RegistrationStats, String)> {
    let mut stats = RegistrationStats::default();
    let generation = uuid::Uuid::new_v4().to_string();
    let mut barrier = pool.begin().await?;
    let changed =
        sqlx::query("UPDATE flow_publication_barrier SET generation=?,registry_ready=0 WHERE id=1")
            .bind(&generation)
            .execute(&mut *barrier)
            .await?
            .rows_affected();
    anyhow::ensure!(changed == 1, "flow publication barrier singleton missing");
    barrier.commit().await?;
    for f in flushes {
        if f.closed.is_empty() {
            continue;
        }
        let mut tx = pool.begin().await?;
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let Some(device_id) = f.device_id else {
            continue;
        };
        let exporter_id: u64 = sqlx::query_scalar(
            "SELECT id FROM flow_exporters WHERE source_addr=? AND observation_domain=? AND version=?",
        )
        .bind(f.src_ip.to_string())
        .bind(f.observation_domain)
        .bind(f.version)
        .fetch_one(pool)
        .await?;
        let bucket_times = f
            .closed
            .iter()
            .map(|(ts, _)| *ts)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        for chunk in bucket_times.chunks(REGISTRATION_CHUNK) {
            let mut tx = pool.begin().await?;
            let mut query = sqlx::QueryBuilder::<sqlx::MySql>::new(
                "DELETE FROM flow_bucket_quality WHERE exporter_id=",
            );
            query.push_bind(exporter_id).push(" AND bucket_ts IN (");
            let mut separated = query.separated(",");
            for ts in chunk {
                separated.push_bind(Utc.timestamp_opt(*ts, 0).single().unwrap_or_else(Utc::now));
            }
            query.push(")");
            query.build().execute(&mut *tx).await?;
            tx.commit().await?;
            tokio::task::yield_now().await;
        }
        let mut wanted = HashMap::<(u32, Direction), (i64, i64)>::new();
        for (bucket_ts, acc) in &f.closed {
            for key in acc.iface.keys() {
                wanted
                    .entry(*key)
                    .and_modify(|range| {
                        range.0 = range.0.min(*bucket_ts);
                        range.1 = range.1.max(*bucket_ts);
                    })
                    .or_insert((*bucket_ts, *bucket_ts));
            }
        }
        let indexes = wanted
            .keys()
            .map(|(index, _)| *index)
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut resolved = HashMap::new();
        for chunk in indexes.chunks(REGISTRATION_CHUNK) {
            let mut query = sqlx::QueryBuilder::<sqlx::MySql>::new(
                "SELECT id,if_index FROM device_interfaces WHERE device_id=",
            );
            query.push_bind(device_id).push(" AND if_index IN (");
            let mut separated = query.separated(",");
            for index in chunk {
                separated.push_bind(*index);
            }
            query.push(")");
            for (id, index) in query.build_query_as::<(u64, u32)>().fetch_all(pool).await? {
                resolved.insert(index, id);
            }
            tokio::task::yield_now().await;
        }
        let mut rows = wanted
            .into_iter()
            .filter_map(|((if_index, direction), (first, last))| {
                resolved
                    .get(&if_index)
                    .copied()
                    .map(|interface_id| (interface_id, if_index, direction, first, last))
            })
            .collect::<Vec<_>>();
        rows.sort_by_key(|(_, if_index, direction, _, _)| (*if_index, direction.as_str()));
        for chunk in rows.chunks(REGISTRATION_CHUNK) {
            let mut tx = pool.begin().await?;
            for (interface_id, if_index, direction, first, last) in chunk {
                sqlx::query(
                    "INSERT INTO flow_exporter_interfaces \
                        (exporter_id,device_id,interface_id,if_index,direction,first_seen_at,last_seen_at) \
                     VALUES (?,?,?,?,?,?,?) \
                     ON DUPLICATE KEY UPDATE first_seen_at=LEAST(first_seen_at,VALUES(first_seen_at)), \
                        last_seen_at=GREATEST(last_seen_at,VALUES(last_seen_at)), \
                        device_id=VALUES(device_id),if_index=VALUES(if_index)",
                )
                .bind(exporter_id)
                .bind(device_id)
                .bind(interface_id)
                .bind(if_index)
                .bind(direction.as_str())
                .bind(Utc.timestamp_opt(*first,0).single().unwrap_or_else(Utc::now))
                .bind(Utc.timestamp_opt(*last,0).single().unwrap_or_else(Utc::now))
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            stats.rows += chunk.len();
            stats.chunks += 1;
            tokio::task::yield_now().await;
            if fail_after_chunks_for_test == Some(stats.chunks) {
                anyhow::bail!("injected contributor registration failure");
            }
        }
    }
    let ready=sqlx::query("UPDATE flow_publication_barrier SET registry_ready=1 WHERE id=1 AND generation=? AND registry_ready=0")
        .bind(&generation).execute(pool).await?.rows_affected();
    anyhow::ensure!(ready == 1, "flow publication generation was superseded");
    Ok((stats, generation))
}

/// Persist one exporter: upsert its row, resolve its sampling, write any closed
/// buckets, run SNMP cross-calibration, and update its health. Returns
/// (ip, db_id, snmp_derived_rate, snmp_xcal_ratio) to write back.
type FlushBack = (IpAddr, Protocol, u64, Option<u32>, Option<f64>);

async fn flush_exporter(
    pool: &MySqlPool,
    cfg: &Config,
    f: &mut ExporterFlush,
    committed: &mut std::collections::BTreeSet<(u64, u32)>,
    fail_bucket_for_test: Option<i64>,
    publication_generation: &str,
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
        "SELECT id, configured_sampling_rate FROM flow_exporters \
         WHERE source_addr = ? AND observation_domain = ? AND version = ?",
    )
    .bind(f.src_ip.to_string())
    .bind(f.observation_domain)
    .bind(f.version)
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
        f.closed.sort_by_key(|(ts, _)| *ts);
        let mut newest = true;
        while let Some((ts, acc)) = f.closed.pop() {
            if fail_bucket_for_test == Some(ts) {
                f.closed.push((ts, acc));
                anyhow::bail!("injected bucket flush failure");
            }
            let bucket_ts = Utc.timestamp_opt(ts, 0).single().unwrap_or_else(Utc::now);
            let ctx = BucketCtx {
                exporter_id,
                device_id,
                bucket_ts,
            };
            if let Err(e) = write_bucket(
                pool,
                cfg,
                &ctx,
                &acc,
                &sampling,
                &mut iface_id_cache,
                publication_generation,
            )
            .await
            {
                f.closed.push((ts, acc));
                return Err(e);
            }
            committed.extend(acc.iface.keys().map(|(if_index, _)| (device_id, *if_index)));
            if newest {
                if let Some((ratio, derived)) = cross_calibrate(
                    pool,
                    cfg,
                    device_id,
                    &acc,
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
                newest = false;
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
            dropped_bucket_backlog = ?, \
            last_packet_at = CASE \
                WHEN last_packet_at IS NULL OR last_packet_at < FROM_UNIXTIME(?) \
                THEN FROM_UNIXTIME(?) ELSE last_packet_at END \
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
    .bind(f.dropped_bucket_backlog)
    .bind(f.last_seen)
    .bind(f.last_seen)
    .bind(exporter_id)
    .execute(pool)
    .await?;

    Ok(Some((
        f.src_ip,
        f.protocol,
        exporter_id,
        snmp_derived,
        xcal_ratio,
    )))
}

/// Resolve an ifIndex to a `device_interfaces.id` (cached per flush).
async fn resolve_interface_id(
    conn: &mut sqlx::MySqlConnection,
    cache: &mut HashMap<u32, Option<u64>>,
    device_id: u64,
    if_index: u32,
) -> anyhow::Result<Option<u64>> {
    if let Some(v) = cache.get(&if_index) {
        return Ok(*v);
    }
    let id: Option<u64> =
        sqlx::query_scalar("SELECT id FROM device_interfaces WHERE device_id = ? AND if_index = ?")
            .bind(device_id)
            .bind(if_index)
            .fetch_optional(&mut *conn)
            .await?;
    cache.insert(if_index, id);
    Ok(id)
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
    publication_generation: &str,
) -> anyhow::Result<()> {
    let BucketCtx {
        exporter_id,
        device_id,
        bucket_ts,
    } = *ctx;
    let mut timing = crate::timing::Stage::start("bucket_commit", exporter_id);
    let rate = sampling.rate;
    let conf = sampling.confidence_str();
    if acc.iface_dropped > 0 || acc.port_dropped > 0 || acc.asn_dropped > 0 {
        tracing::warn!(
            event_type = "flow_rollup_cardinality_capped",
            exporter_id,
            device_id,
            iface_dropped = acc.iface_dropped,
            port_dropped = acc.port_dropped,
            asn_dropped = acc.asn_dropped,
            "flow interface/port/ASN cardinality exceeded a bounded bucket cap"
        );
    }
    let mut tx = pool.begin().await?;
    let ready:Option<String>=sqlx::query_scalar("SELECT generation FROM flow_publication_barrier WHERE id=1 AND registry_ready=1 AND generation=? FOR UPDATE")
        .bind(publication_generation).fetch_optional(&mut *tx).await?;
    anyhow::ensure!(
        ready.as_deref() == Some(publication_generation),
        "flow publication generation is not ready or was superseded"
    );
    let quality = acc.quality(cfg.flow.top_k_talkers.max(1));

    // Interface totals.
    for ((if_index, dir), c) in &acc.iface {
        let iface_id = resolve_interface_id(&mut tx, iface_cache, device_id, *if_index).await?;
        sqlx::query(
            "INSERT INTO flow_iface_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, pkts, pkts_available, bytes, bytes_available, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = VALUES(pkts), pkts_available = VALUES(pkts_available), \
                bytes = VALUES(bytes), bytes_available = VALUES(bytes_available), flow_count = VALUES(flow_count), \
                effective_sampling_rate = VALUES(effective_sampling_rate), sampling_confidence = VALUES(sampling_confidence)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(c.pkts).bind(c.pkts_available).bind(c.bytes).bind(c.bytes_available)
        .bind(c.flows).bind(rate).bind(conf)
        .execute(&mut *tx).await?;

        // Only discovered/enrolled interfaces enter the contributor registry;
        // this bounds membership by device_interfaces and prevents arbitrary
        // wire ifIndex values from creating durable identities.
        if let Some(interface_id) = iface_id {
            sqlx::query(
                "INSERT INTO flow_exporter_interfaces \
                    (exporter_id, device_id, interface_id, if_index, direction, first_seen_at, last_seen_at) \
                 VALUES (?, ?, ?, ?, ?, ?, ?) \
                 ON DUPLICATE KEY UPDATE first_seen_at = LEAST(first_seen_at, VALUES(first_seen_at)), \
                    last_seen_at = GREATEST(last_seen_at, VALUES(last_seen_at)), \
                    device_id = VALUES(device_id), if_index = VALUES(if_index)",
            )
            .bind(exporter_id)
            .bind(device_id)
            .bind(interface_id)
            .bind(*if_index)
            .bind(dir.as_str())
            .bind(bucket_ts)
            .bind(bucket_ts)
            .execute(&mut *tx)
            .await?;
        }
    }

    // Port rollups.
    for ((if_index, dir, proto, kind, port), c) in &acc.port {
        let iface_id = resolve_interface_id(&mut tx, iface_cache, device_id, *if_index).await?;
        sqlx::query(
            "INSERT INTO flow_port_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, protocol, port_kind, port, pkts, pkts_available, bytes, bytes_available, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = VALUES(pkts), pkts_available = VALUES(pkts_available), \
                bytes = VALUES(bytes), bytes_available = VALUES(bytes_available), flow_count = VALUES(flow_count), \
                effective_sampling_rate = VALUES(effective_sampling_rate), sampling_confidence = VALUES(sampling_confidence)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(*proto).bind(kind.as_str()).bind(*port)
        .bind(c.pkts).bind(c.pkts_available).bind(c.bytes).bind(c.bytes_available)
        .bind(c.flows).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    // AS rollups (only present when the exporter collects SRC_AS/DST_AS).
    for ((if_index, dir, kind, asn), c) in &acc.as_ {
        let iface_id = resolve_interface_id(&mut tx, iface_cache, device_id, *if_index).await?;
        sqlx::query(
            "INSERT INTO flow_as_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, as_kind, asn, pkts, pkts_available, bytes, bytes_available, flow_count, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = VALUES(pkts), pkts_available = VALUES(pkts_available), \
                bytes = VALUES(bytes), bytes_available = VALUES(bytes_available), flow_count = VALUES(flow_count), \
                effective_sampling_rate = VALUES(effective_sampling_rate), sampling_confidence = VALUES(sampling_confidence)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(kind.as_str()).bind(*asn)
        .bind(c.pkts).bind(c.pkts_available).bind(c.bytes).bind(c.bytes_available)
        .bind(c.flows).bind(rate).bind(conf)
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
        let iface_id = resolve_interface_id(&mut tx, iface_cache, device_id, *if_index).await?;
        sqlx::query(
            "INSERT INTO flow_talker_buckets \
                (exporter_id, device_id, interface_id, if_index, direction, bucket_ts, src_addr, dst_addr, src_port, dst_port, protocol, pkts, pkts_available, bytes, bytes_available, effective_sampling_rate, sampling_confidence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE pkts = VALUES(pkts), pkts_available = VALUES(pkts_available), \
                bytes = VALUES(bytes), bytes_available = VALUES(bytes_available), \
                effective_sampling_rate = VALUES(effective_sampling_rate), sampling_confidence = VALUES(sampling_confidence)",
        )
        .bind(exporter_id).bind(device_id).bind(iface_id).bind(*if_index).bind(dir.as_str())
        .bind(bucket_ts).bind(src.to_string()).bind(dst.to_string()).bind(*sport).bind(*dport).bind(*proto)
        .bind(c.pkts).bind(c.pkts_available).bind(c.bytes).bind(c.bytes_available).bind(rate).bind(conf)
        .execute(&mut *tx).await?;
    }

    sqlx::query(
        "INSERT INTO flow_bucket_quality \
            (exporter_id, bucket_ts, iface_complete, port_complete, asn_complete, talker_complete, \
             iface_dropped, port_dropped, asn_dropped, talker_dropped) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE iface_complete = VALUES(iface_complete), \
            port_complete = VALUES(port_complete), asn_complete = VALUES(asn_complete), \
            talker_complete = VALUES(talker_complete), iface_dropped = VALUES(iface_dropped), \
            port_dropped = VALUES(port_dropped), asn_dropped = VALUES(asn_dropped), \
            talker_dropped = VALUES(talker_dropped)",
    )
    .bind(exporter_id)
    .bind(bucket_ts)
    .bind(quality.iface_complete)
    .bind(quality.port_complete)
    .bind(quality.asn_complete)
    .bind(quality.talker_complete)
    .bind(quality.iface_dropped)
    .bind(quality.port_dropped)
    .bind(quality.asn_dropped)
    .bind(quality.talker_dropped)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    timing.complete("committed");
    tracing::info!(event_type = "flow_bucket_committed", exporter_id, device_id,
        bucket_ts = %bucket_ts, bucket_width_seconds = cfg.flow.bucket_seconds,
        "flow aggregates and quality published together");
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
    if !c.bytes_available || c.bytes == 0 {
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

#[cfg(test)]
mod tests {
    use super::{
        flush_exporter, prepare_flush_batch, prepare_flush_batch_inner, wire_observation_domain,
        write_bucket, Accum, BucketCtx, Direction, Exporter, ExporterFlush, FlowRecord, Protocol,
        MAX_OPEN_BUCKETS, MAX_PORT_KEYS, MAX_TALKER_KEYS, REGISTRATION_CHUNK,
    };
    use crate::telemetry::flow::quality::{
        bucket_evidence, EvidenceAvailability, QualityDimension,
    };
    use crate::telemetry::flow::{Sampling, SamplingSource};
    use chrono::{TimeZone, Utc};
    use std::collections::HashMap;
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
            bytes: Some(100),
            pkts: Some(1),
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
        assert_eq!(acc.iface_dropped, 0);
        assert_eq!(acc.port_dropped, 0);
        assert_eq!(acc.asn_dropped, 0);
        assert!(!acc.quality(100).talker_complete);
        assert!(acc.quality(100).iface_complete);
        assert!(acc.quality(100).port_complete);
        assert_eq!(
            acc.iface.get(&(1, Direction::Ingress)).unwrap().flows,
            MAX_TALKER_KEYS as u64 + 1000,
            "talker loss must not change interface totals"
        );
    }

    #[test]
    fn port_cap_only_marks_port_dimension_incomplete() {
        let mut acc = Accum::default();
        for port in 0..=u16::MAX {
            let mut flow = rec(port as u32);
            flow.src_port = Some(port);
            flow.dst_port = Some(port);
            acc.fold(&flow);
        }
        let mut overflow = rec(u32::MAX);
        overflow.protocol = 6;
        acc.fold(&overflow);

        assert_eq!(acc.port.len(), MAX_PORT_KEYS);
        let quality = acc.quality(usize::MAX);
        assert!(!quality.port_complete);
        assert!(quality.iface_complete);
        assert!(quality.asn_complete);
    }

    #[test]
    fn bucket_started_before_collector_is_incomplete_but_next_bucket_is_fresh() {
        let mut acc = Accum {
            base_complete: false,
            ..Default::default()
        };
        let partial = acc.quality(100);
        assert!(!partial.iface_complete);
        assert!(!partial.port_complete);
        assert!(!partial.asn_complete);
        assert!(!partial.talker_complete);

        acc.base_complete = true;
        let fresh = acc.quality(100);
        assert!(fresh.iface_complete);
        assert!(fresh.port_complete);
        assert!(fresh.asn_complete);
        assert!(fresh.talker_complete);

        let mut discovered_mid_bucket = Exporter::new(None, 9, 0, 95);
        assert!(
            !discovered_mid_bucket
                .bucket_entry_bounded(60)
                .unwrap()
                .quality(100)
                .iface_complete
        );
        assert!(
            discovered_mid_bucket
                .bucket_entry_bounded(120)
                .unwrap()
                .quality(100)
                .iface_complete
        );
    }

    #[test]
    fn sequence_gaps_wrap_reorder_and_restart_are_conservative() {
        let mut ex = Exporter::new(None, 5, 7, 60);
        assert_eq!(ex.observe_sequence(u32::MAX, Some(1000), false, 61, 60), 0);
        assert_eq!(ex.observe_sequence(0, Some(1010), false, 62, 60), 0);
        assert_eq!(ex.observe_sequence(3, Some(1020), false, 63, 60), 2);
        assert_eq!(ex.observe_sequence(2, Some(1015), false, 64, 60), 0);
        assert_eq!(
            ex.last_sequence,
            Some(3),
            "reorder does not rewind watermark"
        );

        ex.bucket_entry_bounded(60).unwrap();
        assert_eq!(ex.observe_sequence(1, Some(5), false, 95, 60), 0);
        assert!(!ex.buckets.get(&60).unwrap().quality(100).iface_complete);
    }

    #[test]
    fn retry_collision_merges_counts_and_never_restores_completeness() {
        let mut current = Accum::default();
        current.fold(&rec(1));
        let mut retry = Accum::default();
        retry.fold(&rec(2));
        retry.base_complete = false;
        retry.mark_all_dropped(1);

        current.merge_from(retry);
        let totals = current.iface.get(&(1, Direction::Ingress)).unwrap();
        assert_eq!(totals.flows, 2);
        assert_eq!(totals.pkts, 2);
        assert!(!current.quality(100).iface_complete);
        assert_eq!(current.quality(100).iface_dropped, 1);
    }

    #[test]
    fn missing_counter_is_not_converted_to_measured_zero() {
        let mut acc = Accum::default();
        let mut missing = rec(1);
        missing.pkts = None;
        missing.bytes = Some(0); // an explicit, measured zero remains available.
        acc.fold(&missing);
        let counts = acc.iface.get(&(1, Direction::Ingress)).unwrap();
        assert!(!counts.pkts_available);
        assert!(counts.bytes_available);
        assert_eq!(counts.pkts, 0);
        assert_eq!(counts.bytes, 0);
    }

    #[test]
    fn open_bucket_backlog_is_bounded() {
        // Simulates a sustained DB outage: closed buckets keep getting re-queued
        // (via the same helper the flush path uses) while the receive loop opens
        // new ones. The per-exporter open-bucket map must stay capped, retain the
        // NEWEST buckets, and count every drop — never grow toward OOM.
        let mut ex = Exporter::new(None, 9, 0, 0);
        let extra = 50i64;
        for ts in 0..(MAX_OPEN_BUCKETS as i64 + extra) {
            assert!(ex.bucket_entry_bounded(ts).is_some());
        }
        assert_eq!(ex.buckets.len(), MAX_OPEN_BUCKETS);
        assert_eq!(ex.dropped_bucket_backlog, extra as u64);
        // The retained keys are the newest MAX_OPEN_BUCKETS timestamps.
        let min_kept = *ex.buckets.keys().min().unwrap();
        let max_kept = *ex.buckets.keys().max().unwrap();
        assert_eq!(max_kept, MAX_OPEN_BUCKETS as i64 + extra - 1);
        assert_eq!(min_kept, extra);

        // Inserting a timestamp older than the current minimum into a full map is
        // refused (returns None) and evicts nothing.
        let dropped_before = ex.dropped_bucket_backlog;
        let len_before = ex.buckets.len();
        assert!(ex.bucket_entry_bounded(min_kept - 1).is_none());
        assert_eq!(ex.buckets.len(), len_before);
        assert_eq!(ex.dropped_bucket_backlog, dropped_before + 1);
        assert!(ex.buckets.contains_key(&min_kept));
        assert!(Accum::default().quality(100).iface_complete);
    }

    #[test]
    fn netflow_v9_observation_domain_comes_from_source_id() {
        let mut datagram = [0u8; 20];
        datagram[0..2].copy_from_slice(&9u16.to_be_bytes());
        datagram[16..20].copy_from_slice(&0x1020_3040u32.to_be_bytes());
        assert_eq!(
            wire_observation_domain(Protocol::NetflowV9, &datagram),
            Some(0x1020_3040)
        );
        datagram[0..2].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(
            wire_observation_domain(Protocol::NetflowV9, &datagram),
            None
        );
    }

    #[test]
    fn sflow_observation_domain_comes_from_sub_agent_id() {
        let mut ipv4 = [0u8; 16];
        ipv4[0..4].copy_from_slice(&5u32.to_be_bytes());
        ipv4[4..8].copy_from_slice(&1u32.to_be_bytes());
        ipv4[12..16].copy_from_slice(&77u32.to_be_bytes());
        assert_eq!(wire_observation_domain(Protocol::Sflow, &ipv4), Some(77));

        let mut ipv6 = [0u8; 28];
        ipv6[0..4].copy_from_slice(&5u32.to_be_bytes());
        ipv6[4..8].copy_from_slice(&2u32.to_be_bytes());
        ipv6[24..28].copy_from_slice(&901u32.to_be_bytes());
        assert_eq!(wire_observation_domain(Protocol::Sflow, &ipv6), Some(901));
        assert_eq!(wire_observation_domain(Protocol::Sflow, &ipv6[..20]), None);
    }

    #[tokio::test]
    async fn flush_batch_coverage_blocks_partial_public_evidence() {
        let database = crate::db::connect_test_database().await;
        let pool = (*database).clone();
        let suffix = uuid::Uuid::new_v4();
        let device_id = sqlx::query("INSERT INTO devices (name,hostname,enabled) VALUES (?,?,0)")
            .bind(format!("quality-{suffix}"))
            .bind(format!("quality-{suffix}"))
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_id();
        sqlx::query("INSERT INTO device_interfaces (device_id,if_index) VALUES (?,1)")
            .bind(device_id)
            .execute(&pool)
            .await
            .unwrap();
        let bucket_ts = Utc.timestamp_opt(1_700_000_040, 0).single().unwrap();

        let make_acc = |src| {
            let mut acc = Accum::default();
            acc.fold(&rec(src));
            acc
        };
        let mut flushes = [
            ExporterFlush {
                src_ip: "192.0.2.1".parse().unwrap(),
                protocol: Protocol::NetflowV9,
                device_id: Some(device_id),
                version: 9,
                observation_domain: 1,
                template_count: 1,
                reported_rate: Some(1),
                snmp_derived_rate: None,
                datagrams_total: 1,
                dropped_no_template: 0,
                dropped_malformed: 0,
                dropped_bucket_backlog: 0,
                last_sequence: Some(1),
                last_seen: bucket_ts.timestamp(),
                closed: vec![(bucket_ts.timestamp(), make_acc(1))],
            },
            ExporterFlush {
                src_ip: "192.0.2.2".parse().unwrap(),
                protocol: Protocol::NetflowV9,
                device_id: Some(device_id),
                version: 9,
                observation_domain: 2,
                template_count: 1,
                reported_rate: Some(1),
                snmp_derived_rate: None,
                datagrams_total: 1,
                dropped_no_template: 0,
                dropped_malformed: 0,
                dropped_bucket_backlog: 0,
                last_sequence: Some(1),
                last_seen: bucket_ts.timestamp(),
                closed: vec![(bucket_ts.timestamp(), make_acc(2))],
            },
        ];
        let generation = prepare_flush_batch(&pool, &flushes).await.unwrap();
        let exporters: Vec<u64> = sqlx::query_scalar(
            "SELECT id FROM flow_exporters WHERE device_id=? ORDER BY observation_domain",
        )
        .bind(device_id)
        .fetch_all(&pool)
        .await
        .unwrap();
        let sampling = Sampling {
            rate: 1,
            source: SamplingSource::Reported,
            high_confidence: true,
        };
        let cfg = crate::config::Config::default();
        let mut cache = HashMap::new();
        write_bucket(
            &pool,
            &cfg,
            &BucketCtx {
                exporter_id: exporters[0],
                device_id,
                bucket_ts,
            },
            &flushes[0].closed[0].1,
            &sampling,
            &mut cache,
            &generation,
        )
        .await
        .unwrap();
        let partial = bucket_evidence(
            &pool,
            device_id,
            1,
            Direction::Ingress,
            bucket_ts,
            QualityDimension::Port,
        )
        .await
        .unwrap();
        assert_eq!(partial.availability, EvidenceAvailability::Unavailable);
        assert_eq!(
            (partial.expected_exporters, partial.observed_exporters),
            (2, 1)
        );

        write_bucket(
            &pool,
            &cfg,
            &BucketCtx {
                exporter_id: exporters[1],
                device_id,
                bucket_ts,
            },
            &flushes[1].closed[0].1,
            &sampling,
            &mut cache,
            &generation,
        )
        .await
        .unwrap();
        let complete = bucket_evidence(
            &pool,
            device_id,
            1,
            Direction::Ingress,
            bucket_ts,
            QualityDimension::Port,
        )
        .await
        .unwrap();
        assert_eq!(complete.availability, EvidenceAvailability::Available);
        assert!(complete.sampling_high_confidence && complete.pkts_available);

        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device_id)
            .execute(&pool)
            .await
            .unwrap();
        flushes.iter_mut().for_each(|f| f.closed.clear());
    }

    #[tokio::test]
    async fn committed_newer_bucket_survives_older_failure_and_remains_wakeable() {
        let database = crate::db::connect_test_database().await;
        let pool = (*database).clone();
        let suffix = uuid::Uuid::new_v4();
        let device_id = sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,?,0)")
            .bind(format!("wake-{suffix}"))
            .bind(format!("wake-{suffix}"))
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_id();
        let interface_id =
            sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES (?,1)")
                .bind(device_id)
                .execute(&pool)
                .await
                .unwrap()
                .last_insert_id();
        let make = |src| {
            let mut acc = Accum::default();
            acc.fold(&rec(src));
            acc
        };
        let older = 1_700_000_040i64;
        let newer = older + 60;
        let mut flush = ExporterFlush {
            src_ip: "192.0.2.91".parse().unwrap(),
            protocol: Protocol::NetflowV9,
            device_id: Some(device_id),
            version: 9,
            observation_domain: 91,
            template_count: 1,
            reported_rate: Some(1),
            snmp_derived_rate: None,
            datagrams_total: 2,
            dropped_no_template: 0,
            dropped_malformed: 0,
            dropped_bucket_backlog: 0,
            last_sequence: Some(2),
            last_seen: newer,
            closed: vec![(older, make(1)), (newer, make(2))],
        };
        let generation = prepare_flush_batch(&pool, std::slice::from_ref(&flush))
            .await
            .unwrap();
        let mut committed = std::collections::BTreeSet::new();
        let error = flush_exporter(
            &pool,
            &crate::config::Config::default(),
            &mut flush,
            &mut committed,
            Some(older),
            &generation,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("injected"));
        assert_eq!(
            committed,
            std::collections::BTreeSet::from([(device_id, 1)])
        );
        assert_eq!(flush.closed.len(), 1);
        assert_eq!(flush.closed[0].0, older);
        let stored:i64=sqlx::query_scalar("SELECT COUNT(*) FROM flow_iface_buckets WHERE device_id=? AND interface_id=? AND bucket_ts=FROM_UNIXTIME(?)").bind(device_id).bind(interface_id).bind(newer).fetch_one(&pool).await.unwrap();
        assert_eq!(stored,1,"committed newest bucket remains durable and its interface is returned for wake publication");
        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device_id)
            .execute(&pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn contributor_registration_is_chunked_and_partial_phase_publishes_no_quality() {
        let database = crate::db::connect_test_database().await;
        let pool = (*database).clone();
        let suffix = uuid::Uuid::new_v4();
        let device_id = sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,?,0)")
            .bind(format!("chunk-{suffix}"))
            .bind(format!("chunk-{suffix}"))
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_id();
        for index in 1..=(REGISTRATION_CHUNK as u32 + 1) {
            sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES (?,?)")
                .bind(device_id)
                .bind(index)
                .execute(&pool)
                .await
                .unwrap();
        }
        let mut acc = Accum::default();
        for index in 1..=(REGISTRATION_CHUNK as u32 + 1) {
            let mut flow = rec(index);
            flow.in_if_index = Some(index);
            acc.fold(&flow);
        }
        let bucket = 1_700_000_160i64;
        let flush = ExporterFlush {
            src_ip: "192.0.2.92".parse().unwrap(),
            protocol: Protocol::NetflowV9,
            device_id: Some(device_id),
            version: 9,
            observation_domain: 92,
            template_count: 1,
            reported_rate: Some(1),
            snmp_derived_rate: None,
            datagrams_total: 1,
            dropped_no_template: 0,
            dropped_malformed: 0,
            dropped_bucket_backlog: 0,
            last_sequence: Some(1),
            last_seen: bucket,
            closed: vec![(bucket, acc)],
        };
        assert!(
            prepare_flush_batch_inner(&pool, std::slice::from_ref(&flush), Some(1))
                .await
                .is_err()
        );
        let (stale_generation, ready): (String, bool) = sqlx::query_as(
            "SELECT generation,registry_ready FROM flow_publication_barrier WHERE id=1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(
            !ready,
            "failed registry preparation leaves publication closed"
        );
        let partial:i64=sqlx::query_scalar("SELECT COUNT(*) FROM flow_exporter_interfaces m JOIN flow_exporters e ON e.id=m.exporter_id WHERE e.observation_domain=92").fetch_one(&pool).await.unwrap();
        assert_eq!(partial, REGISTRATION_CHUNK as i64);
        let quality:i64=sqlx::query_scalar("SELECT COUNT(*) FROM flow_bucket_quality q JOIN flow_exporters e ON e.id=q.exporter_id WHERE e.observation_domain=92").fetch_one(&pool).await.unwrap();
        assert_eq!(quality, 0, "registration phase never publishes quality");
        let evidence = bucket_evidence(
            &pool,
            device_id,
            1,
            Direction::Ingress,
            Utc.timestamp_opt(bucket, 0).single().unwrap(),
            QualityDimension::Interface,
        )
        .await
        .unwrap();
        assert_eq!(evidence.availability, EvidenceAvailability::Unavailable);
        let (stats, _generation) =
            prepare_flush_batch_inner(&pool, std::slice::from_ref(&flush), None)
                .await
                .unwrap();
        assert_eq!((stats.rows, stats.chunks), (REGISTRATION_CHUNK + 1, 2));
        let complete:i64=sqlx::query_scalar("SELECT COUNT(*) FROM flow_exporter_interfaces m JOIN flow_exporters e ON e.id=m.exporter_id WHERE e.observation_domain=92").fetch_one(&pool).await.unwrap();
        assert_eq!(complete, (REGISTRATION_CHUNK + 1) as i64);
        let exporter_id: u64 =
            sqlx::query_scalar("SELECT id FROM flow_exporters WHERE observation_domain=92")
                .fetch_one(&pool)
                .await
                .unwrap();
        let mut cache = HashMap::new();
        let sampling = Sampling {
            rate: 1,
            source: SamplingSource::Reported,
            high_confidence: true,
        };
        let stale = write_bucket(
            &pool,
            &crate::config::Config::default(),
            &BucketCtx {
                exporter_id,
                device_id,
                bucket_ts: Utc.timestamp_opt(bucket, 0).single().unwrap(),
            },
            &flush.closed[0].1,
            &sampling,
            &mut cache,
            &stale_generation,
        )
        .await;
        assert!(
            stale.is_err(),
            "an old preparation generation cannot publish after a newer ready cohort"
        );
        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device_id)
            .execute(&pool)
            .await
            .unwrap();
    }
}
