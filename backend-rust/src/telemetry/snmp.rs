//! SNMP v2c interface poller — the v1 telemetry engine.
//!
//! Polls SNMP agents (Cisco ASRs and any standards-compliant agent) over v2c for
//! 64-bit ifXTable interface counters, derives per-interface rates, and persists
//! current + history. Three operations:
//!
//! * [`test`] — GET sysDescr/sysName/sysUpTime; parse vendor/model/OS;
//! * [`discover`] — walk ifXTable + ifTable; upsert `device_interfaces`
//!   (reconciled by ifIndex);
//! * [`poll`] — read counters for monitored interfaces, derive rates vs the
//!   previous `interface_metrics_current` baseline, store both.
//!
//! Pure-Rust async SNMP via the `csnmp` crate (GETBULK table walks, no openssl).
//! SNMP is read-only, which is exactly what observe mode wants. v3 is a typed
//! stub returning "unsupported in v1".
//!
//! Counter wrap/reset (docs/telemetry-model.md): if a counter goes backwards the
//! sample is marked invalid (`valid_sample = 0`) and emits no rate, but the new
//! raw counters are always stored as the next baseline. A failed poll marks the
//! device unreachable (telemetry stale) with `last_error`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use csnmp::{ObjectIdentifier, ObjectValue, Snmp2cClient};
use sqlx::MySqlPool;

use super::{interface_rates, InterfaceCounters};
use crate::crypto;

/// Per-request SNMP timeout and retry budget. Short so an unreachable device
/// fails fast and the scheduler moves on.
const SNMP_TIMEOUT: Duration = Duration::from_secs(4);
const SNMP_RETRIES: usize = 1;
/// GETBULK max-repetitions for table walks.
const BULK_REPETITIONS: u32 = 20;

// ---- OIDs (docs/telemetry-model.md) --------------------------------------------
// Scalars (GET the .0 instance).
const OID_SYS_DESCR: &str = "1.3.6.1.2.1.1.1.0";
const OID_SYS_UPTIME: &str = "1.3.6.1.2.1.1.3.0";
const OID_SYS_NAME: &str = "1.3.6.1.2.1.1.5.0";
// ifXTable (1.3.6.1.2.1.31.1.1.1.*) — 64-bit HC counters, ifName, ifAlias.
const OID_IF_NAME: &str = "1.3.6.1.2.1.31.1.1.1.1";
const OID_IF_HC_IN_OCTETS: &str = "1.3.6.1.2.1.31.1.1.1.6";
const OID_IF_HC_IN_UCAST: &str = "1.3.6.1.2.1.31.1.1.1.7";
const OID_IF_HC_OUT_OCTETS: &str = "1.3.6.1.2.1.31.1.1.1.10";
const OID_IF_HC_OUT_UCAST: &str = "1.3.6.1.2.1.31.1.1.1.11";
const OID_IF_HIGH_SPEED: &str = "1.3.6.1.2.1.31.1.1.1.15"; // Mbps
const OID_IF_ALIAS: &str = "1.3.6.1.2.1.31.1.1.1.18";
// ifTable (1.3.6.1.2.1.2.2.1.*) — descr/type/speed/status/errors/discards.
const OID_IF_DESCR: &str = "1.3.6.1.2.1.2.2.1.2";
const OID_IF_TYPE: &str = "1.3.6.1.2.1.2.2.1.3";
const OID_IF_SPEED: &str = "1.3.6.1.2.1.2.2.1.5"; // bps (32-bit, caps at ~4.29 Gbps)
const OID_IF_ADMIN_STATUS: &str = "1.3.6.1.2.1.2.2.1.7";
const OID_IF_OPER_STATUS: &str = "1.3.6.1.2.1.2.2.1.8";
const OID_IF_IN_DISCARDS: &str = "1.3.6.1.2.1.2.2.1.13";
const OID_IF_IN_ERRORS: &str = "1.3.6.1.2.1.2.2.1.14";
const OID_IF_OUT_DISCARDS: &str = "1.3.6.1.2.1.2.2.1.19";
const OID_IF_OUT_ERRORS: &str = "1.3.6.1.2.1.2.2.1.20";
// ENTITY-MIB entPhysicalName + CISCO-ENTITY-SENSOR-MIB (transceiver DOM optics).
// Sensors are named e.g. "subslot 0/0 transceiver 0 Rx Power Sensor" and indexed
// by entPhysicalIndex; actual reading = entSensorValue / 10^entSensorPrecision.
const OID_ENT_PHYS_NAME: &str = "1.3.6.1.2.1.47.1.1.1.1.7";
const OID_SENSOR_PRECISION: &str = "1.3.6.1.4.1.9.9.91.1.1.1.1.3";
const OID_SENSOR_VALUE: &str = "1.3.6.1.4.1.9.9.91.1.1.1.1.4";
const OID_SENSOR_STATUS: &str = "1.3.6.1.4.1.9.9.91.1.1.1.1.5"; // 1 = ok
                                                                // BGP4-MIB (1.3.6.1.2.1.15) — IPv4 BGP peer table, indexed by the peer's remote
                                                                // IP (4 OID arcs). Used to discover scrubber sessions operators can toggle.
const OID_BGP_LOCAL_AS: &str = "1.3.6.1.2.1.15.2.0"; // scalar
const OID_BGP_PEER_STATE: &str = "1.3.6.1.2.1.15.3.1.2"; // 1..6 FSM state
const OID_BGP_PEER_ADMIN_STATUS: &str = "1.3.6.1.2.1.15.3.1.3"; // 1=stop(shut) 2=start
const OID_BGP_PEER_REMOTE_AS: &str = "1.3.6.1.2.1.15.3.1.9";

fn oid(s: &str) -> Result<ObjectIdentifier> {
    s.parse::<ObjectIdentifier>()
        .map_err(|e| anyhow!("invalid OID {s}: {e}"))
}

// ---- Device row + connection ---------------------------------------------------

/// The subset of a `devices` row the poller needs. Decrypted community lives
/// only in memory and is never logged.
#[derive(Debug, Clone)]
pub struct DeviceConn {
    pub id: u64,
    pub name: String,
    pub hostname: String,
    pub snmp_version: String,
    pub snmp_port: u16,
    pub poll_interval_seconds: u32,
    pub community_encrypted: Option<Vec<u8>>,
}

/// Identity parsed from sysDescr plus the live scalars, returned by [`test`].
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceIdentity {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub sys_name: Option<String>,
    pub sys_descr: Option<String>,
    pub sys_uptime: Option<u64>,
}

/// Load the connection fields for one device by id.
pub async fn load_device(pool: &MySqlPool, device_id: u64) -> Result<DeviceConn> {
    let row = sqlx::query_as::<_, (u64, String, String, String, u16, u32, Option<Vec<u8>>)>(
        "SELECT id, name, hostname, snmp_version, snmp_port, poll_interval_seconds, community_encrypted \
         FROM devices WHERE id = ?",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("loading device")?
    .ok_or_else(|| anyhow!("device {device_id} not found"))?;
    Ok(DeviceConn {
        id: row.0,
        name: row.1,
        hostname: row.2,
        snmp_version: row.3,
        snmp_port: row.4,
        poll_interval_seconds: row.5,
        community_encrypted: row.6,
    })
}

/// Load every enabled device's connection fields (for the scheduler).
pub async fn load_enabled_devices(pool: &MySqlPool) -> Result<Vec<DeviceConn>> {
    let rows = sqlx::query_as::<_, (u64, String, String, String, u16, u32, Option<Vec<u8>>)>(
        "SELECT id, name, hostname, snmp_version, snmp_port, poll_interval_seconds, community_encrypted \
         FROM devices WHERE enabled = 1",
    )
    .fetch_all(pool)
    .await
    .context("loading enabled devices")?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceConn {
            id: r.0,
            name: r.1,
            hostname: r.2,
            snmp_version: r.3,
            snmp_port: r.4,
            poll_interval_seconds: r.5,
            community_encrypted: r.6,
        })
        .collect())
}

/// Build a v2c client for a device. Resolves the hostname (IP literal or DNS),
/// decrypts the community. v3 is explicitly unsupported in v1.
async fn connect(dev: &DeviceConn) -> Result<Snmp2cClient> {
    if dev.snmp_version != "v2c" {
        return Err(anyhow!(
            "SNMP {} is unsupported in v1 (v2c only)",
            dev.snmp_version
        ));
    }
    let community = match &dev.community_encrypted {
        Some(blob) => crypto::open(blob).context("decrypting SNMP community")?,
        None => return Err(anyhow!("device has no SNMP community configured")),
    };
    let addr = resolve(&dev.hostname, dev.snmp_port).await?;
    let client = Snmp2cClient::new(addr, community, None, Some(SNMP_TIMEOUT), SNMP_RETRIES)
        .await
        .with_context(|| format!("opening SNMP socket to {addr}"))?;
    Ok(client)
}

/// Resolve `host:port` to a single SocketAddr. Accepts an IP literal directly or
/// a DNS name (first A/AAAA result). Runs the blocking resolver off the runtime.
async fn resolve(host: &str, port: u16) -> Result<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    let host = host.to_string();
    let host_for_err = host.clone();
    let addrs = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|it| it.collect::<Vec<_>>())
    })
    .await
    .context("DNS resolver task")?
    .with_context(|| format!("resolving SNMP target '{host_for_err}'"))?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("no addresses for SNMP target '{host_for_err}'"))
}

// ---- test() --------------------------------------------------------------------

/// Reachability + identity probe: GET sysDescr / sysName / sysUpTime and parse
/// vendor/model/OS from sysDescr. Returns a structured error on failure (no panic);
/// callers surface it as the device `last_error`.
pub async fn test(dev: &DeviceConn) -> Result<DeviceIdentity> {
    let client = connect(dev).await?;

    let descr = get_string(&client, OID_SYS_DESCR).await.ok();
    let sys_name = get_string(&client, OID_SYS_NAME)
        .await
        .ok()
        .filter(|s| !s.is_empty());
    let sys_uptime = client
        .get(oid(OID_SYS_UPTIME)?)
        .await
        .ok()
        .and_then(|v| value_to_u64(&v));

    // At least sysDescr must answer, or this isn't a usable SNMP agent.
    if descr.is_none() && sys_name.is_none() && sys_uptime.is_none() {
        return Err(anyhow!(
            "device did not answer SNMP (check community, version, reachability)"
        ));
    }

    let (vendor, model, os_version) = descr
        .as_deref()
        .map(parse_sys_descr)
        .unwrap_or((None, None, None));

    Ok(DeviceIdentity {
        vendor,
        model,
        os_version,
        sys_name,
        sys_descr: descr,
        sys_uptime,
    })
}

/// `test` + persist the identity/reachability back onto the device row. Returns
/// the identity. On failure, records the error and marks the device unreachable.
pub async fn test_and_store(pool: &MySqlPool, device_id: u64) -> Result<DeviceIdentity> {
    let dev = load_device(pool, device_id).await?;
    match test(&dev).await {
        Ok(id) => {
            sqlx::query(
                "UPDATE devices SET reachable = 1, last_poll_at = UTC_TIMESTAMP(), last_error = NULL, \
                 vendor = COALESCE(?, vendor), model = COALESCE(?, model), \
                 os_version = COALESCE(?, os_version), sys_name = COALESCE(?, sys_name), \
                 sys_uptime = ? WHERE id = ?",
            )
            .bind(&id.vendor)
            .bind(&id.model)
            .bind(&id.os_version)
            .bind(&id.sys_name)
            .bind(id.sys_uptime)
            .bind(device_id)
            .execute(pool)
            .await
            .context("storing device identity")?;
            Ok(id)
        }
        Err(e) => {
            mark_unreachable(pool, device_id, &e.to_string()).await;
            Err(e)
        }
    }
}

/// Debug helper: SNMP-walk an OID prefix on a device (using its stored,
/// decrypted credentials) and print `oid = value` lines. For exploring an
/// agent's MIBs — e.g. CISCO-ENTITY-SENSOR-MIB optics sensors. `--snmp-walk`.
pub async fn debug_walk(pool: &MySqlPool, device_id: u64, oid_prefix: &str) -> Result<()> {
    let dev = load_device(pool, device_id).await?;
    let client = connect(&dev).await?;
    let base = oid(oid_prefix)?;
    let raw = client
        .walk_bulk(base, BULK_REPETITIONS)
        .await
        .with_context(|| format!("walk {oid_prefix}"))?;
    println!("# {} entries under {oid_prefix}", raw.len());
    for (o, v) in raw {
        println!("{o} = {}", value_to_string(&v));
    }
    Ok(())
}

// ---- discover() ----------------------------------------------------------------

/// One discovered interface (pre-upsert).
#[derive(Debug, Clone, Default)]
pub struct DiscoveredInterface {
    pub if_index: u32,
    pub if_name: Option<String>,
    pub if_descr: Option<String>,
    pub if_alias: Option<String>,
    pub if_speed_bps: u64,
    pub admin_status: Option<String>,
    pub oper_status: Option<String>,
    pub is_physical: bool,
}

/// Walk ifXTable + ifTable and return one entry per ifIndex. if_speed_bps prefers
/// ifHighSpeed (Mbps × 1_000_000), falling back to the 32-bit ifSpeed.
pub async fn discover(dev: &DeviceConn) -> Result<Vec<DiscoveredInterface>> {
    let client = connect(dev).await?;

    let if_names_result = walk_strings(&client, OID_IF_NAME).await;
    let if_aliases = walk_strings(&client, OID_IF_ALIAS)
        .await
        .unwrap_or_default();
    let if_descrs_result = walk_strings(&client, OID_IF_DESCR).await;
    if if_names_result.is_err() && if_descrs_result.is_err() {
        return Err(anyhow!(
            "both ifName and ifDescr walks failed; the interface inventory is unavailable"
        ));
    }
    let if_names = if_names_result.unwrap_or_default();
    let if_descrs = if_descrs_result.unwrap_or_default();
    let if_high_speed = walk_u64(&client, OID_IF_HIGH_SPEED)
        .await
        .unwrap_or_default();
    let if_speed = walk_u64(&client, OID_IF_SPEED).await.unwrap_or_default();
    let if_type = walk_u64(&client, OID_IF_TYPE).await.unwrap_or_default();
    let if_admin = walk_u64(&client, OID_IF_ADMIN_STATUS)
        .await
        .unwrap_or_default();
    let if_oper = walk_u64(&client, OID_IF_OPER_STATUS)
        .await
        .unwrap_or_default();

    // The set of ifIndexes from any table that returned rows. ifDescr (ifTable)
    // is the most universally present, so union it with ifName (ifXTable).
    let mut indexes: std::collections::BTreeSet<u32> = std::collections::BTreeSet::new();
    indexes.extend(if_names.keys().copied());
    indexes.extend(if_descrs.keys().copied());
    if indexes.is_empty() {
        return Err(anyhow!(
            "no interfaces found (ifXTable/ifTable empty or blocked by the agent's MIB view)"
        ));
    }

    let mut out = Vec::with_capacity(indexes.len());
    for idx in indexes {
        let speed_bps = match if_high_speed.get(&idx) {
            Some(&mbps) if mbps > 0 => mbps.saturating_mul(1_000_000),
            _ => if_speed.get(&idx).copied().unwrap_or(0),
        };
        out.push(DiscoveredInterface {
            if_index: idx,
            if_name: if_names.get(&idx).cloned(),
            if_descr: if_descrs.get(&idx).cloned(),
            if_alias: if_aliases.get(&idx).cloned().filter(|s| !s.is_empty()),
            if_speed_bps: speed_bps,
            admin_status: if_admin.get(&idx).map(|&v| admin_status_str(v).to_string()),
            oper_status: if_oper.get(&idx).map(|&v| oper_status_str(v).to_string()),
            is_physical: if_type
                .get(&idx)
                .map(|&t| is_physical_type(t))
                .unwrap_or(false),
        });
    }
    Ok(out)
}

/// `discover` + reconcile into `device_interfaces` by (device_id, if_index):
/// insert new, refresh existing.
/// Returns the number of interfaces seen.
pub async fn discover_and_store(pool: &MySqlPool, device_id: u64) -> Result<usize> {
    let dev = load_device(pool, device_id).await?;
    let ifaces = match discover(&dev).await {
        Ok(v) => v,
        Err(e) => {
            mark_unreachable(pool, device_id, &e.to_string()).await;
            return Err(e);
        }
    };

    let mut tx = pool.begin().await?;
    for (order, ifc) in ifaces.iter().enumerate() {
        sqlx::query(
            "INSERT INTO device_interfaces \
                (device_id, if_index, if_name, if_descr, if_alias, if_speed_bps, \
                 admin_status, oper_status, is_physical, display_order, first_seen_at, last_seen_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
             ON DUPLICATE KEY UPDATE \
                if_name = VALUES(if_name), if_descr = VALUES(if_descr), if_alias = VALUES(if_alias), \
                if_speed_bps = VALUES(if_speed_bps), admin_status = VALUES(admin_status), \
                oper_status = VALUES(oper_status), is_physical = VALUES(is_physical), \
                last_seen_at = UTC_TIMESTAMP()",
        )
        .bind(device_id)
        .bind(ifc.if_index)
        .bind(&ifc.if_name)
        .bind(&ifc.if_descr)
        .bind(&ifc.if_alias)
        .bind(ifc.if_speed_bps)
        .bind(&ifc.admin_status)
        .bind(&ifc.oper_status)
        .bind(ifc.is_physical as i32)
        .bind(order as i32)
        .execute(&mut *tx)
        .await
        .context("upserting interface")?;
    }

    // Discovery proves reachability.
    sqlx::query("UPDATE devices SET reachable = 1, last_error = NULL, last_poll_at = UTC_TIMESTAMP() WHERE id = ?")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(ifaces.len())
}

// ---- BGP peer discovery --------------------------------------------------------

/// Discover BGP peers via BGP4-MIB `bgpPeerTable` and reconcile
/// `device_bgp_peers` by (device_id, peer_remote_addr). Returns the peer count.
/// IPv4 peers only (classic BGP4-MIB); a device that doesn't run BGP returns 0.
pub async fn discover_bgp_and_store(pool: &MySqlPool, device_id: u64) -> Result<usize> {
    let dev = load_device(pool, device_id).await?;
    let client = connect(&dev).await?;

    let local_as = client
        .get(oid(OID_BGP_LOCAL_AS)?)
        .await
        .ok()
        .and_then(|v| value_to_u64(&v))
        .filter(|&n| n > 0);

    // State is the authoritative peer set. If that walk fails, preserve the
    // prior snapshot as stale and report an error instead of treating it as an
    // empty, successful discovery.
    let states = walk_ip_u64(&client, OID_BGP_PEER_STATE).await?;
    let admins = walk_ip_u64(&client, OID_BGP_PEER_ADMIN_STATUS)
        .await
        .unwrap_or_default();
    let remote_as = walk_ip_u64(&client, OID_BGP_PEER_REMOTE_AS)
        .await
        .unwrap_or_default();

    // State is the authoritative peer set. Auxiliary columns may be incomplete,
    // but they must never resurrect an address absent from the state snapshot.
    let peers: std::collections::BTreeSet<String> = states.keys().cloned().collect();

    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE device_bgp_peers SET last_polled_at = NULL WHERE device_id = ?")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    for ip in &peers {
        let state = states.get(ip).map(|&s| bgp_state_str(s));
        let admin = admins.get(ip).map(|&a| bgp_admin_str(a));
        let ras = remote_as.get(ip).copied().filter(|&n| n > 0);
        sqlx::query(
            "INSERT INTO device_bgp_peers \
                (device_id, peer_remote_addr, peer_remote_as, local_as, peer_state, peer_admin_status, \
                 first_seen_at, last_seen_at, last_polled_at) \
             VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
             ON DUPLICATE KEY UPDATE \
                peer_remote_as = VALUES(peer_remote_as), local_as = VALUES(local_as), \
                peer_state = VALUES(peer_state), peer_admin_status = VALUES(peer_admin_status), \
                last_seen_at = UTC_TIMESTAMP(), last_polled_at = UTC_TIMESTAMP()",
        )
        .bind(device_id)
        .bind(ip)
        .bind(ras)
        .bind(local_as)
        .bind(state)
        .bind(admin)
        .execute(&mut *tx)
        .await
        .context("upserting BGP peer")?;
    }
    tx.commit().await?;

    Ok(peers.len())
}

/// Walk a BGP4-MIB column indexed by the peer remote IP (4 OID arcs) -> u64.
async fn walk_ip_u64(client: &Snmp2cClient, base: &str) -> Result<BTreeMap<String, u64>> {
    let base_oid = oid(base)?;
    let raw = client
        .walk_bulk(base_oid, BULK_REPETITIONS)
        .await
        .with_context(|| format!("walk {base}"))?;
    Ok(index_by_ip(&base_oid, raw, |v| value_to_u64(&v)))
}

/// Reduce a walk result keyed by a trailing 4-arc IPv4 suffix -> T.
fn index_by_ip<T>(
    base: &ObjectIdentifier,
    raw: BTreeMap<ObjectIdentifier, ObjectValue>,
    map: impl Fn(ObjectValue) -> Option<T>,
) -> BTreeMap<String, T> {
    let mut out = BTreeMap::new();
    for (entry_oid, value) in raw {
        let Some(rel) = entry_oid.relative_to(base) else {
            continue;
        };
        let arcs = rel.as_slice();
        if arcs.len() < 4 {
            continue;
        }
        let ip = arcs[arcs.len() - 4..]
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(".");
        if let Some(v) = map(value) {
            out.insert(ip, v);
        }
    }
    out
}

/// BGP4-MIB bgpPeerState (1..6) -> label.
fn bgp_state_str(v: u64) -> &'static str {
    match v {
        1 => "idle",
        2 => "connect",
        3 => "active",
        4 => "opensent",
        5 => "openconfirm",
        6 => "established",
        _ => "unknown",
    }
}

/// BGP4-MIB bgpPeerAdminStatus (1=stop/shut, 2=start) -> label.
fn bgp_admin_str(v: u64) -> &'static str {
    match v {
        1 => "stop",
        2 => "start",
        _ => "unknown",
    }
}

// ---- poll() --------------------------------------------------------------------

/// An interface to poll (id + ifIndex + speed for util%, name/descr for optics
/// mapping).
#[derive(Debug, Clone)]
struct PollInterface {
    interface_id: u64,
    if_index: u32,
    if_speed_bps: u64,
    if_name: Option<String>,
    if_descr: Option<String>,
}

/// Poll EVERY discovered interface on a device (physical, port-channels,
/// tunnels, …) — not just rule-targeted ones — so the device page has telemetry
/// for all of them: read HC counters + errors, derive rates against the previous
/// baseline, upsert `interface_metrics_current` and append `interface_samples`.
/// Returns the number of interfaces updated.
///
/// On a transport-level failure the device is marked unreachable (telemetry
/// stale) with `last_error`; a wrap/reset on a single interface only invalidates
/// that interface's sample.
pub async fn poll(pool: &MySqlPool, device_id: u64) -> Result<usize> {
    let dev = load_device(pool, device_id).await?;

    let ifaces: Vec<PollInterface> = sqlx::query_as::<_, (u64, u32, u64, Option<String>, Option<String>)>(
        "SELECT id, if_index, if_speed_bps, if_name, if_descr FROM device_interfaces WHERE device_id = ?",
    )
    .bind(device_id)
    .fetch_all(pool)
    .await
    .context("loading device interfaces")?
    .into_iter()
    .map(|(interface_id, if_index, if_speed_bps, if_name, if_descr)| PollInterface {
        interface_id,
        if_index,
        if_speed_bps,
        if_name,
        if_descr,
    })
    .collect();

    if ifaces.is_empty() {
        // No interfaces yet (e.g. just enrolled) -> auto-discover now; the next
        // poll tick will have interfaces to read.
        return discover_and_store(pool, device_id).await;
    }

    let client = match connect(&dev).await {
        Ok(c) => c,
        Err(e) => {
            mark_unreachable(pool, device_id, &e.to_string()).await;
            return Err(e);
        }
    };

    // Walk the counter columns once each (GETBULK), then index by ifIndex.
    let in_oct = walk_u64(&client, OID_IF_HC_IN_OCTETS)
        .await
        .unwrap_or_default();
    let out_oct = walk_u64(&client, OID_IF_HC_OUT_OCTETS)
        .await
        .unwrap_or_default();
    let in_pkt = walk_u64(&client, OID_IF_HC_IN_UCAST)
        .await
        .unwrap_or_default();
    let out_pkt = walk_u64(&client, OID_IF_HC_OUT_UCAST)
        .await
        .unwrap_or_default();
    let in_err = walk_u64(&client, OID_IF_IN_ERRORS)
        .await
        .unwrap_or_default();
    let out_err = walk_u64(&client, OID_IF_OUT_ERRORS)
        .await
        .unwrap_or_default();
    let in_disc = walk_u64(&client, OID_IF_IN_DISCARDS)
        .await
        .unwrap_or_default();
    let out_disc = walk_u64(&client, OID_IF_OUT_DISCARDS)
        .await
        .unwrap_or_default();
    let oper = walk_u64(&client, OID_IF_OPER_STATUS)
        .await
        .unwrap_or_default();
    let admin = walk_u64(&client, OID_IF_ADMIN_STATUS)
        .await
        .unwrap_or_default();

    // Rate math needs BOTH octet directions. If EITHER walk came back empty
    // (asymmetric GETBULK timeout, or an agent missing ifXTable), fail LOUD and
    // mark the device unreachable — never report a device healthy with zero
    // interfaces refreshed (a silent false "all clear").
    if in_oct.is_empty() || out_oct.is_empty() {
        let msg =
            "poll returned incomplete HC octet counters (agent may not support ifXTable / 64-bit counters, or a GETBULK walk timed out)";
        tracing::warn!(
            event_type = "snmp_poll_incomplete",
            device_id,
            in_octets = in_oct.len(),
            out_octets = out_oct.len(),
            "{msg}"
        );
        mark_unreachable(pool, device_id, msg).await;
        return Err(anyhow!(msg));
    }

    // Transceiver optics (best-effort; empty for agents/ports without DOM).
    let optics = collect_optics(&client, &ifaces).await;

    let now = Utc::now();
    let mut updated = 0usize;

    for m in &ifaces {
        // Missing a counter for this interface -> skip it (leave its row as-is).
        let (Some(&io), Some(&oo), Some(&ip), Some(&op)) = (
            in_oct.get(&m.if_index),
            out_oct.get(&m.if_index),
            in_pkt.get(&m.if_index),
            out_pkt.get(&m.if_index),
        ) else {
            continue;
        };

        let current = InterfaceCounters {
            sampled_at: now,
            in_octets: io,
            out_octets: oo,
            in_ucast_pkts: ip,
            out_ucast_pkts: op,
        };
        let (previous, prev_in_err, prev_out_err, prev_in_disc, prev_out_disc) =
            load_baseline(pool, m.interface_id).await?;
        let rates = interface_rates(&current, previous.as_ref(), m.if_speed_bps);

        let oper_s = oper
            .get(&m.if_index)
            .map(|&v| oper_status_str(v).to_string());
        let admin_s = admin
            .get(&m.if_index)
            .map(|&v| admin_status_str(v).to_string());

        let cur_in_err = in_err.get(&m.if_index).copied();
        let cur_out_err = out_err.get(&m.if_index).copied();
        let cur_in_disc = in_disc.get(&m.if_index).copied();
        let cur_out_disc = out_disc.get(&m.if_index).copied();
        let opt = optics.get(&m.interface_id);

        // Error rates (errors/sec) from the cumulative counters over the same
        // interval as the bps/pps rates. No baseline / wrap => 0 (rate_from_counters
        // returns None). Only meaningful when valid_sample = 1 (detection gates on it).
        let err_elapsed = previous
            .as_ref()
            .map(|p| (current.sampled_at - p.sampled_at).num_milliseconds() as f64 / 1000.0)
            .unwrap_or(0.0);
        let in_err_rate = super::rate_from_counters(
            cur_in_err.unwrap_or(0),
            prev_in_err.unwrap_or(0),
            err_elapsed,
        )
        .unwrap_or(0.0);
        let out_err_rate = super::rate_from_counters(
            cur_out_err.unwrap_or(0),
            prev_out_err.unwrap_or(0),
            err_elapsed,
        )
        .unwrap_or(0.0);

        store_metrics(
            pool,
            device_id,
            m.interface_id,
            &current,
            &rates,
            cur_in_err,
            cur_out_err,
            cur_in_disc,
            cur_out_disc,
            in_err_rate,
            out_err_rate,
            admin_s.as_deref(),
            oper_s.as_deref(),
            // per-interval error/discard deltas for the history charts
            err_delta(cur_in_err, prev_in_err),
            err_delta(cur_out_err, prev_out_err),
            err_delta(cur_in_disc, prev_in_disc),
            err_delta(cur_out_disc, prev_out_disc),
            opt.and_then(|o| o.temp_c),
            opt.and_then(|o| o.tx_power_dbm),
            opt.and_then(|o| o.rx_power_dbm),
        )
        .await?;
        updated += 1;
    }

    if updated == 0 {
        let msg = "poll returned no interface with a complete octet and packet counter set";
        mark_unreachable(pool, device_id, msg).await;
        return Err(anyhow!(msg));
    }

    sqlx::query("UPDATE devices SET reachable = 1, last_error = NULL, last_poll_at = UTC_TIMESTAMP() WHERE id = ?")
        .bind(device_id)
        .execute(pool)
        .await?;

    Ok(updated)
}

/// Load the previous raw octet/packet counters (rate baseline) plus the previous
/// cumulative error and discard counters (for per-interval deltas) from
/// `interface_metrics_current`. Returns
/// `(counters, in_errors, out_errors, in_discards, out_discards)`.
#[allow(clippy::type_complexity)]
async fn load_baseline(
    pool: &MySqlPool,
    interface_id: u64,
) -> Result<(
    Option<InterfaceCounters>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
)> {
    // sampled_at is a TIMESTAMP column -> DateTime<Utc> (sqlx-mysql maps
    // NaiveDateTime only to DATETIME).
    type Row = (
        Option<chrono::DateTime<chrono::Utc>>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        Option<u64>,
    );
    let row = sqlx::query_as::<_, Row>(
        "SELECT sampled_at, in_octets, out_octets, in_ucast_pkts, out_ucast_pkts, \
                in_errors, out_errors, in_discards, out_discards \
         FROM interface_metrics_current WHERE interface_id = ?",
    )
    .bind(interface_id)
    .fetch_optional(pool)
    .await
    .context("loading interface baseline")?;

    let Some((ts, io, oo, ip, op, in_e, out_e, in_d, out_d)) = row else {
        return Ok((None, None, None, None, None));
    };
    let counters = match (ts, io, oo, ip, op) {
        (Some(ts), Some(io), Some(oo), Some(ip), Some(op)) => Some(InterfaceCounters {
            sampled_at: ts,
            in_octets: io,
            out_octets: oo,
            in_ucast_pkts: ip,
            out_ucast_pkts: op,
        }),
        _ => None,
    };
    Ok((counters, in_e, out_e, in_d, out_d))
}

/// Per-interval error count: current minus the previous cumulative counter.
/// Returns 0 when there is no baseline yet or the counter wrapped (current < previous).
fn err_delta(current: Option<u64>, previous: Option<u64>) -> u64 {
    match (current, previous) {
        (Some(c), Some(p)) if c >= p => c - p,
        _ => 0,
    }
}

/// Upsert `interface_metrics_current` with the new raw counters (next baseline)
/// and derived rates, then append a history row to `interface_samples`.
#[allow(clippy::too_many_arguments)]
async fn store_metrics(
    pool: &MySqlPool,
    device_id: u64,
    interface_id: u64,
    counters: &InterfaceCounters,
    rates: &super::InterfaceRates,
    in_errors: Option<u64>,
    out_errors: Option<u64>,
    in_discards: Option<u64>,
    out_discards: Option<u64>,
    in_err_rate: f64,
    out_err_rate: f64,
    admin_status: Option<&str>,
    oper_status: Option<&str>,
    sample_in_errors: u64,
    sample_out_errors: u64,
    sample_in_discards: u64,
    sample_out_discards: u64,
    temp_c: Option<f64>,
    tx_power_dbm: Option<f64>,
    rx_power_dbm: Option<f64>,
) -> Result<()> {
    let sampled_at = counters.sampled_at.naive_utc();
    let valid = rates.valid as i32;

    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO interface_metrics_current \
            (interface_id, device_id, sampled_at, valid_sample, \
             in_octets, out_octets, in_ucast_pkts, out_ucast_pkts, \
             rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent, \
             in_errors, out_errors, in_discards, out_discards, in_err_rate, out_err_rate, \
             admin_status, oper_status, \
             temp_c, tx_power_dbm, rx_power_dbm) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         ON DUPLICATE KEY UPDATE \
            sampled_at = VALUES(sampled_at), valid_sample = VALUES(valid_sample), \
            in_octets = VALUES(in_octets), out_octets = VALUES(out_octets), \
            in_ucast_pkts = VALUES(in_ucast_pkts), out_ucast_pkts = VALUES(out_ucast_pkts), \
            rx_bps = VALUES(rx_bps), tx_bps = VALUES(tx_bps), rx_pps = VALUES(rx_pps), \
            tx_pps = VALUES(tx_pps), rx_util_percent = VALUES(rx_util_percent), \
            tx_util_percent = VALUES(tx_util_percent), in_errors = VALUES(in_errors), \
            out_errors = VALUES(out_errors), in_discards = VALUES(in_discards), \
            out_discards = VALUES(out_discards), in_err_rate = VALUES(in_err_rate), \
            out_err_rate = VALUES(out_err_rate), admin_status = VALUES(admin_status), \
            oper_status = VALUES(oper_status), temp_c = VALUES(temp_c), \
            tx_power_dbm = VALUES(tx_power_dbm), rx_power_dbm = VALUES(rx_power_dbm)",
    )
    .bind(interface_id)
    .bind(device_id)
    .bind(sampled_at)
    .bind(valid)
    .bind(counters.in_octets)
    .bind(counters.out_octets)
    .bind(counters.in_ucast_pkts)
    .bind(counters.out_ucast_pkts)
    .bind(rates.rx_bps)
    .bind(rates.tx_bps)
    .bind(rates.rx_pps)
    .bind(rates.tx_pps)
    .bind(rates.rx_util_percent)
    .bind(rates.tx_util_percent)
    .bind(in_errors)
    .bind(out_errors)
    .bind(in_discards)
    .bind(out_discards)
    .bind(in_err_rate)
    .bind(out_err_rate)
    .bind(admin_status)
    .bind(oper_status)
    .bind(temp_c)
    .bind(tx_power_dbm)
    .bind(rx_power_dbm)
    .execute(&mut *tx)
    .await
    .context("upserting interface_metrics_current")?;

    // History: append only valid samples? No — keep invalid markers too so the
    // gap is visible, but detection filters on valid_sample.
    sqlx::query(
        "INSERT INTO interface_samples \
            (interface_id, device_id, sampled_at, valid_sample, \
             rx_bps, tx_bps, rx_pps, tx_pps, rx_util_percent, tx_util_percent, \
             in_errors, out_errors, in_discards, out_discards, \
             temp_c, tx_power_dbm, rx_power_dbm) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(interface_id)
    .bind(device_id)
    .bind(sampled_at)
    .bind(valid)
    .bind(rates.rx_bps)
    .bind(rates.tx_bps)
    .bind(rates.rx_pps)
    .bind(rates.tx_pps)
    .bind(rates.rx_util_percent)
    .bind(rates.tx_util_percent)
    .bind(sample_in_errors)
    .bind(sample_out_errors)
    .bind(sample_in_discards)
    .bind(sample_out_discards)
    .bind(temp_c)
    .bind(tx_power_dbm)
    .bind(rx_power_dbm)
    .execute(&mut *tx)
    .await
    .context("appending interface_samples")?;

    sqlx::query(
        "UPDATE device_interfaces SET last_seen_at = UTC_TIMESTAMP(), \
         admin_status = COALESCE(?, admin_status), oper_status = COALESCE(?, oper_status) \
         WHERE id = ? AND device_id = ?",
    )
    .bind(admin_status)
    .bind(oper_status)
    .bind(interface_id)
    .bind(device_id)
    .execute(&mut *tx)
    .await
    .context("refreshing interface inventory timestamp")?;
    tx.commit().await?;

    Ok(())
}

/// Mark a device unreachable (telemetry stale) with a short error. Best-effort;
/// never propagates a secondary DB error over the original poll failure.
async fn mark_unreachable(pool: &MySqlPool, device_id: u64, error: &str) {
    let truncated: String = error.chars().take(1000).collect();
    if let Err(e) = sqlx::query(
        "UPDATE devices SET reachable = 0, last_error = ?, last_poll_at = UTC_TIMESTAMP() WHERE id = ?",
    )
    .bind(truncated)
    .bind(device_id)
    .execute(pool)
    .await
    {
        tracing::error!(event_type = "snmp_unreachable_write_failed", device_id, error = %e, "could not persist the device-unreachable status");
    }
    tracing::warn!(event_type = "snmp_poll_failed", device_id, error = %error, "SNMP poll failed; device marked unreachable");
}

// ---- SNMP value helpers --------------------------------------------------------

/// GET one OID as a UTF-8 string (lossy for non-UTF-8 octet strings).
async fn get_string(client: &Snmp2cClient, oid_str: &str) -> Result<String> {
    let v = client
        .get(oid(oid_str)?)
        .await
        .with_context(|| format!("GET {oid_str}"))?;
    Ok(value_to_string(&v))
}

/// Walk a table column and return ifIndex -> string. The ifIndex is the final
/// sub-identifier of each returned OID relative to the column base.
async fn walk_strings(client: &Snmp2cClient, base: &str) -> Result<BTreeMap<u32, String>> {
    let base_oid = oid(base)?;
    let raw = client
        .walk_bulk(base_oid, BULK_REPETITIONS)
        .await
        .with_context(|| format!("walk {base}"))?;
    Ok(index_by_suffix(&base_oid, raw, |v| {
        Some(value_to_string(&v))
    }))
}

/// Walk a table column and return ifIndex -> u64 (counters, speeds, statuses).
async fn walk_u64(client: &Snmp2cClient, base: &str) -> Result<BTreeMap<u32, u64>> {
    let base_oid = oid(base)?;
    let raw = client
        .walk_bulk(base_oid, BULK_REPETITIONS)
        .await
        .with_context(|| format!("walk {base}"))?;
    Ok(index_by_suffix(&base_oid, raw, |v| value_to_u64(&v)))
}

/// Walk a table column and return index -> i64 (signed — e.g. entSensorValue,
/// where optical power is negative dBm).
async fn walk_i64(client: &Snmp2cClient, base: &str) -> Result<BTreeMap<u32, i64>> {
    let base_oid = oid(base)?;
    let raw = client
        .walk_bulk(base_oid, BULK_REPETITIONS)
        .await
        .with_context(|| format!("walk {base}"))?;
    Ok(index_by_suffix(&base_oid, raw, |v| value_to_i64(&v)))
}

/// Reduce a walk result to ifIndex -> T. The ifIndex is the single sub-identifier
/// remaining after stripping the column base (ifXTable/ifTable are 1-deep).
fn index_by_suffix<T>(
    base: &ObjectIdentifier,
    raw: BTreeMap<ObjectIdentifier, ObjectValue>,
    map: impl Fn(ObjectValue) -> Option<T>,
) -> BTreeMap<u32, T> {
    let mut out = BTreeMap::new();
    for (oid, value) in raw {
        let Some(rel) = oid.relative_to(base) else {
            continue;
        };
        // ifIndex is the last arc; ifXTable/ifTable have exactly one index arc.
        let Some(idx) = rel.as_slice().last().copied() else {
            continue;
        };
        if let Some(v) = map(value) {
            out.insert(idx, v);
        }
    }
    out
}

/// Coerce any SNMP value to a string (octet strings decode UTF-8 lossily).
fn value_to_string(v: &ObjectValue) -> String {
    match v {
        ObjectValue::String(bytes) | ObjectValue::Opaque(bytes) => String::from_utf8_lossy(bytes)
            .trim_end_matches('\0')
            .to_string(),
        ObjectValue::Integer(i) => i.to_string(),
        ObjectValue::Counter32(n) | ObjectValue::Unsigned32(n) | ObjectValue::TimeTicks(n) => {
            n.to_string()
        }
        ObjectValue::Counter64(n) => n.to_string(),
        ObjectValue::IpAddress(ip) => ip.to_string(),
        ObjectValue::ObjectId(o) => o.to_string(),
    }
}

/// Coerce a numeric SNMP value to u64. None for non-numeric types.
fn value_to_u64(v: &ObjectValue) -> Option<u64> {
    match v {
        ObjectValue::Counter64(n) => Some(*n),
        ObjectValue::Counter32(n) | ObjectValue::Unsigned32(n) | ObjectValue::TimeTicks(n) => {
            Some(*n as u64)
        }
        ObjectValue::Integer(i) if *i >= 0 => Some(*i as u64),
        _ => None,
    }
}

/// Coerce a numeric SNMP value to i64 (preserves sign for entSensorValue dBm).
fn value_to_i64(v: &ObjectValue) -> Option<i64> {
    match v {
        ObjectValue::Integer(i) => Some(*i as i64),
        ObjectValue::Counter32(n) | ObjectValue::Unsigned32(n) | ObjectValue::TimeTicks(n) => {
            Some(*n as i64)
        }
        ObjectValue::Counter64(n) => Some(*n as i64),
        _ => None,
    }
}

// ---- optics (CISCO-ENTITY-SENSOR-MIB) ------------------------------------------

/// Per-interface transceiver optics. Any field may be absent.
#[derive(Debug, Clone, Default)]
struct Optics {
    temp_c: Option<f64>,
    tx_power_dbm: Option<f64>,
    rx_power_dbm: Option<f64>,
}

/// Parse "subslot A/B transceiver N <kind> Sensor" -> port path "A/B/N".
fn transceiver_port(name: &str) -> Option<String> {
    let toks: Vec<&str> = name.split_whitespace().collect();
    let subslot = toks
        .iter()
        .position(|&t| t == "subslot")
        .and_then(|i| toks.get(i + 1))?;
    let n = toks
        .iter()
        .position(|&t| t == "transceiver")
        .and_then(|i| toks.get(i + 1))?;
    if !n.chars().all(|c| c.is_ascii_digit()) {
        return None; // "transceiver container" / the transceiver entity itself
    }
    Some(format!("{subslot}/{n}"))
}

/// Numeric port path of an interface name/descr (strip leading type letters):
/// "TenGigabitEthernet0/0/0" / "Te0/0/0" -> "0/0/0".
fn numeric_path(s: &str) -> &str {
    s.trim_start_matches(|c: char| !c.is_ascii_digit())
}

/// Walk the transceiver DOM sensors and map each to one of `ifaces` by port path.
/// Best-effort: an empty map if the agent exposes no optics. Reading scaling is
/// `entSensorValue / 10^entSensorPrecision`; kind comes from the entPhysicalName.
async fn collect_optics(client: &Snmp2cClient, ifaces: &[PollInterface]) -> BTreeMap<u64, Optics> {
    let names = walk_strings(client, OID_ENT_PHYS_NAME)
        .await
        .unwrap_or_default();
    if names.is_empty() {
        return BTreeMap::new();
    }
    let precs = walk_u64(client, OID_SENSOR_PRECISION)
        .await
        .unwrap_or_default();
    let vals = walk_i64(client, OID_SENSOR_VALUE).await.unwrap_or_default();
    let status = walk_u64(client, OID_SENSOR_STATUS)
        .await
        .unwrap_or_default();

    // entPhysicalIndex sensors -> optics grouped by port path ("0/0/0").
    let mut by_port: BTreeMap<String, Optics> = BTreeMap::new();
    for (idx, name) in &names {
        if status.get(idx).copied() != Some(1) {
            continue; // not "ok"
        }
        let kind = if name.contains("Temperature") {
            't'
        } else if name.contains("Tx Power") {
            'x'
        } else if name.contains("Rx Power") {
            'r'
        } else {
            continue;
        };
        let Some(port) = transceiver_port(name) else {
            continue;
        };
        let Some(&val) = vals.get(idx) else { continue };
        let prec = precs.get(idx).copied().unwrap_or(0);
        let actual = val as f64 / 10f64.powi(prec as i32);
        let e = by_port.entry(port).or_default();
        match kind {
            't' => e.temp_c = Some(actual),
            'x' => e.tx_power_dbm = Some(actual),
            _ => e.rx_power_dbm = Some(actual),
        }
    }

    // Map each interface to its port's optics by numeric port path.
    let mut out = BTreeMap::new();
    for ifc in ifaces {
        let path = ifc
            .if_name
            .as_deref()
            .map(numeric_path)
            .filter(|p| !p.is_empty())
            .or_else(|| {
                ifc.if_descr
                    .as_deref()
                    .map(numeric_path)
                    .filter(|p| !p.is_empty())
            });
        if let Some(path) = path {
            if let Some(opt) = by_port.get(path) {
                out.insert(ifc.interface_id, opt.clone());
            }
        }
    }
    out
}

// ---- sysDescr / status parsing -------------------------------------------------

/// Best-effort vendor/model/OS extraction from sysDescr. Recognizes Cisco IOS /
/// IOS-XE / IOS-XR (the ASR target) and a few common others; unknown agents get
/// a vendor guess from the first token. Never fails — returns Nones.
pub fn parse_sys_descr(descr: &str) -> (Option<String>, Option<String>, Option<String>) {
    let lower = descr.to_lowercase();

    if lower.contains("cisco") {
        let vendor = Some("Cisco".to_string());
        // OS family.
        let os_family = if lower.contains("ios-xr") || lower.contains("ios xr") {
            "IOS-XR"
        } else if lower.contains("ios-xe") || lower.contains("ios xe") {
            "IOS-XE"
        } else if lower.contains("nx-os") || lower.contains("nxos") {
            "NX-OS"
        } else {
            "IOS"
        };
        // Version: token after "Version" up to a comma.
        let version = descr
            .split_once("Version")
            .map(|(_, rest)| rest.trim())
            .and_then(|rest| rest.split([',', ' ']).find(|s| !s.is_empty()))
            .map(|v| format!("{os_family} {v}"))
            .or_else(|| Some(os_family.to_string()));
        // Model: a token starting with ASR/ISR/CSR/Nexus/C followed by digits.
        let model = descr
            .split_whitespace()
            .find(|t| {
                let u = t.to_uppercase();
                u.starts_with("ASR")
                    || u.starts_with("ISR")
                    || u.starts_with("CSR")
                    || u.starts_with("NEXUS")
            })
            .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string());
        return (vendor, model, version);
    }

    if lower.contains("juniper") || lower.contains("junos") {
        let version = descr
            .split_once("JUNOS")
            .and_then(|(_, rest)| rest.split_whitespace().find(|s| !s.is_empty()))
            .map(|v| format!("JUNOS {v}"));
        return (Some("Juniper".to_string()), None, version);
    }

    if lower.contains("linux") {
        // "Linux host 6.8.0-x ..." — kernel version is the 3rd token.
        let version = descr
            .split_whitespace()
            .nth(2)
            .map(|s| format!("Linux {s}"));
        return (Some("Linux".to_string()), None, version);
    }
    if lower.contains("mikrotik") || lower.contains("routeros") {
        return (Some("MikroTik".to_string()), None, None);
    }

    // Unknown agent: vendor guess = first whitespace token.
    let vendor = descr.split_whitespace().next().map(|s| s.to_string());
    (vendor, None, None)
}

/// ifAdminStatus enum -> label (1 up, 2 down, 3 testing).
fn admin_status_str(v: u64) -> &'static str {
    match v {
        1 => "up",
        2 => "down",
        3 => "testing",
        _ => "unknown",
    }
}

/// ifOperStatus enum -> label (1 up, 2 down, 3 testing, 4 unknown, 5 dormant,
/// 6 notPresent, 7 lowerLayerDown).
fn oper_status_str(v: u64) -> &'static str {
    match v {
        1 => "up",
        2 => "down",
        3 => "testing",
        4 => "unknown",
        5 => "dormant",
        6 => "notPresent",
        7 => "lowerLayerDown",
        _ => "unknown",
    }
}

/// Heuristic: is this ifType a physical interface (vs loopback/tunnel/virtual)?
/// 6 = ethernetCsmacd, 117 = gigabitEthernet, 161 = ieee8023adLag are common
/// "real" types; 24 = softwareLoopback, 131 = tunnel, 53 = propVirtual are not.
fn is_physical_type(t: u64) -> bool {
    matches!(t, 6 | 117 | 161 | 62 | 169)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cisco_iosxe_asr() {
        // Real ASR1000 IOS-XE sysDescr includes the "IOS-XE Software" marker.
        let d = "Cisco IOS-XE Software, ASR1000 Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.3.3, RELEASE SOFTWARE (fc7)";
        let (vendor, model, os) = parse_sys_descr(d);
        assert_eq!(vendor.as_deref(), Some("Cisco"));
        assert_eq!(model.as_deref(), Some("ASR1000"));
        assert!(os.as_deref().unwrap().contains("17.3.3"));
        assert!(os.as_deref().unwrap().starts_with("IOS-XE"));
    }

    #[test]
    fn parse_cisco_plain_ios_falls_back() {
        // A descriptor without an XE/XR marker classifies as plain IOS.
        let d = "Cisco IOS Software [Amsterdam], ISR4000 Software, Version 16.9.4";
        let (vendor, model, os) = parse_sys_descr(d);
        assert_eq!(vendor.as_deref(), Some("Cisco"));
        assert_eq!(model.as_deref(), Some("ISR4000"));
        assert!(os.as_deref().unwrap().starts_with("IOS "));
    }

    #[test]
    fn parse_cisco_iosxr() {
        let d = "Cisco IOS XR Software, Version 7.5.2, ASR9000";
        let (vendor, model, os) = parse_sys_descr(d);
        assert_eq!(vendor.as_deref(), Some("Cisco"));
        assert_eq!(model.as_deref(), Some("ASR9000"));
        assert!(os.as_deref().unwrap().starts_with("IOS-XR"));
    }

    #[test]
    fn parse_linux_agent() {
        let d = "Linux andrei-dev 6.8.0-124-generic #124-Ubuntu SMP x86_64";
        let (vendor, _model, os) = parse_sys_descr(d);
        assert_eq!(vendor.as_deref(), Some("Linux"));
        assert_eq!(os.as_deref(), Some("Linux 6.8.0-124-generic"));
    }

    #[test]
    fn status_labels() {
        assert_eq!(admin_status_str(1), "up");
        assert_eq!(oper_status_str(2), "down");
        assert_eq!(oper_status_str(7), "lowerLayerDown");
    }

    #[test]
    fn value_coercions() {
        assert_eq!(value_to_u64(&ObjectValue::Counter64(42)), Some(42));
        assert_eq!(value_to_u64(&ObjectValue::Counter32(7)), Some(7));
        assert_eq!(value_to_u64(&ObjectValue::String(vec![1, 2])), None);
        assert_eq!(value_to_string(&ObjectValue::Counter64(99)), "99");
    }
}
