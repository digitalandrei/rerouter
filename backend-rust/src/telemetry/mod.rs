//! Traffic telemetry ingestion + normalization. See ../docs/telemetry-model.md.
//!
//! v1 telemetry is **SNMP v2c interface polling** (see [`snmp`]). The model is
//! device (router) + interface: poll 64-bit ifXTable counters, derive per-
//! interface rates, store current + history, and feed the detection engine.
//! SNMP is read-only — ideal for observe mode.

pub mod flow;
pub mod snmp;

use chrono::{DateTime, Utc};

/// A normalized per-asset measurement over an interval (flow-source shape; kept
/// for the future NetFlow path).
#[derive(Debug, Clone, Default)]
pub struct AssetMetrics {
    pub valid_sample: bool,
    pub sampling_rate: u32,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub new_conns_per_sec: f64,
    pub syn_rate: f64,
    pub syn_ack_ratio: f64,
    pub unique_src_count: u64,
}

/// Derive a rate from a counter pair, handling wrap/reset.
/// Returns None (invalid sample) when the counter went backwards or no time
/// elapsed; the caller then resets the baseline and emits no rate.
pub fn rate_from_counters(current: u64, previous: u64, elapsed_secs: f64) -> Option<f64> {
    if elapsed_secs <= 0.0 || current < previous {
        return None; // wrap/reset -> invalid; caller resets baseline.
    }
    Some((current - previous) as f64 / elapsed_secs)
}

/// Octet-counter delta -> bits/sec (×8). None on wrap/reset.
pub fn bps_from_octets(current: u64, previous: u64, elapsed_secs: f64) -> Option<f64> {
    rate_from_counters(current, previous, elapsed_secs).map(|r| r * 8.0)
}

/// Packet-counter delta -> packets/sec. None on wrap/reset.
pub fn pps_from_pkts(current: u64, previous: u64, elapsed_secs: f64) -> Option<f64> {
    rate_from_counters(current, previous, elapsed_secs)
}

/// Link utilization percent from a derived bps and the interface speed.
/// Returns 0.0 when the speed is unknown (0) — never NaN/inf, never > caller's
/// expectation without a real speed.
pub fn util_percent(bps: f64, if_speed_bps: u64) -> f64 {
    if if_speed_bps == 0 {
        return 0.0;
    }
    bps / if_speed_bps as f64 * 100.0
}

/// One interface's derived rates for a poll tick. `valid` is false on the first
/// poll (no baseline) or a wrap/reset on either direction.
#[derive(Debug, Clone, Default)]
pub struct InterfaceRates {
    pub valid: bool,
    pub rx_bps: f64,
    pub tx_bps: f64,
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub rx_util_percent: f64,
    pub tx_util_percent: f64,
}

/// Raw 64-bit interface counters from one SNMP read, plus the moment they were
/// sampled. The previous row of these (from interface_metrics_current) is the
/// delta baseline for the next read.
#[derive(Debug, Clone)]
pub struct InterfaceCounters {
    pub sampled_at: DateTime<Utc>,
    pub in_octets: u64,
    pub out_octets: u64,
    pub in_ucast_pkts: u64,
    pub out_ucast_pkts: u64,
}

/// Compute interface rates from the current and previous counter reads.
///
/// Counter wrap/reset rule (docs/telemetry-model.md): if a counter went
/// backwards, the whole sample is marked invalid — detection must not fire on it
/// — and the caller stores the new raw counters as the next baseline regardless.
/// `if_speed_bps` drives the utilization percentages.
pub fn interface_rates(
    current: &InterfaceCounters,
    previous: Option<&InterfaceCounters>,
    if_speed_bps: u64,
) -> InterfaceRates {
    let prev = match previous {
        Some(p) => p,
        None => return InterfaceRates::default(), // first poll: no baseline yet.
    };
    let elapsed = (current.sampled_at - prev.sampled_at).num_milliseconds() as f64 / 1000.0;

    // All four derivations must be valid; any wrap/reset invalidates the sample.
    let (rx_bps, tx_bps, rx_pps, tx_pps) = match (
        bps_from_octets(current.in_octets, prev.in_octets, elapsed),
        bps_from_octets(current.out_octets, prev.out_octets, elapsed),
        pps_from_pkts(current.in_ucast_pkts, prev.in_ucast_pkts, elapsed),
        pps_from_pkts(current.out_ucast_pkts, prev.out_ucast_pkts, elapsed),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => return InterfaceRates::default(), // invalid sample (wrap/reset/no time).
    };

    InterfaceRates {
        valid: true,
        rx_bps,
        tx_bps,
        rx_pps,
        tx_pps,
        rx_util_percent: util_percent(rx_bps, if_speed_bps),
        tx_util_percent: util_percent(tx_bps, if_speed_bps),
    }
}
