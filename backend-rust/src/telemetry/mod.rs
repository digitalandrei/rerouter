//! Traffic telemetry ingestion + normalization. See ../docs/telemetry-model.md
//! and ../skills/traffic-telemetry.md.
//!
//! Sources: NetFlow/IPFIX/sFlow (flow), the BGP feed (for reroute verification),
//! and Cloudflare analytics. Output: per-asset normalized metrics carrying
//! `method`, `valid_sample`, `sampling_rate`, and a staleness flag.

pub mod netflow;
pub mod sflow;
pub mod bgp;
pub mod cloudflare;

/// A normalized per-asset measurement over an interval.
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
/// Returns None (invalid sample) when the counter went backwards.
pub fn rate_from_counters(current: u64, previous: u64, elapsed_secs: f64) -> Option<f64> {
    if elapsed_secs <= 0.0 || current < previous {
        return None; // wrap/reset -> invalid; caller resets baseline.
    }
    Some((current - previous) as f64 / elapsed_secs)
}

// TODO(milestone 1): rollup flow records into AssetMetrics, apply sampling rate,
// write asset_metrics_current + traffic_samples, mark staleness.
