//! Unit tests for SNMP rate derivation and counter wrap/reset handling, using
//! synthetic counter pairs (no live device required). These cover the core of
//! the v1 telemetry math: octets -> bps (×8), pkts -> pps, util%, and the rule
//! that a backwards counter invalidates the whole sample (docs/telemetry-model.md).

use chrono::{Duration, Utc};
use rerouter_controller::telemetry::{
    bps_from_octets, interface_rates, pps_from_pkts, rate_from_counters, util_percent,
    InterfaceCounters,
};

fn counters(secs_ago: i64, in_oct: u64, out_oct: u64, in_pkt: u64, out_pkt: u64) -> InterfaceCounters {
    InterfaceCounters {
        sampled_at: Utc::now() - Duration::seconds(secs_ago),
        in_octets: in_oct,
        out_octets: out_oct,
        in_ucast_pkts: in_pkt,
        out_ucast_pkts: out_pkt,
    }
}

#[test]
fn octets_to_bps_is_delta_times_8_over_elapsed() {
    // 1_250_000 octets in 10s = 1_000_000 bps (1 Mbps).
    let bps = bps_from_octets(2_250_000, 1_000_000, 10.0).unwrap();
    assert!((bps - 1_000_000.0).abs() < 1e-6, "got {bps}");
}

#[test]
fn pkts_to_pps_is_delta_over_elapsed() {
    let pps = pps_from_pkts(15_000, 5_000, 10.0).unwrap();
    assert!((pps - 1_000.0).abs() < 1e-6, "got {pps}");
}

#[test]
fn util_percent_uses_interface_speed() {
    // 5 Gbps on a 10 Gbps link = 50%.
    let u = util_percent(5_000_000_000.0, 10_000_000_000);
    assert!((u - 50.0).abs() < 1e-6, "got {u}");
}

#[test]
fn util_percent_zero_speed_is_zero_not_nan() {
    let u = util_percent(1_000_000.0, 0);
    assert_eq!(u, 0.0);
    assert!(u.is_finite());
}

#[test]
fn rate_zero_or_negative_elapsed_is_invalid() {
    assert_eq!(rate_from_counters(100, 0, 0.0), None);
    assert_eq!(rate_from_counters(100, 0, -1.0), None);
}

#[test]
fn full_sample_derivation_is_correct() {
    // 10s apart. in: +1_250_000 oct -> 1 Mbps; out: +12_500_000 oct -> 10 Mbps.
    //          in pkts: +10_000 -> 1000 pps; out pkts: +20_000 -> 2000 pps.
    let prev = counters(10, 1_000_000, 5_000_000, 100_000, 200_000);
    let cur = counters(0, 2_250_000, 17_500_000, 110_000, 220_000);
    let r = interface_rates(&cur, Some(&prev), 100_000_000); // 100 Mbps link

    assert!(r.valid);
    assert!((r.rx_bps - 1_000_000.0).abs() < 1.0, "rx_bps {}", r.rx_bps);
    assert!((r.tx_bps - 10_000_000.0).abs() < 10.0, "tx_bps {}", r.tx_bps);
    assert!((r.rx_pps - 1_000.0).abs() < 0.1, "rx_pps {}", r.rx_pps);
    assert!((r.tx_pps - 2_000.0).abs() < 0.1, "tx_pps {}", r.tx_pps);
    // 1 Mbps / 100 Mbps = 1%, 10 Mbps / 100 Mbps = 10%.
    assert!((r.rx_util_percent - 1.0).abs() < 0.01, "rx_util {}", r.rx_util_percent);
    assert!((r.tx_util_percent - 10.0).abs() < 0.01, "tx_util {}", r.tx_util_percent);
}

#[test]
fn first_poll_without_baseline_is_invalid() {
    let cur = counters(0, 1_000_000, 1_000_000, 1000, 1000);
    let r = interface_rates(&cur, None, 1_000_000_000);
    assert!(!r.valid, "first poll must not produce a rate");
    assert_eq!(r.rx_bps, 0.0);
}

#[test]
fn counter_wrap_on_inbound_octets_invalidates_sample() {
    // Current in_octets < previous -> wrap/reset. Whole sample invalid, no rate.
    let prev = counters(10, 9_000_000_000, 1_000_000, 100_000, 200_000);
    let cur = counters(0, 5_000, 2_000_000, 110_000, 220_000); // in_octets went backwards
    let r = interface_rates(&cur, Some(&prev), 10_000_000_000);
    assert!(!r.valid, "wrap/reset must invalidate the sample");
    assert_eq!(r.rx_bps, 0.0);
    assert_eq!(r.tx_bps, 0.0);
}

#[test]
fn counter_reset_on_outbound_pkts_invalidates_sample() {
    // A device reboot resets all counters; out_ucast_pkts going backwards alone
    // invalidates the sample even though octets advanced.
    let prev = counters(10, 1_000_000, 5_000_000, 100_000, 9_000_000);
    let cur = counters(0, 2_000_000, 6_000_000, 110_000, 10); // out pkts reset
    let r = interface_rates(&cur, Some(&prev), 1_000_000_000);
    assert!(!r.valid);
}

#[test]
fn equal_counters_give_zero_rate_and_remain_valid() {
    // No traffic between polls: deltas are 0, sample is valid with zero rates.
    let prev = counters(10, 1_000_000, 5_000_000, 100_000, 200_000);
    let cur = counters(0, 1_000_000, 5_000_000, 100_000, 200_000);
    let r = interface_rates(&cur, Some(&prev), 1_000_000_000);
    assert!(r.valid);
    assert_eq!(r.rx_bps, 0.0);
    assert_eq!(r.tx_pps, 0.0);
}
