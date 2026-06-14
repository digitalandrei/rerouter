//! Flow telemetry (NetFlow v9 / IPFIX) — a SECOND, read-only telemetry source.
//! See ../../../docs/flow-telemetry.md.
//!
//! SNMP gives per-interface *volume*; flow gives per-tuple *composition* (which
//! sources, ports, 5-tuples make up that volume) — the base for a high-pps /
//! low-bitrate detector (e.g. UDP/53 reflection). This module is purely
//! telemetry: it ingests, aggregates, and displays. It executes nothing — observe
//! mode and every reroute gate are unchanged.
//!
//! Layout: [`v9`] is the wire decoder (pure, never panics, structured errors);
//! [`collector`] is the UDP listener + bucket aggregation + DB flush + prune.
//! The decoder normalizes to [`FlowRecord`] so an IPFIX (v10) decoder is additive.

pub mod collector;
pub mod v9;

use std::net::IpAddr;

/// Flow direction relative to the interface. NetFlow's DIRECTION field (61):
/// 0 = ingress, 1 = egress. Maps to the `direction` ENUM in the DB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Ingress,
    Egress,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        }
    }
    /// NetFlow DIRECTION field value -> Direction. Anything but 1 is ingress
    /// (Cisco exports ingress flows by default).
    pub fn from_netflow(v: u8) -> Self {
        if v == 1 {
            Direction::Egress
        } else {
            Direction::Ingress
        }
    }
}

/// Whether a `flow_port_buckets` row keys on the source or destination port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortKind {
    Src,
    Dst,
}

impl PortKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PortKind::Src => "src",
            PortKind::Dst => "dst",
        }
    }
}

/// One normalized flow record decoded from a data set. Counts are RAW (sampled);
/// the effective sampling rate is applied later (at display/detection), never
/// baked into stored counts. `*_if_index` come from INPUT_SNMP / OUTPUT_SNMP and
/// map to `device_interfaces.if_index`.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowRecord {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    /// None for protocols without L4 ports (e.g. ICMP, GRE).
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: u8,
    pub in_if_index: Option<u32>,
    pub out_if_index: Option<u32>,
    /// Source / destination AS (SRC_AS 16 / DST_AS 17) — None unless the exporter
    /// collects them (Cisco FNF `collect routing source/destination as`).
    pub src_as: Option<u32>,
    pub dst_as: Option<u32>,
    /// NetFlow DIRECTION (61) if the template carried it.
    pub direction: Option<u8>,
    pub bytes: u64,
    pub pkts: u64,
}

impl FlowRecord {
    /// The (direction, interface ifIndex) this flow is attributed to. With a
    /// DIRECTION field, ingress uses INPUT_SNMP and egress uses OUTPUT_SNMP;
    /// without it, default to ingress on INPUT_SNMP (the Cisco default export).
    pub fn attribution(&self) -> (Direction, Option<u32>) {
        match self.direction.map(Direction::from_netflow) {
            Some(Direction::Egress) => (Direction::Egress, self.out_if_index),
            Some(Direction::Ingress) => (Direction::Ingress, self.in_if_index),
            None => (Direction::Ingress, self.in_if_index),
        }
    }

    /// True for protocols whose L4 ports are meaningful (TCP/UDP/SCTP).
    pub fn has_ports(&self) -> bool {
        matches!(self.protocol, 6 | 17 | 132)
    }
}

/// How an exporter's effective sampling rate was resolved. Maps to the
/// `sampling_source` ENUM. Precedence (docs/flow-telemetry.md): config (force) >
/// reported > snmp_derived > default > unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingSource {
    Config,
    Reported,
    SnmpDerived,
    Default,
    Unknown,
}

impl SamplingSource {
    pub fn as_str(self) -> &'static str {
        match self {
            SamplingSource::Config => "config",
            SamplingSource::Reported => "reported",
            SamplingSource::SnmpDerived => "snmp_derived",
            SamplingSource::Default => "default",
            SamplingSource::Unknown => "unknown",
        }
    }
}

/// Resolved sampling state for an exporter: the multiplier to apply and whether
/// it is trustworthy. Low confidence must block flow-driven automatic actions.
#[derive(Debug, Clone, Copy)]
pub struct Sampling {
    pub rate: u32,
    pub source: SamplingSource,
    pub high_confidence: bool,
}

impl Sampling {
    pub fn confidence_str(&self) -> &'static str {
        if self.high_confidence {
            "high"
        } else {
            "low"
        }
    }
}

/// Resolve the effective sampling rate from the available inputs, applying the
/// documented precedence. `default_rate` is the global `[flow]` fallback.
///
/// - `configured`: operator override — authoritative when set (operator intent
///   wins over a possibly-stale device-reported value).
/// - `reported`: rate parsed from the exporter's options template.
/// - `snmp_derived`: rate back-calculated against SNMP ifHC counters.
///
/// A rate of 1 (unsampled) is always high-confidence. Falling through to the
/// global default for a sampled-looking exporter (or having nothing at all) is
/// low-confidence.
pub fn resolve_sampling(
    configured: Option<u32>,
    reported: Option<u32>,
    snmp_derived: Option<u32>,
    default_rate: u32,
) -> Sampling {
    if let Some(rate) = configured.filter(|r| *r >= 1) {
        return Sampling {
            rate,
            source: SamplingSource::Config,
            high_confidence: true,
        };
    }
    if let Some(rate) = reported.filter(|r| *r >= 1) {
        return Sampling {
            rate,
            source: SamplingSource::Reported,
            high_confidence: true,
        };
    }
    if let Some(rate) = snmp_derived.filter(|r| *r >= 1) {
        return Sampling {
            rate,
            source: SamplingSource::SnmpDerived,
            high_confidence: true,
        };
    }
    let rate = default_rate.max(1);
    // An unsampled (1:1) default is trustworthy; any assumed >1 rate is not.
    Sampling {
        rate,
        source: SamplingSource::Default,
        high_confidence: rate == 1,
    }
}
