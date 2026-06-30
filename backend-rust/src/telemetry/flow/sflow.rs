//! sFlow v5 (sflow.org / RFC 3176 lineage) wire decoder.
//!
//! A SECOND flow decoder alongside [`super::v9`], normalizing to the same
//! [`FlowRecord`] so the collector's aggregation, storage, API, and UI are
//! unchanged. Two things make sFlow fundamentally different from NetFlow v9:
//!
//! 1. **Stateless / self-describing.** There are no templates — the datagram
//!    layout is fixed XDR. So there is no per-exporter template cache and no
//!    "data before template" gap; [`decode`] takes only the datagram.
//! 2. **Raw packet headers, not counts.** A flow sample carries the first ~N
//!    bytes of the *actual sampled packet*, not pre-aggregated byte/packet
//!    counts. We parse that header (Ethernet/802.1Q -> IPv4/IPv6 -> TCP/UDP/SCTP)
//!    to build the tuple. Each sample represents one packet: `pkts = 1`,
//!    `bytes = frame_length` (the on-wire length), with the sample's own
//!    `sampling_rate` surfaced as the reported rate (reliable in sFlow, unlike
//!    NetFlow's options template).
//!
//! Doctrine: this parser MUST NEVER panic and MUST return structured errors. A
//! truncated/hostile datagram is dropped + counted, never fatal. Every read goes
//! through the bounds-checked [`Reader`]; a sampled header that is cut short
//! simply yields fewer fields (ports/addresses become `None` and the record is
//! skipped) rather than reading out of bounds.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::FlowRecord;

/// sFlow datagram version we decode.
const SFLOW_V5: u32 = 5;

// Sample types (data_format = enterprise << 12 | format; standard enterprise 0).
const SAMPLE_FLOW: u32 = 1;
const SAMPLE_FLOW_EXPANDED: u32 = 3;
// (counter samples 2 / 4 are intentionally ignored in v1 — they overlap SNMP.)

// Flow-record data formats (standard enterprise 0).
const RECORD_RAW_PACKET_HEADER: u32 = 1;

// Header protocols inside a raw-packet-header record.
const HP_ETHERNET: u32 = 1;
const HP_IPV4: u32 = 11;
const HP_IPV6: u32 = 12;

// EtherTypes.
const ET_IPV4: u16 = 0x0800;
const ET_IPV6: u16 = 0x86DD;
const ET_VLAN: u16 = 0x8100;
const ET_QINQ: u16 = 0x88A8;

// L4 protocols whose ports we read.
const IP_TCP: u8 = 6;
const IP_UDP: u8 = 17;
const IP_SCTP: u8 = 132;

/// Structured decode error. Mirrors [`super::v9::FlowError`] in spirit; the
/// collector drops + counts on `Err` and never panics.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SflowError {
    #[error("short buffer: needed {needed} bytes, have {have}")]
    Short { needed: usize, have: usize },
    #[error("unsupported sFlow version {0} (this decoder is sFlow v5)")]
    UnsupportedVersion(u32),
    #[error("unsupported agent address type {0}")]
    BadAddressType(u32),
}

/// The outcome of decoding one sFlow datagram. `sub_agent_id` maps to the
/// exporter `observation_domain`; `reported_sampling` is the last flow sample's
/// sampling rate (reliable in sFlow). `samples_skipped` counts samples that
/// carried no usable raw-packet-header record (e.g. counter samples) — normal,
/// not an error.
#[derive(Debug, Default, PartialEq)]
pub struct Decoded {
    pub agent_addr: Option<IpAddr>,
    pub sub_agent_id: u32,
    pub sequence: u32,
    pub records: Vec<FlowRecord>,
    pub reported_sampling: Option<u32>,
    pub samples_total: usize,
    pub samples_skipped: usize,
}

/// Bounds-checked big-endian (XDR) reader. Every accessor returns `Err(Short)`
/// rather than panicking when the buffer is too small.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SflowError> {
        if self.remaining() < n {
            return Err(SflowError::Short {
                needed: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u32(&mut self) -> Result<u32, SflowError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    /// Skip `n` bytes, clamped to what remains (never errors — used for opaque
    /// padding and for stepping over a body we have already sub-parsed).
    fn skip(&mut self, n: usize) {
        self.pos = (self.pos + n).min(self.buf.len());
    }
    /// Read an XDR opaque<>: a u32 length followed by that many bytes, then the
    /// 4-byte-alignment padding. Returns just the data slice. The declared
    /// length is clamped to what remains so a lying length cannot over-read.
    fn opaque(&mut self) -> Result<&'a [u8], SflowError> {
        let len = self.u32()? as usize;
        let len = len.min(self.remaining());
        let data = self.take(len)?;
        let pad = (4 - (len % 4)) % 4;
        self.skip(pad);
        Ok(data)
    }
}

/// Decode one sFlow v5 datagram. Returns structured errors; the caller drops +
/// counts on `Err`. Individual malformed samples are skipped, not fatal — a
/// best-effort parse extracts every record it can.
pub fn decode(datagram: &[u8]) -> Result<Decoded, SflowError> {
    let mut r = Reader::new(datagram);
    let version = r.u32()?;
    if version != SFLOW_V5 {
        return Err(SflowError::UnsupportedVersion(version));
    }
    let agent_addr = read_address(&mut r)?;
    let sub_agent_id = r.u32()?;
    let sequence = r.u32()?;
    let _uptime = r.u32()?;
    let num_samples = r.u32()?;

    let mut out = Decoded {
        agent_addr: Some(agent_addr),
        sub_agent_id,
        sequence,
        ..Default::default()
    };

    // Walk samples. `num_samples` is advisory: we stop when the buffer is
    // exhausted so a lying count cannot loop us past the data.
    for _ in 0..num_samples {
        if r.remaining() < 8 {
            break;
        }
        let sample_type = r.u32()?;
        let body = match r.opaque() {
            Ok(b) => b,
            Err(_) => break, // truncated sample body — stop cleanly.
        };
        out.samples_total += 1;
        match sample_type {
            SAMPLE_FLOW => parse_flow_sample(body, false, &mut out),
            SAMPLE_FLOW_EXPANDED => parse_flow_sample(body, true, &mut out),
            // counter samples (2 / 4) and unknown types: ignored in v1.
            _ => out.samples_skipped += 1,
        }
    }
    Ok(out)
}

/// Read an address: a u32 type (1 = IPv4, 2 = IPv6) followed by 4 or 16 bytes.
fn read_address(r: &mut Reader) -> Result<IpAddr, SflowError> {
    let kind = r.u32()?;
    match kind {
        1 => {
            let b = r.take(4)?;
            Ok(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
        }
        2 => {
            let b = r.take(16)?;
            let mut o = [0u8; 16];
            o.copy_from_slice(b);
            Ok(IpAddr::V6(Ipv6Addr::from(o)))
        }
        other => Err(SflowError::BadAddressType(other)),
    }
}

/// Decode the most-significant-2-bits "format" interface field used by the
/// non-expanded flow sample. Format 0 with a non-zero value is a real ifIndex;
/// anything else (unknown / multiple / discard) attributes to no interface.
fn iface(v: u32) -> Option<u32> {
    let format = v >> 30;
    let value = v & 0x3FFF_FFFF;
    if format == 0 && value != 0 {
        Some(value)
    } else {
        None
    }
}

/// Expanded flow sample carries the format and value as separate words.
fn iface_expanded(format: u32, value: u32) -> Option<u32> {
    if format == 0 && value != 0 {
        Some(value)
    } else {
        None
    }
}

/// Parse a (possibly expanded) flow sample body, appending one [`FlowRecord`]
/// per sample that contains a usable raw-packet-header record.
fn parse_flow_sample(body: &[u8], expanded: bool, out: &mut Decoded) {
    let mut r = Reader::new(body);
    // header fields up to num_records; bail (skip the sample) on truncation.
    let parsed = (|| -> Result<(u32, Option<u32>, Option<u32>, u32), SflowError> {
        let _seq = r.u32()?;
        let (sampling_rate, in_if, out_if);
        if expanded {
            let _src_type = r.u32()?;
            let _src_index = r.u32()?;
            sampling_rate = r.u32()?;
            let _pool = r.u32()?;
            let _drops = r.u32()?;
            let in_fmt = r.u32()?;
            let in_val = r.u32()?;
            let out_fmt = r.u32()?;
            let out_val = r.u32()?;
            in_if = iface_expanded(in_fmt, in_val);
            out_if = iface_expanded(out_fmt, out_val);
        } else {
            let _src_id = r.u32()?;
            sampling_rate = r.u32()?;
            let _pool = r.u32()?;
            let _drops = r.u32()?;
            in_if = iface(r.u32()?);
            out_if = iface(r.u32()?);
        }
        let num_records = r.u32()?;
        Ok((sampling_rate, in_if, out_if, num_records))
    })();
    let (sampling_rate, in_if, out_if, num_records) = match parsed {
        Ok(v) => v,
        Err(_) => {
            out.samples_skipped += 1;
            return;
        }
    };

    // sFlow's per-sample rate is reliable; surface it for the exporter's
    // effective-rate resolution (last writer wins — see the uniform-rate caveat
    // in docs/flow-telemetry.md).
    if sampling_rate >= 1 {
        out.reported_sampling = Some(sampling_rate);
    }

    // Walk the flow records; we build the tuple from the raw-packet-header one.
    let mut record: Option<FlowRecord> = None;
    for _ in 0..num_records {
        if r.remaining() < 8 {
            break;
        }
        let data_format = match r.u32() {
            Ok(v) => v,
            Err(_) => break,
        };
        let rec_body = match r.opaque() {
            Ok(b) => b,
            Err(_) => break,
        };
        if data_format == RECORD_RAW_PACKET_HEADER {
            if let Some(mut fr) = parse_raw_header(rec_body) {
                fr.in_if_index = in_if;
                fr.out_if_index = out_if;
                record = Some(fr);
            }
        }
    }

    match record {
        Some(fr) => out.records.push(fr),
        None => out.samples_skipped += 1,
    }
}

/// Parse a `sampled_header` record: header_protocol, frame_length, stripped, and
/// the opaque header bytes; then decode the header into a [`FlowRecord`]. `bytes`
/// is the original on-wire `frame_length` (L2-inclusive — the SNMP cross-cal
/// tolerance already accounts for the L2/L3 delta); `pkts` is 1.
fn parse_raw_header(body: &[u8]) -> Option<FlowRecord> {
    let mut r = Reader::new(body);
    let header_protocol = r.u32().ok()?;
    let frame_length = r.u32().ok()?;
    let _stripped = r.u32().ok()?;
    let header = r.opaque().ok()?;

    let (src_addr, dst_addr, protocol, src_port, dst_port) = match header_protocol {
        HP_ETHERNET => parse_ethernet(header)?,
        HP_IPV4 => parse_ipv4(header)?,
        HP_IPV6 => parse_ipv6(header)?,
        _ => return None, // unsupported link layer (e.g. PPP) — skip.
    };

    Some(FlowRecord {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        in_if_index: None, // filled in by the caller from the sample header.
        out_if_index: None,
        src_as: None,
        dst_as: None,
        // sFlow attributes per packet; leave direction unset so the collector
        // attributes ingress on the input ifIndex (the Cisco-default behavior the
        // NetFlow path already uses).
        direction: None,
        bytes: frame_length as u64,
        pkts: 1,
    })
}

type Tuple = (IpAddr, IpAddr, u8, Option<u16>, Option<u16>);

/// Parse an Ethernet frame: dst/src MAC, EtherType, optional 802.1Q / QinQ tags,
/// then IPv4 / IPv6. Returns None for non-IP frames or truncation.
fn parse_ethernet(h: &[u8]) -> Option<Tuple> {
    if h.len() < 14 {
        return None;
    }
    let mut off = 12usize; // skip dst+src MAC.
    let mut ethertype = be16(h, off)?;
    off += 2;
    // Step over up to two VLAN tags (single-tagged and QinQ are common).
    for _ in 0..2 {
        if ethertype == ET_VLAN || ethertype == ET_QINQ {
            // TCI (2) + inner EtherType (2).
            ethertype = be16(h, off + 2)?;
            off += 4;
        } else {
            break;
        }
    }
    match ethertype {
        ET_IPV4 => parse_ipv4(h.get(off..)?),
        ET_IPV6 => parse_ipv6(h.get(off..)?),
        _ => None,
    }
}

/// Parse an IPv4 header (and L4 ports for TCP/UDP/SCTP). Truncation past the
/// addresses still yields a record with `None` ports.
fn parse_ipv4(h: &[u8]) -> Option<Tuple> {
    if h.len() < 20 {
        return None;
    }
    let ihl = ((h[0] & 0x0f) as usize) * 4;
    if ihl < 20 {
        return None; // malformed IHL.
    }
    let protocol = h[9];
    let src = IpAddr::V4(Ipv4Addr::new(h[12], h[13], h[14], h[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(h[16], h[17], h[18], h[19]));
    let (src_port, dst_port) = l4_ports(h, ihl, protocol);
    Some((src, dst, protocol, src_port, dst_port))
}

/// Parse a fixed IPv6 header (40 bytes). Extension headers are not walked in v1:
/// if `next_header` is an extension rather than an L4 protocol, ports are `None`
/// (the addresses and the next-header value are still recorded).
fn parse_ipv6(h: &[u8]) -> Option<Tuple> {
    if h.len() < 40 {
        return None;
    }
    let next_header = h[6];
    let src = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&h[8..24]).ok()?));
    let dst = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&h[24..40]).ok()?));
    let (src_port, dst_port) = l4_ports(h, 40, next_header);
    Some((src, dst, next_header, src_port, dst_port))
}

/// Read L4 source/destination ports at `l4_off` for TCP/UDP/SCTP. Returns
/// `(None, None)` for portless protocols or a header truncated before the ports.
fn l4_ports(h: &[u8], l4_off: usize, protocol: u8) -> (Option<u16>, Option<u16>) {
    if !matches!(protocol, IP_TCP | IP_UDP | IP_SCTP) {
        return (None, None);
    }
    match (be16(h, l4_off), be16(h, l4_off + 2)) {
        (Some(sp), Some(dp)) => (Some(sp), Some(dp)),
        _ => (None, None),
    }
}

/// Bounds-checked big-endian u16 read at `off`.
fn be16(h: &[u8], off: usize) -> Option<u16> {
    let b = h.get(off..off + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}
