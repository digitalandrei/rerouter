//! NetFlow v9 (RFC 3954) wire decoder + per-exporter template cache.
//!
//! Doctrine: telemetry parsers MUST return structured errors and NEVER panic; a
//! malformed datagram is dropped + counted, never fatal. Every read is
//! bounds-checked through [`Reader`]; there is no indexing or slicing that can
//! panic on a truncated/hostile packet.
//!
//! v9 is template-based: the exporter periodically sends Template FlowSets
//! (flowset id 0) and Options Template FlowSets (id 1) describing the layout of
//! the Data FlowSets (id >= 256) that reference them by id. A data set that
//! arrives before its template is undecodable and is counted as
//! `data_without_template` (a telemetry gap, not an error). IPFIX (v10) shares
//! these field semantics and is intended as an additive sibling decoder.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::FlowRecord;

/// NetFlow v9 header is 20 bytes.
const HEADER_LEN: usize = 20;
/// FlowSet ids below this are special; >= this is a data set referencing a
/// template id.
const FIRST_DATA_FLOWSET_ID: u16 = 256;
const TEMPLATE_FLOWSET_ID: u16 = 0;
const OPTIONS_TEMPLATE_FLOWSET_ID: u16 = 1;

// NetFlow v9 field type ids we understand. Unknown ids are skipped (their bytes
// advanced) so an unfamiliar template still decodes its known fields.
const F_IN_BYTES: u16 = 1;
const F_IN_PKTS: u16 = 2;
const F_PROTOCOL: u16 = 4;
const F_L4_SRC_PORT: u16 = 7;
const F_IPV4_SRC_ADDR: u16 = 8;
const F_INPUT_SNMP: u16 = 10;
const F_L4_DST_PORT: u16 = 11;
const F_IPV4_DST_ADDR: u16 = 12;
const F_OUTPUT_SNMP: u16 = 14;
const F_SRC_AS: u16 = 16;
const F_DST_AS: u16 = 17;
const F_OUT_BYTES: u16 = 23;
const F_OUT_PKTS: u16 = 24;
const F_IPV6_SRC_ADDR: u16 = 27;
const F_IPV6_DST_ADDR: u16 = 28;
const F_SAMPLING_INTERVAL: u16 = 34;
const F_FLOW_SAMPLER_RANDOM_INTERVAL: u16 = 50;
const F_DIRECTION: u16 = 61;

/// Structured decode error. Carrying the offending sizes makes drops debuggable.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum FlowError {
    #[error("short buffer: needed {needed} bytes, have {have}")]
    Short { needed: usize, have: usize },
    #[error("unsupported version {0} (this decoder is NetFlow v9)")]
    UnsupportedVersion(u16),
    #[error("flowset length {0} is too small to be valid")]
    BadFlowsetLength(u16),
    #[error("template {0} declares zero fields")]
    EmptyTemplate(u16),
    #[error("template {0} has a zero-length record")]
    ZeroLengthRecord(u16),
}

/// A cached template: the ordered (field_type, field_length) layout and the
/// total record length. `is_options` marks an options template (its data sets
/// carry sampler/metadata, not flows).
#[derive(Debug, Clone)]
pub struct Template {
    pub fields: Vec<(u16, u16)>,
    pub record_len: usize,
    pub is_options: bool,
}

/// Per-exporter template cache, keyed by (source_id, template_id). Held by the
/// collector per exporter; volatile (in-memory) — after a restart, data sets are
/// dropped until each template is re-advertised (logged; a telemetry gap, not a
/// safety issue).
/// Cap on distinct templates cached per exporter. The key includes `source_id`,
/// a value the SENDER chooses per datagram, so without a bound a hostile/buggy
/// exporter could grow this map without limit (a whole-process OOM). Real Cisco
/// exporters use a handful of templates, so this is very generous.
const MAX_TEMPLATES: usize = 1024;

#[derive(Debug, Default)]
pub struct TemplateCache {
    templates: HashMap<(u32, u16), (Template, u64)>, // value + last-write tick (LRU)
    tick: u64,
}

impl TemplateCache {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.templates.len()
    }
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
    fn get(&self, source_id: u32, template_id: u16) -> Option<&Template> {
        self.templates
            .get(&(source_id, template_id))
            .map(|(t, _)| t)
    }
    fn insert(&mut self, source_id: u32, template_id: u16, t: Template) {
        self.tick = self.tick.wrapping_add(1);
        let key = (source_id, template_id);
        // At capacity for a NEW key, evict the least-recently-written entry.
        // Exporters re-advertise their templates periodically, refreshing the
        // tick, so an actively-used template stays resident.
        if !self.templates.contains_key(&key) && self.templates.len() >= MAX_TEMPLATES {
            if let Some(victim) = self
                .templates
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(k, _)| *k)
            {
                self.templates.remove(&victim);
            }
        }
        let tick = self.tick;
        self.templates.insert(key, (t, tick));
    }
}

/// The outcome of decoding one datagram. `records` are the flows extracted;
/// `reported_sampling` is a sampling interval seen in an options data set (if
/// any); the counters feed exporter health.
#[derive(Debug, Default, PartialEq)]
pub struct Decoded {
    pub source_id: u32,
    pub sequence: u32,
    pub records: Vec<FlowRecord>,
    pub reported_sampling: Option<u32>,
    pub templates_learned: usize,
    pub data_without_template: usize,
}

/// Bounds-checked big-endian reader. Every accessor returns `Err(Short)` rather
/// than panicking when the buffer is too small.
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
    fn take(&mut self, n: usize) -> Result<&'a [u8], FlowError> {
        if self.remaining() < n {
            return Err(FlowError::Short {
                needed: n,
                have: self.remaining(),
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, FlowError> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, FlowError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// Read a big-endian unsigned integer from a 1..=8 byte field as u64. Fields
/// wider than 8 bytes (unusual for counters we use) are truncated to their low 8
/// bytes; shorter fields are zero-extended. Never panics.
fn be_uint(bytes: &[u8]) -> u64 {
    let mut v: u64 = 0;
    for &b in bytes.iter().rev().take(8).rev() {
        v = (v << 8) | b as u64;
    }
    v
}

/// Decode one NetFlow v9 datagram against (and updating) the exporter's template
/// cache. Returns structured errors; the caller drops + counts on `Err`.
pub fn decode(datagram: &[u8], cache: &mut TemplateCache) -> Result<Decoded, FlowError> {
    if datagram.len() < HEADER_LEN {
        return Err(FlowError::Short {
            needed: HEADER_LEN,
            have: datagram.len(),
        });
    }
    let mut r = Reader::new(datagram);
    let version = r.u16()?;
    if version != 9 {
        return Err(FlowError::UnsupportedVersion(version));
    }
    let _count = r.u16()?; // record count is advisory; we iterate by length.
    let _sys_uptime = r.u32()?;
    let _unix_secs = r.u32()?;
    let sequence = r.u32()?;
    let source_id = r.u32()?;

    let mut out = Decoded {
        source_id,
        sequence,
        ..Default::default()
    };

    // Walk FlowSets until the datagram is exhausted. A FlowSet header is
    // flowset_id (u16) + length (u16, includes the 4 header bytes).
    while r.remaining() >= 4 {
        let flowset_id = r.u16()?;
        let flowset_len = r.u16()?;
        if (flowset_len as usize) < 4 {
            return Err(FlowError::BadFlowsetLength(flowset_len));
        }
        // Body length excludes the 4-byte header. Clamp to what's left so a lying
        // length can't read past the datagram.
        let body_len = (flowset_len as usize - 4).min(r.remaining());
        let body = r.take(body_len)?;

        match flowset_id {
            TEMPLATE_FLOWSET_ID => {
                out.templates_learned += parse_templates(body, source_id, cache, false)?;
            }
            OPTIONS_TEMPLATE_FLOWSET_ID => {
                out.templates_learned += parse_options_template(body, source_id, cache)?;
            }
            id if id >= FIRST_DATA_FLOWSET_ID => match cache.get(source_id, id) {
                Some(t) if t.is_options => {
                    if let Some(rate) = parse_options_data(body, t) {
                        out.reported_sampling = Some(rate);
                    }
                }
                Some(t) => parse_data_records(body, t, &mut out.records),
                None => out.data_without_template += 1,
            },
            // ids 2..=255 are reserved; skip the body.
            _ => {}
        }
    }
    Ok(out)
}

/// Parse one or more templates from a Template FlowSet body into the cache.
/// Returns the number of templates learned.
fn parse_templates(
    body: &[u8],
    source_id: u32,
    cache: &mut TemplateCache,
    is_options: bool,
) -> Result<usize, FlowError> {
    let mut r = Reader::new(body);
    let mut learned = 0;
    // Each template: template_id (u16), field_count (u16), then field_count
    // (type u16, length u16) pairs. Trailing padding (< 4 bytes) ends the loop.
    while r.remaining() >= 4 {
        let template_id = r.u16()?;
        let field_count = r.u16()?;
        if field_count == 0 {
            return Err(FlowError::EmptyTemplate(template_id));
        }
        let mut fields = Vec::with_capacity(field_count as usize);
        let mut record_len = 0usize;
        for _ in 0..field_count {
            let ftype = r.u16()?;
            let flen = r.u16()?;
            record_len += flen as usize;
            fields.push((ftype, flen));
        }
        if record_len == 0 {
            return Err(FlowError::ZeroLengthRecord(template_id));
        }
        cache.insert(
            source_id,
            template_id,
            Template {
                fields,
                record_len,
                is_options,
            },
        );
        learned += 1;
    }
    Ok(learned)
}

/// Parse an Options Template FlowSet body. Layout: template_id (u16),
/// option_scope_length (u16, bytes), option_length (u16, bytes), then
/// scope (type,len) pairs filling scope_length, then option (type,len) pairs
/// filling option_length. We store the combined field list and mark it options.
fn parse_options_template(
    body: &[u8],
    source_id: u32,
    cache: &mut TemplateCache,
) -> Result<usize, FlowError> {
    let mut r = Reader::new(body);
    let mut learned = 0;
    while r.remaining() >= 6 {
        let template_id = r.u16()?;
        let scope_len = r.u16()? as usize;
        let option_len = r.u16()? as usize;
        if scope_len == 0 && option_len == 0 {
            break; // padding
        }
        // (type,len) pairs are 4 bytes each.
        let scope_pairs = scope_len / 4;
        let option_pairs = option_len / 4;
        let mut fields = Vec::with_capacity(scope_pairs + option_pairs);
        let mut record_len = 0usize;
        for _ in 0..(scope_pairs + option_pairs) {
            let ftype = r.u16()?;
            let flen = r.u16()?;
            record_len += flen as usize;
            fields.push((ftype, flen));
        }
        if record_len == 0 {
            return Err(FlowError::ZeroLengthRecord(template_id));
        }
        cache.insert(
            source_id,
            template_id,
            Template {
                fields,
                record_len,
                is_options: true,
            },
        );
        learned += 1;
    }
    Ok(learned)
}

/// Decode flow data records from a Data FlowSet body against its template,
/// appending normalized [`FlowRecord`]s. Trailing padding (< record_len) is
/// ignored. Bounds are guaranteed by slicing exactly `record_len` per record.
fn parse_data_records(body: &[u8], template: &Template, out: &mut Vec<FlowRecord>) {
    let rec = template.record_len;
    if rec == 0 {
        return;
    }
    let n = body.len() / rec;
    for i in 0..n {
        let start = i * rec;
        let record = &body[start..start + rec];
        if let Some(fr) = decode_one_record(record, template) {
            out.push(fr);
        }
    }
}

/// Decode a single fixed-length record into a [`FlowRecord`]. Fields are walked
/// in template order, each slicing exactly its declared length. Returns None if
/// neither an IPv4 nor IPv6 address pair was present (not a flow record we use).
fn decode_one_record(record: &[u8], template: &Template) -> Option<FlowRecord> {
    let mut off = 0usize;
    let mut src_v4: Option<Ipv4Addr> = None;
    let mut dst_v4: Option<Ipv4Addr> = None;
    let mut src_v6: Option<Ipv6Addr> = None;
    let mut dst_v6: Option<Ipv6Addr> = None;
    let mut src_port: Option<u16> = None;
    let mut dst_port: Option<u16> = None;
    let mut protocol: u8 = 0;
    let mut in_if: Option<u32> = None;
    let mut out_if: Option<u32> = None;
    let mut src_as: Option<u32> = None;
    let mut dst_as: Option<u32> = None;
    let mut direction: Option<u8> = None;
    let mut in_bytes: u64 = 0;
    let mut out_bytes: u64 = 0;
    let mut in_pkts: u64 = 0;
    let mut out_pkts: u64 = 0;

    for &(ftype, flen) in &template.fields {
        let flen = flen as usize;
        // Defensive: the record is exactly template.record_len, so this holds,
        // but guard anyway — never slice out of bounds.
        if off + flen > record.len() {
            return None;
        }
        let f = &record[off..off + flen];
        off += flen;
        match ftype {
            F_IN_BYTES => in_bytes = be_uint(f),
            F_OUT_BYTES => out_bytes = be_uint(f),
            F_IN_PKTS => in_pkts = be_uint(f),
            F_OUT_PKTS => out_pkts = be_uint(f),
            F_PROTOCOL => protocol = be_uint(f) as u8,
            F_L4_SRC_PORT => src_port = Some(be_uint(f) as u16),
            F_L4_DST_PORT => dst_port = Some(be_uint(f) as u16),
            F_INPUT_SNMP => in_if = Some(be_uint(f) as u32),
            F_OUTPUT_SNMP => out_if = Some(be_uint(f) as u32),
            F_SRC_AS => src_as = Some(be_uint(f) as u32),
            F_DST_AS => dst_as = Some(be_uint(f) as u32),
            F_DIRECTION => direction = Some(be_uint(f) as u8),
            F_IPV4_SRC_ADDR if flen == 4 => src_v4 = Some(Ipv4Addr::new(f[0], f[1], f[2], f[3])),
            F_IPV4_DST_ADDR if flen == 4 => dst_v4 = Some(Ipv4Addr::new(f[0], f[1], f[2], f[3])),
            F_IPV6_SRC_ADDR if flen == 16 => src_v6 = Some(ipv6_from(f)),
            F_IPV6_DST_ADDR if flen == 16 => dst_v6 = Some(ipv6_from(f)),
            _ => {} // unknown / unused field: already advanced.
        }
    }

    let (src_addr, dst_addr) = match (src_v4, dst_v4, src_v6, dst_v6) {
        (Some(s), Some(d), _, _) => (IpAddr::V4(s), IpAddr::V4(d)),
        (_, _, Some(s), Some(d)) => (IpAddr::V6(s), IpAddr::V6(d)),
        // Partial/absent addressing: not a flow we can attribute. Skip.
        _ => return None,
    };

    Some(FlowRecord {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        protocol,
        in_if_index: in_if,
        out_if_index: out_if,
        src_as,
        dst_as,
        direction,
        // Cisco exports per-direction counters; a record carries one direction's
        // (in OR out). Sum so we don't lose the populated side. `saturating_add`
        // because both operands are attacker-controlled u64 wire fields: a raw
        // `+` panics in debug / wraps in release on a crafted maximal counter.
        bytes: in_bytes.saturating_add(out_bytes),
        pkts: in_pkts.saturating_add(out_pkts),
    })
}

/// Scan an options DATA record for a sampling interval (best-effort). Returns the
/// first sampling field value found, treated as the sampling rate (1-in-N).
fn parse_options_data(body: &[u8], template: &Template) -> Option<u32> {
    let rec = template.record_len;
    if rec == 0 || body.len() < rec {
        return None;
    }
    // Only the first record is needed — the sampler mapping is identical across
    // records in a single options data set.
    let record = &body[0..rec];
    let mut off = 0usize;
    for &(ftype, flen) in &template.fields {
        let flen = flen as usize;
        if off + flen > record.len() {
            return None;
        }
        let f = &record[off..off + flen];
        off += flen;
        if ftype == F_SAMPLING_INTERVAL || ftype == F_FLOW_SAMPLER_RANDOM_INTERVAL {
            let v = be_uint(f) as u32;
            if v >= 1 {
                return Some(v);
            }
        }
    }
    None
}

fn ipv6_from(f: &[u8]) -> Ipv6Addr {
    let mut o = [0u8; 16];
    o.copy_from_slice(&f[..16]);
    Ipv6Addr::from(o)
}

#[cfg(test)]
mod tests {
    use super::{Template, TemplateCache, MAX_TEMPLATES};

    fn dummy() -> Template {
        Template {
            fields: vec![(1, 4)],
            record_len: 4,
            is_options: false,
        }
    }

    #[test]
    fn template_cache_is_bounded_under_key_churn() {
        // A hostile/buggy exporter varying the wire-controlled source_id must not
        // grow the cache without limit (whole-process OOM). Insert well past the
        // cap with distinct keys and confirm it stays bounded.
        let mut cache = TemplateCache::new();
        for i in 0..(MAX_TEMPLATES as u32 + 500) {
            cache.insert(i, (i % 512) as u16, dummy());
        }
        assert!(
            cache.len() <= MAX_TEMPLATES,
            "template cache exceeded cap: {}",
            cache.len()
        );
    }
}
