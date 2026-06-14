//! NetFlow v9 decoder tests, using hand-built datagrams (no socket required).
//! Doctrine: telemetry parsers must NEVER panic and must return structured
//! errors. These cover template caching, the data-before-template gap, sampling
//! extraction from options templates, the sampling-rate precedence, and a fuzz
//! sweep asserting no malformed input ever panics.

use std::net::IpAddr;

use rerouter_controller::telemetry::flow::v9::{decode, FlowError, TemplateCache};
use rerouter_controller::telemetry::flow::{resolve_sampling, SamplingSource};

// --- packet builder -------------------------------------------------------

#[derive(Default)]
struct PacketBuilder {
    body: Vec<u8>,
}

impl PacketBuilder {
    fn u8(&mut self, v: u8) -> &mut Self {
        self.body.push(v);
        self
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.body.extend_from_slice(&v.to_be_bytes());
        self
    }
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.body.extend_from_slice(v);
        self
    }
}

/// Build a v9 header. `count` is advisory (the decoder iterates by length).
fn header(source_id: u32, sequence: u32) -> PacketBuilder {
    let mut p = PacketBuilder::default();
    p.u16(9) // version
        .u16(1) // count (advisory)
        .u32(123_456) // sys_uptime
        .u32(1_700_000_000) // unix_secs
        .u32(sequence)
        .u32(source_id);
    p
}

/// The 8-field flow template used across tests. record_len = 25.
fn flow_template_flowset(template_id: u16) -> Vec<u8> {
    let fields: &[(u16, u16)] = &[
        (8, 4),  // IPV4_SRC_ADDR
        (12, 4), // IPV4_DST_ADDR
        (7, 2),  // L4_SRC_PORT
        (11, 2), // L4_DST_PORT
        (4, 1),  // PROTOCOL
        (10, 4), // INPUT_SNMP
        (2, 4),  // IN_PKTS
        (1, 4),  // IN_BYTES
    ];
    let mut inner = PacketBuilder::default();
    inner.u16(template_id).u16(fields.len() as u16);
    for &(t, l) in fields {
        inner.u16(t).u16(l);
    }
    let len = 4 + inner.body.len() as u16; // + flowset header
    let mut fs = PacketBuilder::default();
    fs.u16(0).u16(len).bytes(&inner.body);
    fs.body
}

/// One data record matching `flow_template_flowset`.
fn flow_data_flowset(template_id: u16) -> Vec<u8> {
    let mut rec = PacketBuilder::default();
    rec.bytes(&[192, 0, 2, 1]) // src
        .bytes(&[198, 51, 100, 2]) // dst
        .u16(40000) // src port
        .u16(53) // dst port (DNS)
        .u8(17) // UDP
        .u32(7) // input snmp ifIndex
        .u32(1000) // pkts
        .u32(64000); // bytes
    let len = 4 + rec.body.len() as u16;
    let mut fs = PacketBuilder::default();
    fs.u16(template_id).u16(len).bytes(&rec.body);
    fs.body
}

// --- tests ----------------------------------------------------------------

#[test]
fn template_then_data_decodes_one_flow() {
    let mut p = header(42, 1);
    p.bytes(&flow_template_flowset(256));
    p.bytes(&flow_data_flowset(256));

    let mut cache = TemplateCache::new();
    let d = decode(&p.body, &mut cache).expect("decode");
    assert_eq!(d.source_id, 42);
    assert_eq!(d.templates_learned, 1);
    assert_eq!(d.data_without_template, 0);
    assert_eq!(d.records.len(), 1);

    let r = &d.records[0];
    assert_eq!(r.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
    assert_eq!(r.dst_addr, "198.51.100.2".parse::<IpAddr>().unwrap());
    assert_eq!(r.src_port, Some(40000));
    assert_eq!(r.dst_port, Some(53));
    assert_eq!(r.protocol, 17);
    assert_eq!(r.in_if_index, Some(7));
    assert_eq!(r.pkts, 1000);
    assert_eq!(r.bytes, 64000);
    assert!(r.has_ports());
    // No DIRECTION field -> ingress on INPUT_SNMP.
    assert_eq!(r.attribution().1, Some(7));
}

#[test]
fn data_before_template_is_counted_then_decodes_after() {
    // Data set arrives with no template cached yet.
    let mut p1 = header(42, 1);
    p1.bytes(&flow_data_flowset(256));
    let mut cache = TemplateCache::new();
    let d1 = decode(&p1.body, &mut cache).expect("decode");
    assert_eq!(d1.records.len(), 0);
    assert_eq!(d1.data_without_template, 1, "undecodable data must be counted, not errored");

    // Template arrives.
    let mut p2 = header(42, 2);
    p2.bytes(&flow_template_flowset(256));
    let d2 = decode(&p2.body, &mut cache).expect("decode");
    assert_eq!(d2.templates_learned, 1);

    // Now the same data set decodes against the cached template.
    let mut p3 = header(42, 3);
    p3.bytes(&flow_data_flowset(256));
    let d3 = decode(&p3.body, &mut cache).expect("decode");
    assert_eq!(d3.records.len(), 1);
    assert_eq!(d3.data_without_template, 0);
}

#[test]
fn multiple_records_in_one_data_set() {
    let mut data = PacketBuilder::default();
    // two records back-to-back (50 bytes), flowset length = 4 + 50.
    let one = {
        let mut rec = PacketBuilder::default();
        rec.bytes(&[10, 0, 0, 1]).bytes(&[10, 0, 0, 2]).u16(1).u16(2).u8(6).u32(3).u32(5).u32(500);
        rec.body
    };
    data.bytes(&one).bytes(&one);
    let len = 4 + data.body.len() as u16;
    let mut fs = PacketBuilder::default();
    fs.u16(256).u16(len).bytes(&data.body);

    let mut p = header(1, 1);
    p.bytes(&flow_template_flowset(256));
    p.bytes(&fs.body);

    let mut cache = TemplateCache::new();
    let d = decode(&p.body, &mut cache).expect("decode");
    assert_eq!(d.records.len(), 2);
}

#[test]
fn options_template_reports_sampling_interval() {
    // Options template 257: scope SYSTEM(1, len4) + option SAMPLING_INTERVAL(34, len4).
    let mut inner = PacketBuilder::default();
    inner
        .u16(257) // template id
        .u16(4) // option_scope_length (bytes)
        .u16(4) // option_length (bytes)
        .u16(1) // scope field: SYSTEM
        .u16(4) // scope len
        .u16(34) // option field: SAMPLING_INTERVAL
        .u16(4); // option len
    let len = 4 + inner.body.len() as u16;
    let mut opt_tmpl = PacketBuilder::default();
    opt_tmpl.u16(1).u16(len).bytes(&inner.body); // flowset id 1 = options template

    // Options data set for template 257: scope value (4) + sampling interval (4).
    let mut rec = PacketBuilder::default();
    rec.u32(0).u32(1000); // 1-in-1000 sampling
    let dlen = 4 + rec.body.len() as u16;
    let mut opt_data = PacketBuilder::default();
    opt_data.u16(257).u16(dlen).bytes(&rec.body);

    let mut p = header(9, 1);
    p.bytes(&opt_tmpl.body).bytes(&opt_data.body);

    let mut cache = TemplateCache::new();
    let d = decode(&p.body, &mut cache).expect("decode");
    assert_eq!(d.reported_sampling, Some(1000));
    assert_eq!(d.records.len(), 0, "options data carries metadata, not flows");
}

#[test]
fn unsupported_version_is_structured_error() {
    let mut p = PacketBuilder::default();
    p.u16(5).u16(0).u32(0).u32(0).u32(0).u32(0); // looks like v5
    let mut cache = TemplateCache::new();
    match decode(&p.body, &mut cache) {
        Err(FlowError::UnsupportedVersion(5)) => {}
        other => panic!("expected UnsupportedVersion(5), got {other:?}"),
    }
}

#[test]
fn short_datagram_is_structured_error_not_panic() {
    let mut cache = TemplateCache::new();
    for n in 0..20usize {
        let buf = vec![0u8; n];
        match decode(&buf, &mut cache) {
            Err(FlowError::Short { .. }) => {}
            other => panic!("len {n}: expected Short error, got {other:?}"),
        }
    }
}

#[test]
fn malformed_input_never_panics() {
    // Deterministic pseudo-random sweep (no Math.random); every input must yield
    // a Result, never a panic, and must not loop forever.
    let mut cache = TemplateCache::new();
    let mut seed: u32 = 0x1234_5678;
    for _ in 0..5000 {
        let len = (seed % 200) as usize;
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            seed = seed.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            buf.push((seed >> 16) as u8);
        }
        // Force the version field to 9 half the time so we exercise the FlowSet
        // walker on garbage bodies, not just the version guard.
        if len >= 2 && seed & 1 == 0 {
            buf[0] = 0;
            buf[1] = 9;
        }
        let _ = decode(&buf, &mut cache); // must not panic
    }
}

#[test]
fn sampling_precedence_config_wins_over_reported() {
    // config override is authoritative even when the device reports a rate.
    let s = resolve_sampling(Some(100), Some(1000), Some(500), 1);
    assert_eq!(s.rate, 100);
    assert_eq!(s.source, SamplingSource::Config);
    assert!(s.high_confidence);
}

#[test]
fn sampling_precedence_reported_then_snmp_then_default() {
    let s = resolve_sampling(None, Some(1000), Some(500), 1);
    assert_eq!((s.rate, s.source), (1000, SamplingSource::Reported));

    let s = resolve_sampling(None, None, Some(500), 1);
    assert_eq!((s.rate, s.source), (500, SamplingSource::SnmpDerived));

    // Nothing known, default is unsampled (1:1) -> trustworthy.
    let s = resolve_sampling(None, None, None, 1);
    assert_eq!((s.rate, s.source, s.high_confidence), (1, SamplingSource::Default, true));

    // Nothing known but an assumed >1 default -> low confidence (blocks auto-actions).
    let s = resolve_sampling(None, None, None, 1000);
    assert_eq!((s.rate, s.source, s.high_confidence), (1000, SamplingSource::Default, false));
}
