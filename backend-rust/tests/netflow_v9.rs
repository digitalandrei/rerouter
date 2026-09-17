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
    header_at(source_id, sequence, 123_456, 1_700_000_000)
}

fn header_at(source_id: u32, sequence: u32, uptime: u32, unix_secs: u32) -> PacketBuilder {
    let mut p = PacketBuilder::default();
    p.u16(9) // version
        .u16(1) // count (advisory)
        .u32(uptime)
        .u32(unix_secs)
        .u32(sequence)
        .u32(source_id);
    p
}

fn template_flowset(template_id: u16, fields: &[(u16, u16)]) -> Vec<u8> {
    let mut inner = PacketBuilder::default();
    inner.u16(template_id).u16(fields.len() as u16);
    for &(kind, len) in fields {
        inner.u16(kind).u16(len);
    }
    let mut fs = PacketBuilder::default();
    fs.u16(0)
        .u16((4 + inner.body.len()) as u16)
        .bytes(&inner.body);
    fs.body
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
    while rec.body.len() % 4 != 0 {
        rec.u8(0);
    }
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
    assert_eq!(r.pkts, Some(1000));
    assert_eq!(r.bytes, Some(64000));
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
    assert_eq!(
        d1.data_without_template, 1,
        "undecodable data must be counted, not errored"
    );

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
        rec.bytes(&[10, 0, 0, 1])
            .bytes(&[10, 0, 0, 2])
            .u16(1)
            .u16(2)
            .u8(6)
            .u32(3)
            .u32(5)
            .u32(500);
        rec.body
    };
    data.bytes(&one).bytes(&one);
    while data.body.len() % 4 != 0 {
        data.u8(0);
    }
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
    while inner.body.len() % 4 != 0 {
        inner.u8(0);
    }
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
    assert_eq!(
        d.records.len(),
        0,
        "options data carries metadata, not flows"
    );
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
fn missing_packet_counter_remains_unavailable_but_measured_zero_is_present() {
    let fields = &[(8, 4), (12, 4), (10, 4), (1, 4)];
    let mut record = PacketBuilder::default();
    record
        .bytes(&[192, 0, 2, 1])
        .bytes(&[198, 51, 100, 2])
        .u32(7)
        .u32(0);
    let mut data = PacketBuilder::default();
    data.u16(300)
        .u16((4 + record.body.len()) as u16)
        .bytes(&record.body);
    let mut packet = header(42, 1);
    packet
        .bytes(&template_flowset(300, fields))
        .bytes(&data.body);
    let mut cache = TemplateCache::new();
    let decoded = decode(&packet.body, &mut cache).expect("decode");
    assert_eq!(decoded.records[0].bytes, Some(0));
    assert_eq!(decoded.records[0].pkts, None);
}

#[test]
fn exporter_restart_invalidates_old_template_generation() {
    let mut cache = TemplateCache::new();
    let mut learned = header_at(42, 100, 500_000, 1_700_000_000);
    learned.bytes(&flow_template_flowset(256));
    decode(&learned.body, &mut cache).expect("learn");

    let mut after_restart = header_at(42, 1, 2_000, 1_700_000_010);
    after_restart.bytes(&flow_data_flowset(256));
    let decoded = decode(&after_restart.body, &mut cache).expect("restart datagram");
    assert!(decoded.exporter_restarted);
    assert_eq!(decoded.records.len(), 0);
    assert_eq!(decoded.data_without_template, 1);
}

#[test]
fn reorder_and_uptime_wrap_preserve_current_templates() {
    let mut cache = TemplateCache::new();
    let mut learned = header_at(7, u32::MAX - 5, u32::MAX - 30_000, 1_700_000_000);
    learned.bytes(&flow_template_flowset(256));
    decode(&learned.body, &mut cache).expect("learn");

    let mut wrapped = header_at(7, 2, 10_000, 1_700_000_010);
    wrapped.bytes(&flow_data_flowset(256));
    let decoded = decode(&wrapped.body, &mut cache).expect("wrap");
    assert!(!decoded.exporter_restarted);
    assert_eq!(decoded.records.len(), 1);

    let mut reordered = header_at(7, 1, 9_500, 1_700_000_009);
    reordered.bytes(&flow_data_flowset(256));
    assert_eq!(
        decode(&reordered.body, &mut cache)
            .expect("reorder")
            .records
            .len(),
        1
    );
}

#[test]
fn stale_template_expires_without_refresh() {
    let mut cache = TemplateCache::new();
    let mut learned = header_at(5, 1, 100_000, 1_700_000_000);
    learned.bytes(&flow_template_flowset(256));
    decode(&learned.body, &mut cache).expect("learn");
    let mut stale = header_at(5, 2, 2_000_000, 1_700_001_801);
    stale.bytes(&flow_data_flowset(256));
    let decoded = decode(&stale.body, &mut cache).expect("decode stale");
    assert_eq!(decoded.records.len(), 0);
    assert_eq!(decoded.data_without_template, 1);
}

#[test]
fn invalid_flowset_framing_is_rejected() {
    let mut cache = TemplateCache::new();
    let mut truncated = header(1, 1);
    truncated.u16(256).u16(100);
    assert!(matches!(
        decode(&truncated.body, &mut cache),
        Err(FlowError::TruncatedFlowset { .. })
    ));

    let mut unaligned = header(1, 2);
    unaligned.u16(256).u16(5).u8(0);
    assert_eq!(
        decode(&unaligned.body, &mut cache),
        Err(FlowError::UnalignedFlowset(5))
    );

    let mut bad_padding = header(1, 3);
    bad_padding.bytes(&[1, 2]);
    assert_eq!(
        decode(&bad_padding.body, &mut cache),
        Err(FlowError::BadPadding(2))
    );
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
    assert_eq!(
        (s.rate, s.source, s.high_confidence),
        (1, SamplingSource::Default, true)
    );

    // Nothing known but an assumed >1 default -> low confidence (blocks auto-actions).
    let s = resolve_sampling(None, None, None, 1000);
    assert_eq!(
        (s.rate, s.source, s.high_confidence),
        (1000, SamplingSource::Default, false)
    );
}
