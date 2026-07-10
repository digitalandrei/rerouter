//! sFlow v5 decoder tests, using hand-built datagrams (no socket required).
//! Doctrine: telemetry parsers must NEVER panic and must return structured
//! errors. These cover the flow-sample header parse (Ethernet/802.1Q ->
//! IPv4/IPv6 -> TCP/UDP), the expanded flow-sample format, counter-sample and
//! malformed-record skipping, and a fuzz sweep asserting no input ever panics.

use std::net::IpAddr;

use rerouter_controller::telemetry::flow::sflow::{decode, SflowError};

// --- XDR builder ----------------------------------------------------------

fn u32b(v: u32) -> Vec<u8> {
    v.to_be_bytes().to_vec()
}

/// Wrap a payload as an XDR opaque<>: u32 length + bytes + pad to 4 bytes.
fn opaque(data: &[u8]) -> Vec<u8> {
    let mut out = u32b(data.len() as u32);
    out.extend_from_slice(data);
    let pad = (4 - (data.len() % 4)) % 4;
    out.resize(out.len() + pad, 0);
    out
}

/// sFlow v5 datagram header for an IPv4 agent, wrapping `samples`.
fn datagram(sub_agent: u32, sequence: u32, num_samples: u32, samples: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(u32b(5)); // version
    p.extend(u32b(1)); // address type = IPv4
    p.extend([10, 0, 0, 1]); // agent address
    p.extend(u32b(sub_agent));
    p.extend(u32b(sequence));
    p.extend(u32b(123_456)); // uptime
    p.extend(u32b(num_samples));
    p.extend_from_slice(samples);
    p
}

/// A raw-packet-header flow record (data_format 1) wrapping a parsed header.
fn raw_header_record(header_protocol: u32, frame_length: u32, header: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u32b(header_protocol));
    body.extend(u32b(frame_length));
    body.extend(u32b(0)); // stripped
    body.extend(opaque(header)); // header opaque<>
    let mut out = u32b(1); // data_format = raw packet header
    out.extend(opaque(&body));
    out
}

/// A standard (non-expanded) flow sample (sample_type 1) carrying `records`.
fn flow_sample(rate: u32, input: u32, output: u32, num_records: u32, records: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u32b(1)); // sample sequence
    body.extend(u32b(0)); // source_id
    body.extend(u32b(rate)); // sampling_rate
    body.extend(u32b(rate)); // sample_pool
    body.extend(u32b(0)); // drops
    body.extend(u32b(input)); // input ifIndex (format 0)
    body.extend(u32b(output)); // output ifIndex
    body.extend(u32b(num_records));
    body.extend_from_slice(records);
    let mut out = u32b(1); // sample_type = flow sample
    out.extend(opaque(&body));
    out
}

/// An expanded flow sample (sample_type 3).
fn flow_sample_expanded(rate: u32, input: u32, output: u32, records: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend(u32b(1)); // sample sequence
    body.extend(u32b(0)); // source_id_type
    body.extend(u32b(0)); // source_id_index
    body.extend(u32b(rate)); // sampling_rate
    body.extend(u32b(rate)); // sample_pool
    body.extend(u32b(0)); // drops
    body.extend(u32b(0)); // input format
    body.extend(u32b(input)); // input value
    body.extend(u32b(0)); // output format
    body.extend(u32b(output)); // output value
    body.extend(u32b(1)); // num_records
    body.extend_from_slice(records);
    let mut out = u32b(3); // sample_type = expanded flow sample
    out.extend(opaque(&body));
    out
}

// --- header builders ------------------------------------------------------

fn ipv4_udp(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.push(0x45); // version 4, IHL 5 (20 bytes)
    h.push(0); // tos
    h.extend(50u16.to_be_bytes()); // total length (advisory here)
    h.extend(0u16.to_be_bytes()); // id
    h.extend(0u16.to_be_bytes()); // flags/frag
    h.push(64); // ttl
    h.push(17); // protocol = UDP
    h.extend(0u16.to_be_bytes()); // checksum
    h.extend(src);
    h.extend(dst);
    h.extend(sport.to_be_bytes());
    h.extend(dport.to_be_bytes());
    h.extend(0u16.to_be_bytes()); // udp length
    h.extend(0u16.to_be_bytes()); // udp checksum
    h
}

fn ipv6_tcp(sport: u16, dport: u16) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend(0x6000_0000u32.to_be_bytes()); // version/class/label
    h.extend(20u16.to_be_bytes()); // payload length
    h.push(6); // next header = TCP
    h.push(64); // hop limit
    h.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src
    h.extend([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst
    h.extend(sport.to_be_bytes());
    h.extend(dport.to_be_bytes());
    h
}

/// Ethernet frame with optional VLAN tags, wrapping an L3 payload.
fn ethernet(vlan_tags: usize, ethertype: u16, l3: &[u8]) -> Vec<u8> {
    let mut h = Vec::new();
    h.extend([0, 0, 0, 0, 0, 1]); // dst MAC
    h.extend([0, 0, 0, 0, 0, 2]); // src MAC
    for _ in 0..vlan_tags {
        h.extend(0x8100u16.to_be_bytes()); // 802.1Q TPID
        h.extend(0u16.to_be_bytes()); // TCI
    }
    h.extend(ethertype.to_be_bytes());
    h.extend_from_slice(l3);
    h
}

// --- tests ----------------------------------------------------------------

#[test]
fn ethernet_ipv4_udp_flow_sample_decodes_one_record() {
    let l3 = ipv4_udp([192, 0, 2, 1], [198, 51, 100, 2], 40000, 53);
    let eth = ethernet(0, 0x0800, &l3);
    let rec = raw_header_record(1, 1500, &eth);
    let sample = flow_sample(2048, 7, 9, 1, &rec);
    let dg = datagram(42, 100, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.sub_agent_id, 42);
    assert_eq!(d.sequence, 100);
    assert_eq!(d.reported_sampling, Some(2048));
    assert_eq!(d.samples_total, 1);
    assert_eq!(d.records.len(), 1);

    let r = &d.records[0];
    assert_eq!(r.src_addr, "192.0.2.1".parse::<IpAddr>().unwrap());
    assert_eq!(r.dst_addr, "198.51.100.2".parse::<IpAddr>().unwrap());
    assert_eq!(r.src_port, Some(40000));
    assert_eq!(r.dst_port, Some(53));
    assert_eq!(r.protocol, 17);
    assert_eq!(r.in_if_index, Some(7));
    assert_eq!(r.out_if_index, Some(9));
    assert_eq!(r.bytes, 1500);
    assert_eq!(r.pkts, 1);
    assert!(r.has_ports());
    // No DIRECTION field -> ingress on the input ifIndex.
    assert_eq!(r.attribution().1, Some(7));
}

#[test]
fn vlan_tagged_ethernet_is_parsed() {
    let l3 = ipv4_udp([10, 1, 1, 1], [10, 2, 2, 2], 1234, 80);
    let eth = ethernet(1, 0x0800, &l3); // single 802.1Q tag
    let rec = raw_header_record(1, 800, &eth);
    let sample = flow_sample(1, 3, 4, 1, &rec);
    let dg = datagram(1, 1, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 1);
    let r = &d.records[0];
    assert_eq!(r.src_addr, "10.1.1.1".parse::<IpAddr>().unwrap());
    assert_eq!(r.dst_port, Some(80));
    assert_eq!(r.protocol, 17);
}

#[test]
fn ipv6_tcp_is_parsed() {
    let l3 = ipv6_tcp(50000, 443);
    let eth = ethernet(0, 0x86DD, &l3);
    let rec = raw_header_record(1, 120, &eth);
    let sample = flow_sample(512, 2, 0, 1, &rec);
    let dg = datagram(5, 5, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 1);
    let r = &d.records[0];
    assert_eq!(r.src_addr, "2001:db8::1".parse::<IpAddr>().unwrap());
    assert_eq!(r.dst_addr, "2001:db8::2".parse::<IpAddr>().unwrap());
    assert_eq!(r.src_port, Some(50000));
    assert_eq!(r.dst_port, Some(443));
    assert_eq!(r.protocol, 6);
    // output ifIndex 0 -> unknown.
    assert_eq!(r.out_if_index, None);
}

#[test]
fn expanded_flow_sample_decodes() {
    let l3 = ipv4_udp([203, 0, 113, 9], [192, 0, 2, 200], 5353, 5353);
    let eth = ethernet(0, 0x0800, &l3);
    let rec = raw_header_record(1, 64, &eth);
    let sample = flow_sample_expanded(4096, 11, 12, &rec);
    let dg = datagram(9, 9, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 1);
    let r = &d.records[0];
    assert_eq!(r.in_if_index, Some(11));
    assert_eq!(r.out_if_index, Some(12));
    assert_eq!(r.bytes, 64);
    assert_eq!(d.reported_sampling, Some(4096));
}

#[test]
fn raw_ipv4_header_protocol_without_ethernet() {
    // header_protocol 11 = IPv4: the header starts at the IP layer (no L2).
    let l3 = ipv4_udp([1, 1, 1, 1], [2, 2, 2, 2], 1, 2);
    let rec = raw_header_record(11, 40, &l3);
    let sample = flow_sample(1, 1, 1, 1, &rec);
    let dg = datagram(1, 1, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 1);
    assert_eq!(d.records[0].src_addr, "1.1.1.1".parse::<IpAddr>().unwrap());
}

#[test]
fn non_ip_ethernet_is_skipped() {
    // EtherType 0x0806 (ARP) -> no FlowRecord, sample counted as skipped.
    let eth = ethernet(0, 0x0806, &[0u8; 28]);
    let rec = raw_header_record(1, 64, &eth);
    let sample = flow_sample(1, 1, 1, 1, &rec);
    let dg = datagram(1, 1, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 0);
    assert_eq!(d.samples_total, 1);
    assert_eq!(d.samples_skipped, 1);
}

#[test]
fn counter_sample_is_ignored_not_fatal() {
    // sample_type 2 = counter sample: skipped, but flow samples still decode.
    let mut counter = u32b(2);
    counter.extend(opaque(&[0u8; 16]));
    let l3 = ipv4_udp([8, 8, 8, 8], [9, 9, 9, 9], 100, 200);
    let eth = ethernet(0, 0x0800, &l3);
    let rec = raw_header_record(1, 100, &eth);
    let flow = flow_sample(10, 1, 2, 1, &rec);
    let mut samples = counter;
    samples.extend(flow);
    let dg = datagram(1, 1, 2, &samples);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.samples_total, 2);
    assert_eq!(d.samples_skipped, 1); // the counter sample
    assert_eq!(d.records.len(), 1);
}

#[test]
fn truncated_l4_yields_record_without_ports() {
    // IPv4 header with the UDP ports chopped off: addresses survive, ports None.
    let mut l3 = ipv4_udp([5, 6, 7, 8], [9, 10, 11, 12], 1, 2);
    l3.truncate(20); // keep IPv4 header, drop L4.
    let eth = ethernet(0, 0x0800, &l3);
    let rec = raw_header_record(1, 60, &eth);
    let sample = flow_sample(1, 1, 1, 1, &rec);
    let dg = datagram(1, 1, 1, &sample);

    let d = decode(&dg).expect("decodes");
    assert_eq!(d.records.len(), 1);
    let r = &d.records[0];
    assert_eq!(r.protocol, 17);
    assert_eq!(r.src_port, None);
    assert_eq!(r.dst_port, None);
}

#[test]
fn unsupported_version_is_structured_error() {
    let mut dg = u32b(9); // looks like a NetFlow-ish version word
    dg.extend([0u8; 16]);
    match decode(&dg) {
        Err(SflowError::UnsupportedVersion(9)) => {}
        other => panic!("expected UnsupportedVersion(9), got {other:?}"),
    }
}

#[test]
fn short_datagram_is_structured_error_not_panic() {
    for n in 0..20usize {
        let dg = vec![0u8; n];
        // Either a structured error or an empty decode — never a panic.
        let _ = decode(&dg);
    }
}

#[test]
fn fuzz_random_bytes_never_panic() {
    // Deterministic LCG; no external rng. A truncated/hostile datagram must be a
    // structured error or a partial decode, never a panic.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    for _ in 0..5000 {
        let len = (s % 600) as usize;
        let mut dg = Vec::with_capacity(len);
        for _ in 0..len {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            dg.push((s >> 33) as u8);
        }
        // Force a valid version word on some iterations to exercise deeper paths.
        if len >= 4 && s & 1 == 0 {
            dg[0..4].copy_from_slice(&u32b(5));
        }
        let _ = decode(&dg);
    }
}
