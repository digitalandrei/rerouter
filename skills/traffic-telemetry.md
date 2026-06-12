---
name: traffic-telemetry
description: How to collect and normalize traffic telemetry for Rerouter — NetFlow v9 / IPFIX / sFlow, sampling-rate handling, rate derivation, counter wrap/reset, and the BGP feed used for reroute verification.
---

# Skill: Traffic telemetry

Implementation guidance for the telemetry layer. See
[../docs/telemetry-model.md](../docs/telemetry-model.md) for the model.

## Flow protocols

- **NetFlow v9 / IPFIX** (template-based) and **sFlow** (packet-sampled).
- Listen on the configured UDP port(s); decode templates before data records
  (NetFlow v9/IPFIX carry templates you must cache per exporter).
- Each record yields src/dst IP, ports, proto, packets, bytes, TCP flags.

## Sampling rate — critical

Flow is sampled (e.g. 1:1000). **Multiply** packet/byte counts by the sampling
rate to estimate real volume. Store the rate per exporter and per sample. A wrong
or missing sampling rate is the #1 cause of false triggers and missed attacks.

## Derived signals (per asset, per interval)

```text
rx_bps / tx_bps          from bytes * 8 * sampling_rate / elapsed
rx_pps / tx_pps          from packets * sampling_rate / elapsed
new_conns_per_sec        new 5-tuples / elapsed
syn_rate                 count(TCP SYN, !ACK) * sampling_rate / elapsed
syn_ack_ratio            syn_ack / syn  (low ratio => SYN flood)
unique_src_count         distinct source IPs (sketch/HLL for scale)
top_src_asn / top_dst_port  compact summary for triage
```

## Counter wrap / reset (for counter-based sources)

```text
if current < previous:
    mark sample invalid for rate calc
    set baseline = current
    do NOT trigger rules from this derivative
```

## Staleness

Track `last_sample_age` per asset. Beyond a threshold, set `telemetry_stale` and
stop evaluating traffic thresholds (the detection engine already ignores stale
samples). Surface staleness in the UI.

## BGP feed

Maintain current announcement state per protected prefix (announced/withdrawn,
next-hop, communities) from the BGP session. This is what reroute **verification**
reads to confirm a blackhole/withdraw/divert actually took effect.

## Cloudflare analytics

For fronted assets, poll zone analytics + firewall events for request rate, threat
score, and whether Under-Attack mode is active — both a detection signal and a
verification source for Cloudflare-side reroutes.

## Output

Write `asset_metrics_current` (latest) and `traffic_samples` (retained), each with
`method`, `valid_sample`, `sampling_rate`, staleness. Keep raw vs derived separate.
Parsers return structured errors, never panic; keep a `raw_ref` for debugging.
