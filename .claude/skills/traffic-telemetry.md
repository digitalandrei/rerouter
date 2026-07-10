---
name: traffic-telemetry
description: How Rerouter collects and normalizes traffic telemetry — SNMP v2c interface polling plus passive NetFlow v9/sFlow collection, counter-rate derivation, wrap/reset handling, sampling-rate handling, and on-router verification.
---

# Skill: Traffic telemetry

Implementation guidance for the telemetry layer. See
[telemetry-model.md](../../docs/telemetry-model.md) (rate math) and
[flow-telemetry.md](../../docs/flow-telemetry.md) (the flow collector).
Everything is normalized **per monitored interface**, not per "asset".

## Sources

- **SNMP v2c interface polling — the primary source** (`telemetry::snmp`).
  Read-only and polled for every discovered interface. It supplies the
  authoritative per-interface volume used to corroborate flow automation.
- **NetFlow v9/sFlow collector — second source, off by default**
  (`telemetry::flow`). A passive UDP listener that adds per-tuple visibility
  (top talkers, ports, source ASNs) SNMP cannot provide. Sampled, so the
  sampling rate matters.

There is **no** continuous BGP feed and **no** Cloudflare analytics source in v1.

## SNMP rate derivation — primary path

Derive rates by differencing consecutive polls (`telemetry::interface_rates`),
preferring the 64-bit `ifHC*` counters (wrap is then extremely rare):

```text
rx_bps = ((cur_in_octets - prev_in_octets) * 8) / elapsed_seconds
rx_pps =  (cur_in_pkts   - prev_in_pkts)        / elapsed_seconds
rx_util_percent = rx_bps / if_speed_bps * 100      (ifHighSpeed×1e6, else ifSpeed)
```

Also surface `in_errors` / `out_errors` / `in_discards` / `out_discards` and
admin/oper status for display.

## Counter wrap / reset (SNMP)

```text
if current < previous:
    mark the sample invalid (valid_sample = 0), emit no rate
    keep the new raw counters as the next baseline regardless
    do NOT trigger rules from this derivative
```

The **first** poll of an interface has no baseline, so it is `valid_sample = 0`
too. Detection ignores invalid samples.

## NetFlow sampling rate — critical for the flow source

Flow is sampled (e.g. 1:1000). **Multiply** packet/byte counts by the sampling
rate to estimate real volume; store the rate per exporter and per sample. A wrong
or missing sampling rate is the #1 cause of false triggers from flow data. The
collector cross-calibrates flow volume against fresh same-interface SNMP
counters. Automatic flow actions require that corroboration in addition to the
independent flow-auto gate — see [flow-telemetry.md](../../docs/flow-telemetry.md).

## Staleness

Track poll health per device (`devices.reachable`, `last_poll_at`, `last_error`).
A device not polled within `telemetry.stale_after_seconds` (or never polled) makes
its interfaces' metrics stale; the detection engine stops evaluating thresholds
against stale values. Surface staleness in the UI.

## Verification (no feed)

Reroutes are verified by an **on-router `show` read-back** over SSH (the template's
`verification_json`), not by a telemetry feed — see
[bgp-reroute-safety](bgp-reroute-safety.md). A successful mitigation should also
show as a traffic drop on the monitored interface.

## Output (current tables)

- SNMP: write the latest to `interface_metrics_current` (one row/interface,
  carrying the raw `*_octets` / `*_pkts` counters that are the next delta baseline)
  and a retained history row to `interface_samples`. Keep raw vs derived separate.
- NetFlow: write bucketed rollups — `flow_iface_buckets`, `flow_port_buckets`,
  `flow_talker_buckets`, `flow_as_buckets` (top-K, exporters in `flow_exporters`).

There is no `asset_metrics_current` / `traffic_samples` table — that asset-era
schema was dropped (migration `20260614000100_drop_asset_provider_model.sql`).
Each normalized sample carries `valid_sample`, `sampled_at`, and (for flow) the
`sampling_rate`. Parsers return structured errors, never panic; keep a raw ref for
debugging.
