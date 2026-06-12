# Telemetry Model

Rerouter ingests traffic telemetry, normalizes it per protected asset, and derives
the rates the detection engine evaluates. Telemetry may be fast; actions are slow.

## Sources

The app supports multiple sources with priority and fallback.

### Flow telemetry (NetFlow v9 / IPFIX / sFlow) — primary

Preferred for volumetric and per-tuple visibility. From flow records, per asset
and per interval compute:

- bits/sec in & out (bps_in, bps_out);
- packets/sec in & out (pps_in, pps_out);
- new connections/sec, concurrent flows;
- SYN rate (and SYN/ACK ratio) for SYN-flood detection;
- unique source IP count, top source ASNs/prefixes;
- protocol/port distribution (to spot amplification: UDP/53, 123, 1900, 11211…).

Flow is sampled; **store and apply the sampling rate** so absolute bps/pps are
scaled correctly. A wrong sampling rate is a classic false-trigger cause.

### BGP feed

Track current announcement state per protected prefix (announced/withdrawn,
next-hop, communities). Needed to *verify* reroutes (did the blackhole/withdraw
actually take effect?) and to detect route changes.

### Cloudflare analytics

For Cloudflare-fronted assets, poll zone analytics / firewall events for request
rate, threat scores, and whether Under-Attack mode is active. Used both as a
detection signal and to verify Cloudflare-side reroutes.

## Rate derivation

Most signals are counters or sampled rates. When deriving rates from counters,
compare consecutive samples:

```text
bps_in  = ((cur_in_octets  - prev_in_octets)  * 8) / elapsed_seconds
pps_in  = (cur_in_packets - prev_in_packets) / elapsed_seconds
```

Counter wrap / reset handling:

- if current < previous, treat as reset/wrap;
- mark the sample **invalid** for rate calculation;
- keep the new value as the new baseline;
- never trigger threshold rules from an invalid derivative sample.

## Sample validity & freshness

Each normalized sample carries: `method`, `valid_sample`, `sampled_at`, and a
staleness flag. The detection engine ignores stale or invalid samples. If
telemetry stops, mark the asset's telemetry stale and **do not** evaluate traffic
thresholds against the last (now stale) value.

## Stored metrics (per asset)

Minimum for v1:

```text
asset reachability / telemetry health
rx_bps, tx_bps
rx_pps, tx_pps
new_conns_per_sec
syn_rate, syn_ack_ratio
unique_src_count
top_src_asn / top_dst_port (compact summary)
last_sample_age
telemetry method used
sample validity
```

Keep raw vs derived values separate; never mix a directly-reported rate with a
counter-derived one silently. Store the latest in `asset_metrics_current` and a
retained history in `traffic_samples` (see [database.md](database.md)).

## Baselines (optional, for anomaly rules)

Maintain a rolling baseline (e.g. median bps/pps over a trailing window) so rules
can express "5× baseline for 60s" in addition to absolute thresholds. Baselines
must be ignored while telemetry is stale or during an active reroute.
