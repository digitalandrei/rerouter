# Telemetry Model

Rerouter ingests telemetry, normalizes it per monitored **interface** (the v1
source) and derives the rates the detection engine evaluates. Telemetry may be
fast; actions are slow.

## Sources

### SNMP interface polling (NetFlow v9 / IPFIX / sFlow) — v1 source

The v1 telemetry source is **SNMP v2c interface polling** of enrolled devices
(routers). It is read-only — exactly what observe mode wants — and needs no
device-side flow configuration. See [device-enrollment.md](device-enrollment.md).

Each poll reads the 64-bit `ifXTable`/`ifTable` counters for every interface with
`enabled_for_monitoring = 1` and derives, per interface and per interval:

- bits/sec in & out (rx_bps, tx_bps) from `ifHCInOctets` / `ifHCOutOctets`;
- packets/sec in & out (rx_pps, tx_pps) from `ifHCInUcastPkts` / `ifHCOutUcastPkts`;
- link utilization % from the derived bps and `ifHighSpeed` (else `ifSpeed`);
- error/discard counters (`ifInErrors`, `ifOutErrors`, …) for display;
- admin/oper status (`ifAdminStatus` / `ifOperStatus`).

Prefer the 64-bit `ifHC*` counters; they make wrap extremely rare. SNMP gives
*volume* per interface — not attack composition (per-source / SYN-rate /
amplification breakdown). For that detail, **flow telemetry** (NetFlow v9 +
sFlow v5, **implemented**, off by default) is a second source: per-tuple
visibility, but sampled, so the **sampling rate** must be stored and applied (a
classic false-trigger cause). The read-only flow-collector — listener, sampling
resolution, SNMP cross-calibration, bucketed storage — is specified in
[flow-telemetry.md](flow-telemetry.md). Flow is a second source, not the v1 path.

### BGP routing context (SNMP + SSH)

BGP **peer state** is discovered over SNMP (`POST /api/devices/{id}/discover-bgp`
-> `device_bgp_peers`). Routing **context** — announced prefixes (`network`
statements) and neighbor labels parsed from `neighbor <ip> description` — is
discovered over SSH (`POST /api/devices/{id}/discover-prefixes`, via the
restricted Cisco view). This populates the prefix/neighbor pickers for guided
mitigation parameters.

A continuous BGP *feed* that tracks live announcement state per prefix
(announced/withdrawn, next-hop, communities) to **verify** reroutes is **future**:
v1 verifies a reroute with an on-router `show` check (see the template's
`verification_json`), not a feed.

### Cloudflare analytics (future / not implemented)

Not implemented in v1. Cloudflare is the CDN/front only, not a telemetry source
or a reroute provider. A future option: poll zone analytics / firewall events for
request rate and threat scores as an additional detection signal.

## Rate derivation

SNMP interface metrics are 64-bit counters. Derive rates by comparing consecutive
polls (implemented in `telemetry::interface_rates`):

```text
rx_bps = ((cur_in_octets  - prev_in_octets)  * 8) / elapsed_seconds
rx_pps =  (cur_in_pkts    - prev_in_pkts)         / elapsed_seconds
rx_util_percent = rx_bps / if_speed_bps * 100
```

Counter wrap / reset handling (`telemetry::rate_from_counters`):

- if current < previous, treat as reset/wrap;
- mark the whole sample **invalid** (`valid_sample = 0`) for rate calculation;
- keep the new raw counters as the next baseline regardless;
- never trigger threshold rules from an invalid derivative sample.

The first poll of an interface has no baseline, so it is `valid_sample = 0` too.

## Sample validity & freshness

Each normalized sample carries `valid_sample` and `sampled_at`. The detection
engine ignores stale or invalid samples. If polling fails, the device is marked
unreachable (`last_error`) and its interfaces' metrics go stale — **do not**
evaluate thresholds against the last (now stale) value.

## Stored metrics (per interface)

Minimum for v1:

```text
device reachability / poll health (devices.reachable, last_poll_at, last_error)
rx_bps, tx_bps
rx_pps, tx_pps
rx_util_percent, tx_util_percent
in_errors, out_errors, in_discards, out_discards
admin_status, oper_status
sampled_at, valid_sample
```

Keep raw vs derived values separate: the raw `*_octets` / `*_pkts` counters stay
in `interface_metrics_current` (they are the next delta baseline), never mixed
with the derived rates. Store the latest in `interface_metrics_current` and a
retained history in `interface_samples` (see [database.md](database.md)).

## Baselines (future, for anomaly rules)

> Not implemented in v1. The only "baseline" v1 keeps is the previous raw counter
> used for rate derivation (above); rules evaluate **absolute** thresholds against
> the derived rates. The rolling anomaly baseline below is future scaffolding.

A future rolling baseline (e.g. median bps/pps over a trailing window) would let
rules express "5× baseline for 60s" in addition to absolute thresholds. Such
baselines must be ignored while telemetry is stale or during an active reroute.
