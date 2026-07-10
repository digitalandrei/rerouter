# Flow Telemetry (NetFlow v9 / sFlow v5 / IPFIX) — design note

> **Status: implemented (NetFlow v9 + sFlow v5).** Passive collection, storage,
> API/UI, `flow_pps`/`flow_bps` detection, and tightly gated automatic signaling
> are in the tree; IPFIX (v10) is the planned additive decoder. The
> primary telemetry source remains **SNMP interface polling**
> ([telemetry-model.md](telemetry-model.md)); flow telemetry is a *second*,
> additive source that gives per-tuple visibility SNMP cannot. Code:
> `backend-rust/src/telemetry/flow/` (`v9.rs` + `sflow.rs` decoders,
> `collector.rs` listener), `src/api/flows.rs`, migration
> `20260614000300_flow_collector.sql`, frontend
> `frontend/src/pages/device-detail/flows-tab.tsx`. OFF by default
> (`[flow].enabled = false`; sFlow additionally gated by `[flow].sflow_enabled`);
> the migration is additive and not auto-applied to any running DB.

## Why

SNMP gives **volume** per interface (rx/tx bps & pps) but not **composition**:
which sources, which ports, which 5-tuples make up that volume. The motivating
case is a high-pps / low-bitrate flood — e.g. a UDP/53 reflection from peer A —
that barely moves the bitrate graph but is obvious as "N Mpps to dst port 53 on
ingress interface X". Flow telemetry is the base for that class of detector.

The collector itself is passive: it ingests and aggregates, and never sends a
packet to a router. Its buckets do feed detection. A flow rule can execute only
through the normal reroute engine and the additional flow-auto gates documented
below; observe mode and every standard reroute gate remain authoritative.

## Scope (v1)

- **Ingest** Cisco ASR 1004 export: **NetFlow v9** now. The decoder normalizes to
  an internal `FlowRecord` so **IPFIX (v10)** is an additive decoder later, not a
  rewrite (v9 and IPFIX share field semantics; they differ in header, set IDs —
  template/options `0`/`1` in v9 vs `2`/`3` in IPFIX — and variable-length
  encoding).
- **Retain** aggregated flow data for `[retention].flow_buckets_days` (default
  2 days / 48 hours), pruned by the unified `scheduler::retention_cleanup` alongside
  `interface_samples`. Note: per-minute flow buckets are high-cardinality
  (especially top-talker 5-tuples), so raising this materially increases disk use.
- **Display** per interface: top-10 talkers (5-tuples), top-10 ports, and
  per-interface/direction totals.
- **Implemented detection:** the latest closed interface bucket drives
  `flow_pps` and `flow_bps`; an optional protocol+port selector is evaluated at
  that same timestamp, so disappeared traffic becomes a current zero rather than
  a stale remembered value. Protocol-only selectors are rejected because no
  protocol-only rollup exists; legacy ambiguous rules are disabled by migration.
- **Out of scope (future):** per-tuple anomaly baselines, sFlow counter samples
  (they duplicate the SNMP path), sFlow extended-router AS records, and IPFIX.

> **sFlow v5 (`sflow.rs`).** A second, additive decoder feeding the *same*
> `FlowRecord` and all downstream aggregation/storage/API/UI. It differs from
> NetFlow v9 in two ways that shape the code: (1) it is **stateless** — the
> datagram is fixed XDR, so there is no template cache and no "data before
> template" gap; and (2) a flow sample carries a **raw packet header** (the first
> ~N bytes of the actual packet), not pre-aggregated counts, so the decoder parses
> Ethernet/802.1Q → IPv4/IPv6 → TCP/UDP/SCTP to build the tuple. Each sample is
> one packet: `pkts = 1`, `bytes = frame_length` (the on-wire length — L2-inclusive;
> the SNMP cross-cal tolerance already absorbs the L2/L3 delta). The
> `sampling_rate` is carried **reliably in every flow sample** (unlike NetFlow's
> unreliable options template), so it feeds the exporter's `reported` rate as
> high-confidence. Counter samples (type 2/4) are decoded-past and ignored in v1.
>
> **v1 uniform-rate caveat:** the collector resolves one effective rate per
> exporter per bucket. sFlow's rate is per-sample/per-interface; if an agent uses
> *different* rates on different interfaces, v1 assumes uniform (last-seen rate
> wins). Estimates stay faithful for uniform-rate agents (the norm) and for large
> aggregates; mixed-rate agents are noted as future work. Raw counts plus the
> stored `effective_sampling_rate` keep every estimate re-derivable if the rate is
> later corrected.

## Listener & configuration

The collector has its **own config block**, independent of the web/API binding.
The Rust API binds loopback-only and is never exposed; the flow listener, by
necessity, must receive UDP from the router, so it binds where the operator
chooses — this is a deliberate, documented exposure, off by default.

```toml
[flow]
enabled        = false          # off by default (master switch for the collector)
automatic_actions_enabled = false # separate acknowledgement for flow auto
bind_addr      = "0.0.0.0"      # inert while off; replace with explicit mgmt IP
bind_port      = 2055           # NetFlow v9 UDP port
sflow_enabled  = false          # bind the sFlow v5 listener too (needs enabled)
sflow_port     = 6343           # sFlow's default UDP port
# Only accept datagrams whose source IP resolves to an enrolled device. A packet
# from an unknown source is counted and dropped (never parsed into state).
allowlist_enrolled_only = true
bucket_seconds    = 60          # aggregation bucket width
top_k_talkers     = 100         # 5-tuples retained per bucket/interface/direction
default_sampling_rate = 1
snmp_corroboration_min_ratio = 0.25
snmp_corroboration_max_ratio = 2.0
```

When `enabled = true`, configuration validation rejects wildcard addresses such
as `0.0.0.0` and `::`; bind the collector to the explicit management-interface
address that receives exporter traffic. Enforce the same source boundary in the
host firewall.

Bucket retention is unified under `[retention].flow_buckets_days` (default 2 days / 48 hours),
not a `[flow]` setting.

NetFlow and sFlow bind **separate UDP ports** and run independent receive loops
that share the same in-memory state (exporter map, allowlist) and aggregate into
the same buckets. A datagram's protocol is fixed by the socket it arrived on, so
the decoder is chosen by port — no version-sniffing on a shared wire. Binding the
sFlow socket is best-effort: if it fails, NetFlow keeps running and only sFlow is
unavailable. The exporter row records `version` (9 = NetFlow v9, 5 = sFlow v5).

Safety rules for the listener (doctrine: parsers "never panic", structured
errors, low confidence blocks automatic actions):

- **Source-IP allowlist.** Only datagrams from enrolled `devices` (matched by
  `hostname`/management IP) are parsed. Everything else increments a drop counter
  and is discarded — no template state, no records.
- **Protocol/domain identity.** In-memory state and durable exporter rows are
  keyed by source address, wire protocol, and NetFlow observation-domain/sFlow
  sub-agent id. Templates and buckets cannot leak across those identities.
- **Never panic on malformed input.** Every decode step returns a structured
  error; a bad datagram is logged + counted and the loop continues. A
  single malformed packet must never take down the collector.
- **Bounded memory.** Template caches and in-flight bucket state are bounded;
  the long tail of 5-tuples is truncated to `top_k_talkers` *before* write (see
  truncation note below — it is logged, never silent).

## Interface mapping (free, reuse existing model)

NetFlow records carry input/output SNMP `ifIndex` (`INPUT_SNMP` 10 /
`OUTPUT_SNMP` 14). We already key `device_interfaces` on `(device_id, if_index)`.
So:

- exporter **source IP** → `devices` row → `device_id`;
- record **ifIndex** → `device_interfaces` row → `interface_id`.

Flows land on the *same* interface model the SNMP path and the rule engine
already use. A flow whose ifIndex is unknown (not yet discovered) is attributed to
the device with `interface_id = NULL` and still counted at device scope.

## Sampling — resolution & confidence

ASR Flexible NetFlow is typically **sampled**. The exporter *may* advertise the
rate via an options template (`FLOW_SAMPLER_ID` 48 / `FLOW_SAMPLER_MODE` 49 /
`FLOW_SAMPLER_RANDOM_INTERVAL` 50; IPFIX `samplingPacketInterval` 305 /
`samplingPacketSpace` 306), but on Cisco this is **unreliable** — the options
template may be sent rarely, late, or not at all, and data records may reference a
`samplerId` we have not yet resolved. So: parse it opportunistically, never depend
on it.

**Effective-rate precedence** (per exporter, recorded in `flow_exporters`):

1. **`config`** — operator-set override for this exporter. **Authoritative when
   set** (force), because a device can report a stale/wrong rate after a config
   change and operator intent must win.
2. **`reported`** — rate resolved from the exporter's options template.
3. **`snmp_derived`** — back-calculated by cross-checking against SNMP (below).
4. **`default`** — global `[flow]` default. If we fall through to here for a
   sampled-looking exporter, the exporter is flagged **low-confidence**.
5. **`unknown`** — no rate known yet → **low-confidence**, and flow-derived
   signals from this exporter must **not** feed automatic actions (doctrine).

Counts are stored as the **raw sampled** values *plus* the
`effective_sampling_rate` used, so an estimate is always re-derivable if the rate
is later corrected. The display/detection layer multiplies; any value scaled by a
rate > 1 is presented as **estimated**, not exact. Estimates are statistically
sound for large aggregates (an interface total, a port-53 flood) and noisy for the
long tail (a single sampled packet × rate) — the UI labels accordingly.

### SNMP cross-calibration

We poll `ifHC*` octet/packet counters on the *same* interfaces. Over a bucket
window we compare flow-estimated vs SNMP-measured volume on the same
`(device_id, if_index)`:

```text
observed_rate ≈ snmp_bytes_in_window / flow_sampled_bytes_in_window
```

This gives (a) a **sanity check** — if the flow estimate and SNMP disagree by
more than a configured factor, raise a "sampling rate likely wrong" flag on the
exporter; and (b) an **auto-derived rate** (`snmp_derived`) when nothing else is
available. It is a calibrator, not a hard source: SNMP and flow count slightly
different things (e.g. broadcast/multicast, L2 overhead), so a tolerance band
applies.

## Storage

Pre-aggregate into fixed-width time buckets (`bucket_seconds`, default 60); never
store raw flows — under the exact DDoS we want to catch, raw 5-tuple cardinality
is millions/hour. Four purpose-built, individually-bounded bucket tables, because
a single "top-K talkers" table would **miss a spoofed-source flood** (millions of
distinct src IPs, each tiny, all to dst/53 — truncating by talker loses them,
while the port rollup aggregates them all):

- **`flow_iface_buckets`** — per `(bucket, interface, direction)` totals
  (pkts/bytes/flow_count). Tiny. Drives per-interface totals and SNMP
  cross-calibration.
- **`flow_port_buckets`** — per `(bucket, interface, direction, protocol,
  port_kind, port)`. Bounded (≤ ~128k/bucket, in practice tiny). **This is what
  catches the port-53 spoofed flood**, since it aggregates across all source IPs.
- **`flow_talker_buckets`** — per `(bucket, interface, direction)` **top-K
  5-tuples only**. The long tail beyond `top_k_talkers` is dropped in memory
  before write; `flow_iface_buckets.flow_count` records how many flows existed so
  the UI shows "top 100 of N" — the truncation is surfaced, never silent.
- **`flow_as_buckets`** — per `(bucket, interface, direction, src/dst AS)` rollup
  (added with the flow-rule work). Bounded like the port table; drives AS-level
  views. Sampling confidence + effective rate are stored per row as elsewhere.

Each row stores raw sampled `pkts`/`bytes`, the `effective_sampling_rate` and
`sampling_confidence` in force, and `flow_count`. Retention: the unified
`scheduler::retention_cleanup` deletes `bucket_ts < now - flow_buckets_days` from
all four bucket tables (see [database.md](database.md#retention-defaults)).
`flow_exporters` is durable state (pruned only once idle past the flow bucket
window, so its cascade never removes still-retained buckets).

Top-N queries are then `ORDER BY SUM(bytes|pkts) DESC LIMIT 10` over the window,
grouped by the relevant dimension.

## Background task

A `flow::collector::run(pool, cfg)` task spawns from `scheduler::run()` alongside
`supervise` and `retention_cleanup` (the collector itself runs only when
`[flow].enabled`):

1. UDP recv loop → allowlist check → decode header → dispatch sets.
2. Template sets update the per-exporter template cache; options templates update
   the sampler state. Data records decode against the cached template (dropped +
   counted if the template is not yet known).
3. Decoded `FlowRecord`s fold into in-memory bucket accumulators keyed by the
   three dimensions above.
4. On bucket close, resolve the effective sampling rate, truncate talkers to
   top-K, and flush to the bucket tables in one transaction.
5. Expired buckets are trimmed by the central `scheduler::retention_cleanup`
   (not the collector), unified with `interface_samples` and `alerts` retention.

Templates are **in-memory** in v1: after a controller restart, data records are
dropped until each template is re-advertised (seconds-to-minutes). This gap is
logged; it is a telemetry blind spot, not a safety issue (no action depends on a
single bucket), and matches "never assume state survived a restart".

## API & UI

- `GET /api/devices/{id}/flows/top?dimension=talkers|ports|traffic&interface_id=&minutes=60`
  → ranked top-10 for the chosen dimension/window, each row carrying
  `estimated` + `sampling_confidence` so the UI can badge it.
- `GET /api/devices/{id}/flow-exporters` → exporter health: effective rate,
  source, confidence, last packet, dropped/unknown-template counters, SNMP
  cross-cal delta.
- UI: a **Flows** panel on the device/interface view — three ranked tables, with
  an "estimated (sampled N:1)" badge and a low-confidence warning when the rate is
  unknown or the SNMP cross-check disagrees.

## Detection hook (implemented)

Flow aggregates expose signals (dst-port pps, talker pps, unique-source count)
that the rule engine now thresholds directly — the `flow_pps` / `flow_bps` metrics
read the latest closed interface bucket in
`detection/engine.rs::flow_observation`; protocol+port rules narrow that same
bucket rather than selecting the last historical bucket that happened to match.
This is the home of the "big-pps / low-bps to port 53 from peer A" detector class. Flow-driven
**automatic** actions require all of the following: enforce mode; global and
per-rule enables; `[flow].automatic_actions_enabled = true`;
`allowlist_enrolled_only = true`; non-low sampling confidence; and a fresh,
same-direction SNMP sample on the same interface. Whole-interface flow estimates
must fit the configured minimum/maximum ratio to SNMP; filtered protocol+port
selectors must remain below the maximum because they are only a subset of the
interface total. SNMP and the flow bucket must also be contemporaneous.

This corroboration means forged UDP cannot act while the physical interface is
quiet. It does **not** cryptographically authenticate flow composition: spoofed
datagrams could still steer a target during a real high-volume event. Enforce
router-to-collector ACLs, source validation/uRPF, and management-plane isolation
before enabling flow auto. Deployments without those controls should keep
`automatic_actions_enabled = false` and use alerts/manual previews only.
