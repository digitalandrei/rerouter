# Asset & Provider Enrollment

> **Not implemented in v1.** This asset/provider enrollment model was superseded
> by **device enrollment** — see [device-enrollment.md](device-enrollment.md).
> v1 enrolls **devices** (routers) and polls their **interfaces** over SNMP;
> reroutes run as device-CLI templates over SSH. There are no provider adapters
> (Cloudflare / BGP-RTBH / FlowSpec / scrubber) and no `/api/assets` or
> `/api/providers` endpoints. This document is retained for design context only;
> the `protected_assets` / `reroute_providers` tables survive merely as legacy
> foreign keys.

Rerouter protects **assets** (prefixes / IPs / services) by rerouting through
**providers** (Cloudflare, BGP upstreams, scrubbing centers). Both are enrolled
explicitly.

## Protected assets

Fields:

- name;
- prefix or IP (CIDR, IPv4/IPv6);
- service description / owner;
- site / region;
- criticality (operator-facing blast-radius label);
- enabled / disabled;
- telemetry sources enabled (flow, BGP, Cloudflare zone);
- baseline traffic profile (learned bps/pps, optional);
- `auto_reroute_eligible` (default **false** — must be explicitly opted in);
- last status, last successful telemetry timestamp, last failure reason.

### Enrollment flow

1. Admin adds the asset name and prefix/IP.
2. Admin selects telemetry sources (flow exporter, BGP, Cloudflare zone).
3. Admin links the providers eligible to reroute this asset.
4. System tests telemetry reception and provider reachability.
5. System learns a short traffic baseline (optional, for anomaly rules).
6. Admin selects which assets are monitored and assigns rules.
7. Admin optionally opts the asset into automatic reroutes (off by default).
8. Asset becomes active.

## Reroute providers

A provider is a channel we can reroute through. Types:

- **cloudflare** — zone(s), API token reference, available features
  (under-attack, firewall rules, rate-limit, magic-transit).
- **bgp_rtbh** — BGP session to an upstream that honors a blackhole community;
  store the community value(s) and which prefixes/lengths are permitted.
- **flowspec** — BGP FlowSpec-capable upstream; store supported actions
  (drop / rate-limit / redirect).
- **scrubber** — scrubbing-center diversion details (announce target, return path,
  contract limits).

Fields:

- name, type, enabled;
- connection details per type (API endpoint, BGP peer, ASN, communities);
- credential reference;
- capabilities (discovered/configured);
- health status, last successful operation, last failure reason;
- `actions_enabled` (must be explicitly enabled to execute any reroute).

### Provider safety

- Never reroute through a provider unless it is explicitly `actions_enabled`.
- Never blackhole/withdraw a prefix unless the prefix is within the provider's
  permitted ranges and the asset is `auto_reroute_eligible` (for automatic) or the
  operator has `trigger_manual_reroute` (for manual).
- Always verify the resulting routing/zone state after acting — see
  [reroute-engine.md](reroute-engine.md).

## Status model

Asset/provider status states:

```text
unknown  ok  degraded  unreachable  auth_failed  telemetry_failed  action_failed  locked
```

Track network reachability, telemetry health, and provider auth separately. An
asset can be reachable while flow telemetry has stopped — mark telemetry stale and
do not evaluate traffic thresholds against stale values.
