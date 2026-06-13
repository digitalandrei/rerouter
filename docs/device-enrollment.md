# SNMP Device Enrollment

The v1 telemetry source is **SNMP v2c interface polling** of network **devices**
(routers — Cisco ASR and any standards-compliant SNMP agent). A device exposes
**interfaces**; the controller polls 64-bit interface counters, derives
per-interface rates, and feeds the [detection engine](detection-engine.md).
SNMP is read-only — exactly what observe mode wants.

See also [telemetry-model.md](telemetry-model.md) (the rate math) and
[database.md](database.md) (the `devices` / `device_interfaces` /
`interface_metrics_current` / `interface_samples` tables).

## Devices

A device row (`devices`) holds:

- name (unique), hostname (management IP or DNS name);
- `snmp_version` (`v2c` in v1; `v3` columns are reserved and return
  "unsupported");
- `snmp_port` (default 161);
- the SNMP **community**, encrypted at rest (AES-256-GCM, key from
  `SECRETS_KEY`) — only ciphertext is ever stored, and it is **never** returned
  by the API;
- `poll_interval_seconds` (default 30);
- learned identity (`vendor`, `model`, `os_version`, `sys_name`,
  `sys_uptime`) parsed from `sysDescr` at test/discover time;
- last poll outcome (`reachable`, `last_poll_at`, `last_error`). `reachable`
  defaults to 0 — telemetry is stale until a poll proves otherwise.

The community is a secret: it is sealed with `crypto::seal` on create/update and
opened only in memory by the poller. It is never logged and never serialized
back to a client.

## SSH access

A device is onboarded with **SSH access**, and SSH is **actively used** by the
controller — it is no longer an idle, enforce-only field. Even in observe mode the
controller uses SSH (through a restricted Cisco read-only view) to discover
routing context: announced prefixes and BGP neighbor labels
(`POST /api/devices/{id}/discover-prefixes`) and a command-access probe
(`POST /api/devices/{id}/ssh-capabilities`). In enforce mode the same SSH path
drives the device-CLI reroute templates. Every SSH command is checked against a
**fail-closed in-app allowlist**; the restricted view ships at
[../deploy/cisco/rerouter-bgp-view.ios](../deploy/cisco/rerouter-bgp-view.ios).

SSH auth is **password XOR key** (the operator picks one per device):

- `ssh_username`, `ssh_port` (default 22);
- `ssh_auth_method` — `password` or `key`;
- `password` method: `ssh_password` (encrypted at rest);
- `key` method: `ssh_private_key` + optional `ssh_key_passphrase` (both
  encrypted at rest);
- `ssh_host_fingerprint` — pinned at enrollment so a later host-key change can
  fail closed (doctrine §8 SSH host verification).

**In-app key generation.** Rather than pasting a private key, the operator can
have the controller mint a device keypair: `POST /api/devices/{id}/ssh-generate-key`
generates an **RSA** keypair (RSA, not ed25519, because Cisco IOS
`ip ssh pubkey-chain` only accepts RSA), stores the encrypted private key, and
saves the **public key** in `ssh_public_key`. That public key is **returned and
shown in the UI** so the operator can enroll it on the router via
`ip ssh pubkey-chain`.

All SSH secret material is AES-256-GCM ciphertext (key from `SECRETS_KEY`), the
same scheme as the community: only ciphertext is stored, nothing is logged, and
the API never returns the private material. `GET /api/devices` exposes only
`ssh_username`, `ssh_port`, `ssh_auth_method`, `ssh_configured` (a boolean —
whether a secret is stored), and the non-secret `ssh_public_key`. On `PUT`, an
omitted/empty secret leaves the stored value untouched; a present one
re-encrypts it.

> SSH is **optional** at enrollment: `ssh_auth_method` may be absent for an
> SNMP-only device, and added later via `PUT /api/devices/{id}`.

## Interfaces

Discovery walks `ifXTable` + `ifTable` and reconciles `device_interfaces` by
`(device_id, if_index)`: new interfaces are inserted, existing ones refreshed,
**without** disturbing the operator's `enabled_for_monitoring` choice. Per
interface: `if_name` (ifName), `if_descr` (ifDescr), `if_alias` (operator
label), `if_speed_bps` (ifHighSpeed×1e6, else ifSpeed), admin/oper status, a
physical-interface heuristic from ifType, and the monitoring flag.

**Only interfaces with `enabled_for_monitoring = 1` are polled and
rule-evaluated.** Discovering an interface does not start polling it; the
operator opts each one in.

## Enrollment flow

1. Operator adds the device: name, hostname, SNMP version/port, community, and
   optional SSH access (username + password **or** private key).
   `POST /api/devices` (requires `edit_asset`). The community and any SSH secret
   are encrypted before insert.
2. Operator runs a reachability/identity probe: `POST /api/devices/{id}/test`.
   The controller GETs `sysDescr`/`sysName`/`sysUpTime`, parses vendor/model/OS,
   and stores them; an unreachable device returns a clean structured error and
   is marked unreachable with `last_error` (no panic).
3. Operator runs discovery: `POST /api/devices/{id}/discover`. The controller
   walks the interface tables and upserts `device_interfaces`, returning the
   count discovered.
4. Operator enables monitoring on the interfaces of interest:
   `PUT /api/interfaces/{id}` `{ "enabled_for_monitoring": true }`.
5. The scheduler picks the device up (it reloads the enabled-device set
   periodically) and starts a per-device poll loop at `poll_interval_seconds`
   plus jitter. Each poll reads HC counters for the monitored interfaces,
   derives rates against the previous baseline, and stores
   `interface_metrics_current` (one row/interface, carrying the raw counters
   that form the next delta baseline) plus an `interface_samples` history row.
6. After each poll the detection engine evaluates that device's enabled
   interface rules.

## Polling, baselines, and validity

- The **first** poll of an interface has no baseline, so it produces no rate and
  is marked `valid_sample = 0`; it still stores the raw counters as the baseline
  for the next poll.
- A counter that goes **backwards** (wrap or device reboot) invalidates that
  sample (`valid_sample = 0`, no rate emitted), but the new raw counters are
  always stored as the next baseline. Detection ignores invalid samples.
- A transport-level failure marks the whole device unreachable (telemetry
  stale) with `last_error`; a per-interface gap only skips that interface.
- Per-device poll loops are independent and supervised: one device failing
  never stops the others, and the device list is reloaded so adding/removing or
  enabling/disabling a device takes effect without a restart.

## Rules on interfaces

A detection rule may target a **monitored interface** (XOR a protected asset).
Interface metrics: `rx_bps`, `tx_bps`, `rx_pps`, `tx_pps`, `rx_util_percent`,
`tx_util_percent`, `oper_status`. Operators `>`, `<`, `>=`, `<=`, `==`, `!=`.
A firing rule never executes a reroute in observe mode (the shipped default);
when a reroute template is attached, the alert carries the **would-run plan**
instead. See [detection-engine.md](detection-engine.md).

## Status & safety

- The community is encrypted at rest; it never appears in logs or API responses.
- The controller binds the API to loopback only; SNMP polling is outbound to the
  device's management address.
- `v3` is a typed stub in v1 (`unsupported`); only `v2c` is implemented.
- Telemetry staleness: an enabled device not polled within
  `telemetry.stale_after_seconds` (or never polled) counts toward
  `telemetry_stale_count` on `GET /api/status`, and stale samples are excluded
  from rule evaluation.
