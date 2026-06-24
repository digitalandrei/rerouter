# Rerouter

A safety-critical DDoS-mitigation controller: it ingests traffic telemetry,
detects attacks, and moves production traffic by pushing validated commands to
network devices. It ships read-only by default. `docs/doctrine.md` is the source
of truth; this file is only the shared vocabulary the codebase and the agent
skills should use consistently.

## Language

### Core

**Reroute**:
A traffic-moving action executed against one device through a validated template.
Every reroute passes the safety gates, is persisted before and after each step,
and is verified by reading the resulting routing state.
_Avoid_: mitigation-action, remediation, fix.

**Action Template**:
The only sanctioned shape a reroute can take — a named command set with a
parameter schema and an optional verification `show`. Arbitrary command execution
is never a first-class feature.
_Avoid_: command, script, playbook.

**Operating Mode**:
`observe` (default) means read-only / alert-only — *nothing* executes, manual or
automatic; a fired rule renders the plan it *would* have run. `enforce` means
reroutes may execute. Mode flips are admin-only and audited.
_Avoid_: read-only-mode (say observe), live-mode (say enforce).

**Rerouter**:
The deep module that exposes `execute()` and orchestrates the Guard, the
two-phase state machine, and the SSH port behind one small interface.
_Avoid_: executor (now an internal phase), reroute-service, manager.

### Safety & execution

**Gate**:
A single safety precondition an execution must satisfy — operating mode, the
global maintenance lock, a device lock, a device/rule cooldown, the global rate
limit, the automatic master switch, verify-or-refuse, and the protected-interface
guard. Re-checked at execution time, never trusted from when the action was planned.
_Avoid_: check, validation, rule (rule means a Detection Rule).

**Reroute Guard**:
The module that owns every Gate and the atomic slot reservation, and answers
whether a reroute may execute. Splits a pure decision over gathered inputs from
the database reads behind it.
_Avoid_: validator, checker, gatekeeper.

**BlockReason**:
The typed reason the Guard refuses a reroute. Renders to a stable human string
for the API and UI.
_Avoid_: error, message string.

**SshExecutor**:
The port (seam) the Rerouter depends on to `apply` config in one session and
`verify_read` state in a separate read-only session. The russh transport — with
credential decryption, host-key pinning, and the fail-closed command allowlist —
is its real adapter; tests inject a fake.
_Avoid_: ssh-client, connection, transport (when you mean the port).

**Verification / Verdict**:
The read-back that confirms the routing state actually changed. A reroute is only
`succeeded` when the Verdict is `Pass`; an unconfirmable result is `Uncertain`.
"Command sent" is never treated as success.
_Avoid_: status-check, confirmation.

**Uncertain**:
The terminal state when a result cannot be confirmed. It locks the affected
device until an admin acknowledges it; controller startup also moves any
in-flight reroute to Uncertain.
_Avoid_: unknown, error, failed (failed means verification disproved the change).

**Device Lock**:
A hold on a device that blocks further reroutes until an admin acknowledges it
(e.g. after an Uncertain outcome or a crash).
_Avoid_: mutex, flag, freeze.

**Cooldown**:
A time window after an action during which the same device or rule will not
re-fire.
_Avoid_: debounce, throttle, backoff.

**Protected Interface**:
A management / transit / SSH path flagged so disruptive interface actions on it
are refused — the controller must not black-hole its own path to the device.
_Avoid_: critical-interface, reserved-interface.

**RTBH / Null0**:
The blackhole mitigation methods over Cisco IOS — a tagged-Null0 route the router
redistributes upstream (remote-triggered black hole), or a local Null0 null-route.
_Avoid_: drop-route, blackhole (name the method: RTBH or Null0).

### Telemetry & detection

**Telemetry Source**:
An ingestion stack producing per-interface metrics. SNMP v2c interface polling is
the primary (v1) source; the read-only NetFlow v9 collector is a second source,
off by default.
_Avoid_: monitor, poller (when you mean the source as a whole).

**Detection Rule**:
A persisted condition over telemetry that, when it fires (after its persistence
window / consecutive-sample requirement), raises an alert and — only with the
global and per-rule enables in enforce mode — triggers a reroute.
_Avoid_: alarm, trigger, alert (an alert is the *output* of a fired rule).
