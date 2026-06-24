# Implementation brief — deepen the reroute core

> Handoff for an implementing agent (run via `/implement`). This is an
> implementation plan, **not doctrine** — delete it once merged. Source of truth
> stays `docs/doctrine.md`; vocabulary in `CONTEXT.md`; decision in
> `docs/adr/0001-reroute-core-seams.md`. Behavioral by design — find the current
> structure yourself; do not trust any line numbers.

## Agent Brief

**Category:** enhancement (architecture / testability refactor)
**Summary:** Restructure the reroute core around an `SshExecutor` port and a typed
`RerouteGuard` so the apply/verify state machine and the safety-gate precedence
are unit-testable without a real device or database — with **no change** to the
public reroute interface or its observable outcomes.

**Current behavior:**
A single `execute()` function in the reroute module renders the plan, runs every
safety gate inline (operating mode, dry-run, protected-interface, automatic
master switch, verify-or-refuse, global maintenance lock, device lock, device and
rule cooldowns, global rate limit), reserves a slot under a MariaDB `GET_LOCK`
advisory lock (re-checking "already running" and "uncertain" atomically with the
INSERT), then drives a two-phase state machine that pushes config and verifies it
over SSH. SSH is called as a free function that loads+decrypts credentials, pins
the host key (TOFU), enforces a fail-closed command allowlist, and runs the
session. Blocks are returned as free-text strings. The pure pieces (`judge`, the
no-verify-step decision, the command allowlist) are already unit-tested; the
state machine and gates are only reachable with a live device + database.

**Desired behavior:**
Same inputs, same `ExecOutcome`, same gate semantics and ordering — but the SSH
transport sits behind an injected port, the gates sit behind a typed guard with a
pure decision core, and the whole thing is reached through one `Rerouter` value.

### Key interfaces

- **`SshExecutor` port** — a trait with two methods that encode the session
  invariant:
  - `apply(device_id, commands) -> SshOutcome` — one ordered session; config-mode
    state must persist across the commands.
  - `verify_read(device_id, command) -> output` — a *separate, read-only* session
    for one `show`. The real adapter should refuse anything but a read here.
  - Real adapter (`RusshExecutor` or similar) holds the pool and keeps credential
    decryption, host-key TOFU pinning, and the fail-closed allowlist inside it.
    A hand-written test fake (no new dev-dependency) returns canned `SshOutcome`s
    and records what it was asked to run.
- **`RerouteGuard`** — owns every block and the reservation:
  - `can_execute(ctx) -> Result<(), BlockReason>` — all blocking gates.
  - `reserve_and_persist(req, plan) -> Result<RerouteId, BlockReason>` — owns the
    advisory-lock lifecycle and the atomic running/uncertain re-check + INSERT.
  - Internally split a **pure** `decide(GateInputs, trigger) -> Result<(), BlockReason>`
    from an async `gather()` that does the DB reads, so gate precedence is
    testable with no I/O.
- **`BlockReason`** — an enum that `Display`s to the **exact** strings `execute()`
  returns today (so `ExecOutcome.blocked_reason` / `.message` are byte-for-byte
  unchanged).
- **`Rerouter`** — holds the `SshExecutor`, pool, and config; exposes one public
  `execute(req, dry_run) -> ExecOutcome`. Provide a production constructor that
  builds the real SSH adapter and a test constructor that accepts an injected
  `SshExecutor`. `execute()` keeps only the two non-block returns (observe-mode →
  would-run plan, dry-run → rendered plan) and the orchestration; gating goes to
  the Guard, transport to the port. `judge`, the verdict→state mapping, and the
  no-verify-step decision stay pure.

### Sequencing (each step compiles and is green before the next)

1. **SSH port.** Extract the `SshExecutor` trait; wrap the existing russh code as
   the real adapter; route the state machine's apply and verify through it. Add
   the test fake and tests asserting outcomes from canned output and that verify
   ran in a separate read-only call.
2. **Reroute Guard.** Move the gates into `decide(GateInputs)` + `gather()` and
   `reserve_and_persist`; introduce `BlockReason` with the exact legacy strings;
   wire `execute()` to call the guard. Add the gate-precedence unit tests.
3. **Rerouter struct.** Fold pool/config/SSH/guard into `Rerouter`; reduce the
   public surface to `execute()`; update the call sites (manual reroute API and
   the detection engine's automatic path).

**Acceptance criteria:**
- [ ] `ExecOutcome` (executed/state/message/blocked_reason/would_run/...) is
      unchanged for every path: observe, dry-run, each block, succeeded, failed,
      uncertain. The manual-reroute API response and frontend are unaffected.
- [ ] Gate ordering and semantics are identical to today (same precedence; the
      automatic master switch and verify-or-refuse still gate automatic only).
- [ ] The double-apply guarantee still holds via the real advisory lock; the
      existing crash-recovery integration test still passes.
- [ ] **Tier-1 unit tests (no DB, always run):** `decide()` precedence matrix
      (maintenance > device lock > cooldown > rate limit; automatic-only gates;
      verify-or-refuse; protected-interface), `judge`, verdict→state, and the
      no-verify-step decision.
- [ ] **Tier-2 tests (CI-gated via the existing `pool_or_skip()` pattern):**
      `Rerouter` driven by the SSH fake covers succeeded / failed / uncertain
      (incl. the device lock created on uncertain) and asserts the exact commands
      and that verify used a separate read-only session.
- [ ] No new runtime dependencies; no new dev-dependency (the SSH fake is
      hand-written).
- [ ] `cargo test` and `cargo clippy` are clean.

**Out of scope:**
- The DB persistence/store seam — deliberately deferred (see ADR-0001). State
  writes stay on inline `sqlx`.
- Any change to the command allowlist, host-key TOFU, credential handling, or the
  set of gates and their thresholds.
- Operating-mode defaults and the automatic-reroute enables — untouched; this
  refactor must not weaken the observe-by-default posture.
- The other audit candidates (frontend transport seam, authorize+audit prologue,
  repository seam, etc.) — separate work.
