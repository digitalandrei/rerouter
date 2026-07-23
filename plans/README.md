# Implementation Plans

## Active plans (2026-07-23 audit at `ef14aec`)

Full audit of doctrine, docs, skills, instructions, and codebase on 2026-07-23.
**Verdict: production-ready for the shipped observe-mode posture (GO).** The
ten-commit delta since 2026-07-21 is regression-free, all seven doctrine safety
invariants verified in code, docs/skills fresh. Three small non-blocking
findings became plans (owner selection); all three were executed by worktree
agents, reviewed, and merged to main on 2026-07-23 (`ee2fbee`, `aad3413`,
`94ad1ca`; merges `1406778`, `1c36216`, `9e8e145`).

| Plan | Title | Priority | Effort | Depends on | Status |
|------|-------|----------|--------|------------|--------|
| [011](011-document-release-gate.md) | Document the local release gate in operator docs | P2 | S | — | DONE |
| [012](012-supersede-ci-claims-in-audit-report.md) | Mark deleted CI as superseded in the 2026-07-10 audit report | P3 | S | 011 | DONE |
| [013](013-fix-context-glossary-rule-wording.md) | Fix CONTEXT.md Detection Rule glossary (flow rules window-only) | P3 | S | — | DONE |

Status values: TODO | IN PROGRESS | DONE | BLOCKED (with one-line reason) |
REJECTED (with one-line rationale).

Dependency note: 012 links to the "Release gate (local)" section that 011
creates in `docs/deployment.md`.

**Deferred (owner decision 2026-07-23, revisit when convenient):** frontend has
zero automated tests and no test runner (`frontend/package.json` — no `test`
script, no vitest/jest). Fix shape: Vitest + React Testing Library covering the
`RequireAuth`/`RequirePermission` gates and the manual-reroute preview-
invalidation UX. M effort; defense-in-depth only — all authority is enforced
server-side.

## Record of the 2026-07-21 run (production-readiness review at `25bee66`)

All ten plans from that run were **implemented, reviewed, merged to `main`
(`25bee66..ced6687`), and deployed to the customer box the same day** — their
plan files have been removed as completed. What shipped:

| Plan | Change | Landed as |
|------|--------|-----------|
| 001 | Recovery-code state errors fail loud, don't count toward lockout | `fix/001-recovery-code-fail-loud` |
| 002 | Step-up re-auth distinguishes a just-used login TOTP code | `fix/002-stepup-totp-reuse` |
| 003 | Maintenance/device locks re-checked inside the reservation critical section | `fix/003-reserve-slot-lock-recheck` |
| 004 | Flow collector open-bucket backlog capped (DB-outage OOM closed) | `fix/004-cap-flow-open-buckets` |
| 005 | CI actions pinned to commit SHAs | `fix/005-pin-ci-actions` (inert — CI later removed) |
| 006 | RustSec cargo-audit CI job | `fix/006-rustsec-ci` (inert — CI later removed) |
| 007 | Lock-ack anchor: #12 can't clear a legacy #123 lock | `fix/007-lock-ack-anchor` |
| 008 | `consecutive_samples` rejected on flow rules | `fix/008-flow-rules-window-only` |
| 009 | CF range updater: structural CIDR validation + nginx -t gate | `fix/009-cf-updater-validation` |
| 010 | Stability window 5 min → 1 min (owner request) | `feat/010-stability-window-1min` |

## Standing notes

- **No hosted CI** (owner decision 2026-07-21). The full gate is local-only:
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, DB-backed
  `cargo test --all-targets`, `npm run typecheck`, `npm run build` — run it
  before every release. Canonically documented in `docs/deployment.md` →
  "Release gate (local)" (plan 011).
- Dependency hygiene done 2026-07-21 (lockfile-only patch bumps: quinn-proto
  0.11.16, anyhow 1.0.104, spin 0.9.9, crypto-bigint 0.7.5; full gate re-run
  green). Run `cargo audit` manually each audit cycle. Two accepted remainders,
  both with no upstream fix as of 2026-07-21:
  - RUSTSEC-2023-0071 (rsa Marvin timing side-channel, via sqlx + russh).
    Accepted risk: MySQL is loopback-only and SSH targets the ACL-restricted
    management plane — an attacker positioned for timing measurements is
    already inside that boundary. Re-check for an upstream fix each cycle.
  - RUSTSEC-2024-0388 (`derivative` unmaintained, transitive) — informational.
- 009 required one revision round during execution (trailing-dot IPv4 CIDR
  slipped POSIX field splitting); fixed and re-verified.

## Findings considered and rejected (do not re-audit)

- Account enumeration via 401-vs-429 lockout response shape (`auth/mod.rs`):
  inherent to the per-account lockout design, pre-existing, low impact behind
  Cloudflare + IP throttle; needs an owner decision on design, not a patch.
- Four long-standing false positives re-confirmed as fine: literal-only SQL in
  sqlx macros; fail-closed 127.0.0.1 bind; u16-bounded flow-parser allocation;
  `.max(1)` division guard.
- SNMP v2c plaintext, SHA-1-first SSH profile, TOFU host keys, UDP flow
  exporter identity: documented residual risks / deliberate IOS-compatibility
  decisions (see `docs/audit-2026-07-10.md` §Residual risks).
- (2026-07-23) "In-app handbook states operator-configurable defaults as fixed
  prose" (`frontend/src/pages/Documentation.tsx` cooldown/token values): false
  positive — the cooldown section is literally headed "Default throttles", and
  the five-minute preview token is fixed in SQL (`api/mod.rs` `INTERVAL 5
  MINUTE`), not a config knob.
- (2026-07-23) `docs/audit-2026-07.md:253` cargo-audit mention: historical
  ("could not be run here"), accurate as written — only the 2026-07-10 report
  makes a present-tense CI claim (handled by plan 012).
