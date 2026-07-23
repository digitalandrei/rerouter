# Plan 011: Document the local release gate in the operator docs

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ef14aec..HEAD -- docs/deployment.md docs/operations-runbook.md plans/README.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: dx
- **Planned at**: commit `ef14aec`, 2026-07-23

## Why this matters

This repo has **no hosted CI** — the GitHub Actions workflow was removed by
owner decision on 2026-07-21 (commit `1272ee2`). The only quality gate is a
sequence of local commands, and today that sequence is written down in exactly
one place: `plans/README.md` (a plan-history artifact operators never read).
The operator docs (`docs/deployment.md`, `docs/operations-runbook.md`) show how
to build but never say what must pass before a release ships. Documenting the
gate in `docs/deployment.md` makes the project instruction in `CLAUDE.md`
("add failure-path tests whenever a change touches execution, recovery, or
identity") enforceable in practice: there is a single documented "is it green?"
sequence.

## Current state

- `plans/README.md:24-31` — the only written record of the gate:

  ```
  - **No hosted CI** (owner decision 2026-07-21). The full gate is local-only:
    `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, DB-backed
    `cargo test --all-targets`, `npm run typecheck`, `npm run build` — run it
    before every release.
  ```

- `docs/deployment.md` — build instructions exist at lines 14–25 (the
  `cargo build --release` / `npm ci && npm run build` block) but no
  verification/gate section anywhere. Section headings, in order:
  `## Quick install (single binary) — the primary path` (line 12),
  `## CLI reference` (line 108), `## Single-binary UI` (line 130),
  `## Topology (production)` (line 146), `## Cloudflare` (line 157),
  `## Nginx (origin)` (line 187), `## systemd` (line 198),
  `## Environment & config` (line 213), `## Production install order` (line 238).

- `docs/operations-runbook.md` — headings end with `## Backups` (line 122) and
  `## Routine checks` (line 130). No mention of the release gate.

- DB-backed tests **skip silently** when `DATABASE_URL` is unset — see
  `backend-rust/tests/guard_reservation.rs:20-27`:

  ```rust
  /// Connect + migrate, or `None` when DATABASE_URL is unset (skip).
      let url = std::env::var("DATABASE_URL").ok()?;
  ```

  The gate doc MUST state this, otherwise `cargo test --all-targets` passing
  without a database gives false confidence (the six integration suites —
  `guard_reservation.rs`, `reachability_gate.rs`, `state_recovery.rs`,
  `snmp_rates.rs`, `netflow_v9.rs`, `sflow.rs` — all skip).

- Repo doc conventions: GitHub-flavored markdown, `##` sections, fenced `bash`
  blocks with comments, bold for emphasis. Match the style of the existing
  build block at `docs/deployment.md:18-25`.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Confirm gate text landed | `grep -n "Release gate" docs/deployment.md` | at least one match |
| Confirm runbook pointer | `grep -n "Release gate\|release gate" docs/operations-runbook.md` | at least one match |
| Docs-only change check | `git status --porcelain` | only in-scope files listed |

(This is a docs-only plan: do NOT run `cargo build`, `cargo test`, or `npm`
commands — nothing they check is being changed.)

## Scope

**In scope** (the only files you should modify):
- `docs/deployment.md`
- `docs/operations-runbook.md`
- `plans/README.md` (status row + one cross-reference line, step 3)

**Out of scope** (do NOT touch, even though they look related):
- `CLAUDE.md` — project instructions are owner-maintained; the gate belongs in
  operator docs, not agent instructions.
- Any `Makefile`/`justfile` creation — a runnable wrapper target was considered
  and deferred; this plan documents only.
- `.github/` — CI stays removed; do not recreate any workflow.
- The two dated audit reports (`docs/audit-2026-07*.md`) — plan 012 handles those.

## Git workflow

- Branch: `advisor/011-document-release-gate`
- Single commit; message style follows repo convention (see `git log`, e.g.
  `fix: document SPA deployment permissions`). Suggested:
  `docs: document the local release gate (no hosted CI)`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add a "Release gate (local)" section to `docs/deployment.md`

Insert a new section immediately **before** `## CLI reference` (currently
line 108). Content to add (adjust wording to flow, keep all five commands and
the DATABASE_URL caveat verbatim in spirit):

```markdown
## Release gate (local)

There is **no hosted CI** (owner decision, 2026-07-21). Before every release,
run the full gate locally and require all five to pass:

```bash
(cd backend-rust && cargo fmt --check)
(cd backend-rust && cargo clippy --all-targets -- -D warnings)
(cd backend-rust && DATABASE_URL="mysql://…/rerouter_test" cargo test --all-targets)
(cd frontend && npm run typecheck)
(cd frontend && npm run build)
```

The integration suites under `backend-rust/tests/` **skip silently when
`DATABASE_URL` is unset** — a green `cargo test` without a MariaDB test
database has not exercised reroute-guard, state-recovery, reachability, or
collector behavior. Point `DATABASE_URL` at a disposable MariaDB database
(the tests run migrations and write to it; never use the production DB).

Run `cargo audit` manually each audit cycle; accepted findings are recorded
in `plans/README.md`.
```

**Verify**: `grep -n "Release gate" docs/deployment.md` → one match, above the
`## CLI reference` heading (compare line numbers).

### Step 2: Cross-reference from the runbook

In `docs/operations-runbook.md`, under `## Routine checks` (currently line
130), add one bullet:

```markdown
- Before deploying any new build: run the full local release gate — see
  [Release gate (local)](deployment.md#release-gate-local). There is no hosted
  CI; nothing passes unless you run it.
```

**Verify**: `grep -n "release gate" docs/operations-runbook.md` (case-insensitive
if needed) → one match under Routine checks.

### Step 3: Point `plans/README.md` at the new canonical location

In `plans/README.md`, in the "Standing notes" bullet about the gate, append
one sentence: `Canonically documented in docs/deployment.md → "Release gate
(local)".` Then update this plan's status row to DONE.

**Verify**: `grep -n "Release gate" plans/README.md` → one match.

## Test plan

No code changes; no tests to write. Verification is the grep gates above plus
a human read-through of the new section for rendering (fenced block inside a
section renders correctly on GitHub — check the nested fence uses matching
backticks).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -c "Release gate" docs/deployment.md` ≥ 1
- [ ] `grep -ci "release gate" docs/operations-runbook.md` ≥ 1
- [ ] The five gate commands (`cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test --all-targets`, `npm run typecheck`, `npm run build`) all appear in the new section
- [ ] The DATABASE_URL skip caveat appears in the new section (`grep -n "skip" docs/deployment.md`)
- [ ] `git status --porcelain` shows only the three in-scope files modified
- [ ] `plans/README.md` status row for 011 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `docs/deployment.md` no longer has a `## CLI reference` heading, or the
  section layout differs materially from the "Current state" listing.
- A `Makefile`, `justfile`, or gate documentation already exists somewhere in
  `docs/` (someone landed this independently) — report instead of duplicating.
- `plans/README.md:24-31` no longer contains the gate command list (the
  source text this plan copies from).

## Maintenance notes

- If a gate command changes (e.g. a frontend test script is added by a future
  plan following the deferred TEST finding), update this section — it is now
  the canonical gate definition.
- Reviewer should check: the nested code fence renders, and the warning about
  silently-skipping DB tests is prominent — that caveat is the highest-value
  sentence in the change.
- Deferred: a runnable `just verify`-style wrapper (owner can request later).
