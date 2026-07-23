# Plan 013: Fix the CONTEXT.md Detection Rule glossary wording (flow rules are window-only)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ef14aec..HEAD -- CONTEXT.md`
> If the file changed since this plan was written, compare the "Current state"
> excerpt against the live file before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: docs
- **Planned at**: commit `ef14aec`, 2026-07-23

## Why this matters

Commit `3ccf5bd` (fix/008) made flow-rule persistence window-only: the rules
API returns 422 when `consecutive_samples > 0` is set on a flow rule. The
authoritative doc (`docs/detection-engine.md`) says so, but the shared-
vocabulary glossary in `CONTEXT.md` still defines a Detection Rule generically
as firing "after its persistence window / consecutive-sample requirement",
which an API integrator reading the glossary alone can take to mean either
mechanism applies to any rule. One reworded sentence removes the ambiguity.

## Current state

- `CONTEXT.md:111-116` — the entry to change, verbatim today:

  ```
  **Detection Rule**:
  A persisted condition over telemetry that, when it fires (after its persistence
  window / consecutive-sample requirement), raises an alert and — only with the
  global and per-rule enables in enforce mode, an automatic-capable template, and
  any source-specific confidence gates — triggers a reroute.
  _Avoid_: alarm, trigger, alert (an alert is the *output* of a fired rule).
  ```

- Ground truth, `backend-rust/src/api/rules.rs:412-421` (validation comment +
  rejection):

  ```rust
  // Flow rules use time-window persistence (duration_seconds); each tick
  // re-reads the same latest closed bucket, so consecutive_samples would
  // count poll ticks against unchanged evidence. Reject it here — the
  // consecutive-samples gate is SNMP-only.
  if body.consecutive_samples.is_some_and(|n| n > 0) {
      return Err((
          StatusCode::UNPROCESSABLE_ENTITY,
          "flow rules use duration_seconds persistence; consecutive_samples must be 0 or omitted".into(),
      ));
  ```

- Matching authoritative doc, `docs/detection-engine.md:79-84`: "…the rules API
  now **rejects** `consecutive_samples > 0` on flow rules … flow rules are
  window-only."

- Convention: CONTEXT.md glossary entries are one dense definition sentence
  plus an `_Avoid_:` line. Keep that shape; do not add a new paragraph.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Locate the entry | `grep -n "consecutive-sample requirement" CONTEXT.md` | exactly 1 match |
| Confirm fix | `grep -n "SNMP rules" CONTEXT.md` | ≥ 1 match in the Detection Rule entry |
| Docs-only change check | `git status --porcelain` | only in-scope files listed |

## Scope

**In scope** (the only files you should modify):
- `CONTEXT.md` (the Detection Rule entry only)
- `plans/README.md` (status row only)

**Out of scope** (do NOT touch):
- `docs/detection-engine.md` — already correct.
- `backend-rust/src/api/rules.rs` — ground truth, no change.
- Every other CONTEXT.md entry.

## Git workflow

- Branch: `advisor/013-context-glossary-rule-wording`
- Single commit, e.g. `docs: glossary — consecutive-samples is SNMP-only, flow rules window-only`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Reword the Detection Rule entry

In `CONTEXT.md`, replace the parenthetical in the Detection Rule definition so
the persistence mechanisms are attributed per source. Target shape:

```
**Detection Rule**:
A persisted condition over telemetry that, when it fires (after its persistence
requirement — a time window for flow rules, consecutive samples for SNMP rules;
flow rules are window-only), raises an alert and — only with the
global and per-rule enables in enforce mode, an automatic-capable template, and
any source-specific confidence gates — triggers a reroute.
_Avoid_: alarm, trigger, alert (an alert is the *output* of a fired rule).
```

Only the parenthetical changes; the surrounding sentence and the `_Avoid_:`
line stay byte-identical.

**Verify**: `grep -n "window-only" CONTEXT.md` → 1 match;
`grep -n "consecutive-sample requirement" CONTEXT.md` → 0 matches.

### Step 2: Update the index

Set this plan's row to DONE in `plans/README.md`.

**Verify**: `grep -n "013" plans/README.md` → row shows DONE.

## Test plan

No code changes; no tests. The greps above are the verification.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -c "consecutive-sample requirement" CONTEXT.md` = 0
- [ ] `grep -c "window-only" CONTEXT.md` ≥ 1
- [ ] The `_Avoid_:` line of the entry is unchanged
  (`grep -c "an alert is the \*output\* of a fired rule" CONTEXT.md` = 1)
- [ ] `git status --porcelain` shows only `CONTEXT.md` and `plans/README.md`
- [ ] `plans/README.md` status row for 013 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The Detection Rule entry no longer matches the "Current state" excerpt.
- `backend-rust/src/api/rules.rs` no longer rejects `consecutive_samples > 0`
  on flow rules (the ground truth changed — the glossary edit would then be
  wrong, not the glossary).

## Maintenance notes

- If a third telemetry source is ever added, this entry needs its persistence
  semantics stated here again — the glossary attributes mechanisms per source
  now, so a new source is a mandatory glossary edit.
- Reviewer should check: wording matches `docs/detection-engine.md:79-84`.
