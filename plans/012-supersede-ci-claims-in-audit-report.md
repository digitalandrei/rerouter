# Plan 012: Mark the deleted CI pipeline as superseded in the 2026-07-10 audit report

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**: `git diff --stat ef14aec..HEAD -- docs/audit-2026-07-10.md`
> If the file changed since this plan was written, compare the "Current state"
> excerpt against the live file before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P3
- **Effort**: S
- **Risk**: LOW
- **Depends on**: plans/011-document-release-gate.md (links to the section it creates)
- **Category**: docs
- **Planned at**: commit `ef14aec`, 2026-07-23

## Why this matters

`docs/audit-2026-07-10.md` §9 describes, in present tense, a GitHub Actions
pipeline that "runs formatting, Clippy with denied warnings, all-target
database-backed tests, frontend typechecking, a high-severity dependency
audit, and a production build." That workflow was deleted on 2026-07-21
(commit `1272ee2`, owner decision). A reader trusting the report believes
quality gates run automatically on every change; none do — the gate is
local-only. The report is a dated artifact, so the fix is a supersession
note, not a rewrite.

## Current state

- `docs/audit-2026-07-10.md:163` — heading `### 9. Configuration,
  documentation, and CI`. The stale claim is in the **Resolution** paragraph
  below it, which contains verbatim (single sentence, lines ~173-175):

  ```
  CI uses least privilege and concurrency cancellation and
  runs formatting, Clippy with denied warnings, all-target database-backed tests,
  frontend typechecking, a high-severity dependency audit, and a production build.
  ```

- The report may also recommend CI-based cargo-audit work near lines 216-218;
  if such a recommendation exists, the single note added in Step 1 covers it —
  do not annotate every mention.

- `docs/audit-2026-07.md:253` mentions cargo-audit only as "could not be run
  here" — historical, accurate, **leave it alone**.

- Convention for this fix: the repo has no existing "superseded" marker
  pattern; use a bold bracketed note in the same GitHub-markdown style as the
  report's own **Finding:**/**Resolution:** markers.

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Locate the claim | `grep -n "CI uses least privilege" docs/audit-2026-07-10.md` | exactly 1 match |
| Confirm note landed | `grep -n "Superseded" docs/audit-2026-07-10.md` | ≥ 1 match |
| Docs-only change check | `git status --porcelain` | only in-scope files listed |

## Scope

**In scope** (the only files you should modify):
- `docs/audit-2026-07-10.md`
- `plans/README.md` (status row only)

**Out of scope** (do NOT touch):
- `docs/audit-2026-07.md` and `docs/audit-2026-06.md` — their CI/cargo-audit
  mentions are historical statements that remain true as written.
- `.github/` — do not recreate any workflow.
- Any other section of `docs/audit-2026-07-10.md` — the report is a dated
  artifact; only the one note is added.

## Git workflow

- Branch: `advisor/012-supersede-ci-claims`
- Single commit, e.g. `docs: note CI removal in the 2026-07-10 audit report`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Add a supersession note to §9

In `docs/audit-2026-07-10.md`, directly under the `### 9. Configuration,
documentation, and CI` heading (line 163) and before the **Finding:** line,
insert:

```markdown
> **[Superseded 2026-07-21]** The GitHub Actions pipeline described below was
> removed by owner decision (commit `1272ee2`). All quality gates are now
> local-only — see "Release gate (local)" in [deployment.md](deployment.md).
> The rest of this section remains accurate as a point-in-time record.
```

**Verify**: `grep -n "Superseded 2026-07-21" docs/audit-2026-07-10.md` → 1
match, on a line number between the §9 heading and the `**Finding:**` that
follows it.

### Step 2: Update the index

Set this plan's row to DONE in `plans/README.md`.

**Verify**: `grep -n "012" plans/README.md` → row shows DONE.

## Test plan

No code changes; no tests. Verification is the greps above plus confirming the
blockquote renders (view the raw markdown — `>` prefix on every line of the
note).

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -c "Superseded 2026-07-21" docs/audit-2026-07-10.md` = 1
- [ ] The original §9 text below the note is unmodified
  (`grep -c "CI uses least privilege" docs/audit-2026-07-10.md` = 1)
- [ ] `git status --porcelain` shows only `docs/audit-2026-07-10.md` and
  `plans/README.md` modified
- [ ] `plans/README.md` status row for 012 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `grep -n "CI uses least privilege" docs/audit-2026-07-10.md` returns 0 or
  more than 1 match (report structure drifted).
- A supersession note already exists in the file.
- Plan 011 has not landed (the deployment.md anchor this note links to does
  not exist) — either land 011 first or STOP.

## Maintenance notes

- Future audit reports should state their CI/gate assumptions with a date so
  supersession notes stay unnecessary.
- Reviewer should check: the note is a blockquote, dated, and does not alter
  the historical text.
