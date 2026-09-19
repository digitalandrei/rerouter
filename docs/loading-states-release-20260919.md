# Loading and preview clarity — 2026-09-19

Long-running controls now use one shared loading contract. The initiating button
shows a spinning progress icon, changes to an operation-specific label, exposes
`aria-busy`, and blocks repeat activation. Sibling controls remain disabled when
their operation conflicts, but do not display false progress.

The pattern covers manual mitigation preview/apply, rule preview/apply and clear,
whole-run revert, individual rollback and reconciliation, read-only configuration
inspection, device discovery/tests/saves, dashboard and retained-data retries,
rule/user/device saves, notification tests, templates, login, and shared prompt
and confirmation dialogs. Immediate navigation, local draft edits, filters,
sorting, and modal opening remain immediate controls without spinners.

Mitigation and recovery workflows now state the required two-step sequence:

1. **Preview** reads current router configuration and prepares the exact plan. It
   makes no configuration changes. Duration depends on router response time and
   the number of actions.
2. **Review and explicitly confirm** applies the prepared plan using its
   expiring, one-use authority.

Read-only preview buttons use neutral styling. Only the confirmed apply/revert
control is destructive. A server acceptance ends the submission spinner and
hands off to the existing recorded-run progress; it is never presented as
execution success.

Validation passed: 65 frontend tests, TypeScript, production build, deployment
script checks, and the Impeccable detector. A delayed mocked whole-run preview
proved the exact desktop/mobile state: one spinner, `aria-busy=true`, disabled
reason and preview controls, no confirmation control before preview completion,
no horizontal overflow, and no request other than the mocked read-only preview.
Evidence is under `/tmp/rerouter-workflow-review-20260919/loading-states/`.

## Deployment result

Frontend source `9193046c4a4128db4cf29541674db28e886bf83e` is deployed
on EMDD. The public and server index SHA-256 is
`0433004b3a25f3bb6dcb3738c49725753a5728df94a095db8077b56ecbd5eb53`.

This was a static-only swap. The controller process remained running with
backend release `3276418925c6dde0e6cf9fae809b5ffc4b3846cd`; its binary,
configuration, database ledger, and service PID were unchanged across the
deployment guard. Run 1 remains `succeeded`, lifecycle `active`, with 8/8
actions complete and eight owned changes, no recovery child or claim, and zero
active locks.

No preview, mitigation, revert, notification test, database write, service
restart, or router connection occurred during deployment. The previous static
frontend and marker are backed up at
`/root/rerouter-backups/loading-states-9193046c4a41`.
