# Manual Mitigations and safe action sets

Manual Mitigations contains named, ordered sets of the existing allowlisted
Action Templates. It does not add a free-form command facility. Rules and manual
runs use the same preparation, authorization, device ownership, verification,
and recovery engine.

## Build and reuse

- Use **Manual Mitigations** to create, edit, duplicate, archive, or run a named
  set. Each action names its router and validated parameters. Order is visible;
  additions and preparation must precede withdrawals and shutdowns.
- **Run once** builds an unsaved set. It requires the existing manual execution
  permission; saving shared definitions additionally requires `edit_rules`.
- A saved run permits temporary router/parameter overrides. Changing operation
  types or order requires an edited/duplicated definition or an unsaved set.
  Overrides never alter the saved definition.
- Rules import independent copies. Append is the normal import; replacement is
  explicit. Later preset edits or archival never update a copied rule.
- Saving a rule action set requires a clear rule, commits the whole set in one
  transaction, and disarms automatic execution until explicitly re-armed.
  Changing a rule condition also invalidates its execution revision and disarms
  automation. Detection and alerting remain enabled.
- Flow-derived victims require a compatible rule context. Standalone manual
  sets use explicit targets.

The existing `/templates` catalog is labelled **Action Templates**. The old
`/mitigations/manual` link redirects to `/manual-mitigations`. Mitigations remains
the shared incident/history view, including source, saved revision, effective
parameters, per-action progress, remaining mutations, and reconciliation.

## Prepare, confirm, execute

Observe mode renders a would-run plan and cannot mutate router configuration.
Enforce previews perform complete read-only preparation of every required
action. The resulting snapshot contains concrete commands, current/desired
state, typed verification requirements, device host/port/pinned identity, and
the exact inverse. A failed sibling refuses the whole set; there is no silent
skip or best-effort execution policy.

A five-minute, one-use preview credential binds the operator, reason, source
revision, ordered actions, and exact prepared snapshot. Confirmation creates a
durable execution identity before handing work to the background runner.
Repeating the same confirmation returns the same bundle; it cannot run twice.
Edits or archival invalidate unconsumed previews. Admitted runs keep their own
immutable definition.

The runner acquires every device's durable ownership window and native IOS
configuration lock before the first write. It rechecks policy, physical device
identity, and the complete ordered preconditions. Native locks remain held
through writes, soft clears, and exact read-back verification. Unsupported
locking, commands, or response shapes refuse execution. The controller never
forces another session's lock clear.

Safety-policy changes serialize with actuation. A completed disarm, maintenance
lock, interface-protection change, or definition revision cannot be bypassed by
an earlier check. Rate admission reserves the entire set; standalone requests
cannot spend another bundle's reservation.

## Ownership and recovery

An action records whether it changed configuration, changed nothing, or has an
unknown effect. A no-op never owns an inverse. Rollback loads the original
persisted snapshot and restores only its owned change, after comparing current
state. An already-restored inverse is a verified no-op. A conflicting state is
never overwritten.

Any ambiguous apply or compensation freezes the entire set. No further router
writes are issued, including compensation on another router. The bundle retains
its ownership windows and reports the known-applied and uncertain actions in a
critical alert. **Reconcile** is a read-only comparison against recorded state;
an acknowledgement note cannot override conflicting evidence. Once uncertainty
is resolved, an operator can preview an exact recovery plan.

Controller restart reconstructs outstanding ownership from durable actions.
It does not automatically resume interrupted writes. Recovery is independent of
the newest retained detection event. Devices with execution history cannot be
hard-deleted; active recovery evidence and undelivered notification intents are
protected from retention. Legacy actions without sufficient snapshots require
operator reconciliation and cannot obtain an invented automatic inverse.

A recovery child records every source activation in
`recovery_attempt_sources`; the older single `recovery_bundle_id` pointer is
only compatibility metadata. Confirmation claims all sources and compares the
exact remaining original IDs in one transaction. Execution then transfers all
claimed device windows together. A separate device/source membership ledger
retains every quarantine when several source activations touched the same
device, so settling one root cannot unlock another root's mutation.

Successful changed and verified-no-op inverses permanently close their original
and are never selected again. A recovery that provably made no write releases
its claim for a fresh manual preview while recording a reason that blocks blind
automatic retry. Any in-flight, unknown, conflicting, or failed changed inverse
freezes the complete source set until evidence-bound reconciliation.

## API and permissions

| Operation | Endpoint | Permission |
| --- | --- | --- |
| List/read definitions | `GET /api/mitigation-presets[/{id}]` | `view_asset` |
| Create/save/archive | `POST /api/mitigation-presets`, `PUT/DELETE /api/mitigation-presets/{id}` | `edit_rules` |
| Preview an effective set | `POST /api/manual-mitigations/preview` | `trigger_manual_reroute` |
| Confirm a prepared plan | `POST /api/manual-mitigations/apply` | `trigger_manual_reroute` |
| Replace/import rule actions atomically | `PUT /api/rules/{id}/actions` | `edit_rules` |
| Read progress | `GET /api/reroute-bundles/{id}` | `view_asset` |
| Read-only reconciliation | `POST /api/reroutes/{id}/reconcile` | `acknowledge_uncertain_reroute` |

Definition updates and archival require the saved revision. Rule action saves
require `actions_revision`. Stale writes return conflict without partial saves.
Manual apply returns `202` with a bundle ID; the compatibility single-template
endpoint preserves its result shape while using the shared engine. Manual clear
and rollback require previews too. Clearing detection without any router changes
can be confirmed in observe mode. A human-confirmed recovery that still owns
mutations may also run in Observe with exact preview authority. Autonomous
condition or timed recovery requires Enforce plus the automatic master switch.
Compensation already authorized for a manual-origin failure policy may finish;
an autonomous-origin compensation is blocked after disarm.

## Release boundary

Tests use a restricted account and dedicated schema on an existing database
service. Missing test configuration is a failure, not a silently successful
skipped suite. The supported protocol remains MariaDB-primary and MySQL 8.4
compatible; certification must include both engines.

Source tests, mocked SSH, and a passing build do not certify an IOS image.
Keep observe mode and automatic execution off until the image/account-specific
matrix in the deployment guide passes. Validate exclusive lock semantics across
management planes, output parsing, disconnects, and complete apply/rollback on a
lab network. Cross-router execution is sequential with conservative recovery,
not an atomic network transaction.
