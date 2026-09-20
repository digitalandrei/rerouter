# Mitigation application logic audit — 20 September 2026

## Definition model

Rerouter has two operator-facing mitigation definitions:

- **Manual Mitigation:** an ordered action set started by an operator.
- **Rule:** a detection condition plus an ordered action set. Detection controls
  automatic triggering; when Manual apply is enabled, the same action set can be
  started by an operator independently of detection state.

Both use the same preparation, admission, execution, ownership, and recovery
engine. Run once is an unsaved Manual Mitigation and has no reusable source id.

## Apply pipeline

1. **Load definition.** The API resolves the saved revision and enabled ordered
   actions. Rule flow auto-targets are resolved at preview time or refused.
2. **Read-only preparation.** The controller reads each router, validates the
   requested object and transport identity, and creates concrete commands,
   before/after evidence, and an exact inverse.
3. **Immutable preview.** The ordered prepared snapshot is hashed and stored with
   the actor, source id/revision, reason, verification scope, and expiry. The
   one-use token stores only its hash.
4. **Confirmation/admission.** In one authorization transaction the controller
   checks actor, token, expiry, snapshot hash, source revision, rule action
   revision, and recovery ownership. Replaying a consumed token returns the same
   bundle rather than creating a second one.
5. **Durable action ledger.** Every prepared action is persisted before the
   asynchronous runner starts. Rate capacity is reserved for the complete set.
6. **Serialized execution.** Device ownership windows and native IOS locks are
   acquired in deterministic order. Current transport identity and the complete
   prepared preconditions are checked again before writes.
7. **Apply and verify.** Actions execute in safety order. Each successful write
   is read back against its typed expected state while locks remain held.
8. **Finalize ownership.** Terminal action state, bundle progress, remaining
   mutations, audit events, alerts, and recovery ownership are persisted. A
   successful bundle can be execution-terminal while still lifecycle-active
   because its router changes remain applied.

## Failure behavior

- A refusal before commands is a proven no-effect failure.
- A known failure after earlier siblings succeeded can compensate those siblings
  in reverse order under `abort_and_compensate`.
- If a command may have changed the router but exact state cannot be proved, the
  action is uncertain. Further writes and blind compensation stop; ownership and
  quarantine remain until reconciliation.
- Revert uses the original persisted inverse, verifies current ownership/state,
  and requires a fresh exact prepared plan. The UI can pause for review or
  explicitly prepare and submit that one-use plan in a single operator action.

## Concurrency and duplicate controls

The backend protects routers with immutable plan binding, atomic rate
reservation, policy fencing, device windows, native locks, cooldowns, and source
revision checks. These prevent overlapping unsafe writes even if a stale client
attempts another run.

The reusable-definition UI now applies a stricter presentation rule: any active
run returned for a Manual Mitigation locks Run, Edit, Archive, temporary
overrides, and preview. Details and read-only inspection remain available, and
the active run is the single place for recovery actions. The lock is refreshed
again when a viewed bundle reaches a terminal execution state.

This UI rule is source-oriented consistency, not a replacement for backend
device safety. Run once has no reusable source id, so its concurrency continues
to be governed by device ownership and admission gates.

## Stop and revert semantics

`POST /api/reroutes/{id}/cancel` can cancel only an individual action still in
`planned` or `pending`; it proves that no command started. There is no force-stop
for a bundle once an SSH action is running. Killing that work could leave an
unknown partial configuration, so the UI must not claim that a generic Stop is
available.

Revert availability is computed by the server from remaining owned mutations,
unknown effects, recovery claims, and existing recovery children. The UI exposes
revert only when that result is eligible. Unknown effects require read-only
reconciliation first.

## Remaining design option

If operators need a bundle-level Stop later, implement a durable cooperative
stop request. The runner should finish the bounded current transport operation,
stop before the next action, record which actions changed, and then offer an
evidence-bound compensation/revert decision. It must not terminate an SSH writer
or infer that an interrupted command made no change.
