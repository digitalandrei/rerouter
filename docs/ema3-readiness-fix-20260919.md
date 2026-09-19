# eMA3 saved mitigation readiness correction

The saved eMA3 mitigation incorrectly reported `action 1: template plan has an
empty apply command list`. Both definition validation and initial inspection
passed `bgp_export_policy_set` through the static command renderer. That template
deliberately stores an empty apply list: structured preparation generates the
exact commands, configuration snapshots, inverse and verification proof.

The correction shares one validation helper between these two entry points.
Only the known export-policy template with `prepared_state` verification defers
command construction. Static templates retain the existing empty-command and
verification rejection. Inventory validation, prepared-plan validation, ordering,
authorization and execution checks remain in place.

The regression was reproduced before the fix with
`cargo test --test ema3_policy_preparation saved_export_policy_action_passes_definition_validation_before_typed_preparation -- --exact`.
It failed with the same empty-command error. The test now reaches definition
validation, saved-preset readiness and manual preview starting with an unprepared
action and a fake configuration reader. Invalid structured verification and
missing policy inventory remain blocked. Earlier tests constructed the prepared
plan first and missed these entry points.

`--check-mitigation-preset ID` runs the same saved readiness calculation against
cached database inventory. It exits before migrations, startup recovery and
workers. It makes no router connection and grants no execution authority. Its
result contains only ID, name, status and validation error. An existing blocked
definition is a successful diagnostic result; a missing ID exits unsuccessfully.

Deployment tooling preserves the current configuration, environment, frontend,
saved definitions, rule definitions and actions, credentials and schema. It
backs up application data and compares these records before and after restarting
only the controller. It checks the complete live eMA3 definition using the
database-only diagnostic before and after restart. No live mitigation preview,
execution, reversal or router configuration change is part of this correction.
