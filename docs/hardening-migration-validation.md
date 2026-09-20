# Hardening migration fixture validation

The harness validates a fresh schema and upgrades from the audited 56- and
69-migration baselines to the migration manifest in the current checkout. It
uses the existing Rust migration example, never starts a database daemon, and
never creates, drops, or resets a schema. Supply an already-empty, task-owned
schema through a URL file:

```bash
python3 scripts/test-hardening-migrations.py fresh \
  --db-url-file /secure/rerouter-test-fresh-url
python3 scripts/test-hardening-migrations.py baseline56 \
  --db-url-file /secure/rerouter-test-upgrade56-url
python3 scripts/test-hardening-migrations.py baseline69 \
  --db-url-file /secure/rerouter-test-upgrade69-url
```

Fresh mode accepts only `rerouter_test_*_fresh_*`; upgrade modes accept only
`rerouter_test_*_upgrade_*`. The account must be non-root, contain `test` in its
name, and connect over loopback or an explicit Unix socket. The harness refuses
a non-empty schema. Resetting a schema is deliberately outside the tool.

The baseline fixture preserves mixed sent/suppressed/rate-limited/failed/no-
audience delivery history, an unattempted alert, and consumed/unused legacy
previews. The 69 fixture additionally preserves consumed/unused execution-plan
snapshots, immutable inverse and prepared-action evidence, a completed historical
recovery, and a current ambiguous child holding a device window. Assertions
verify the intended intent-link/redaction/expiry and ownership backfills without
accepting changes to the evidence payloads.

Run the no-database unit checks with:

```bash
python3 -m unittest scripts/test-hardening-migrations-unit.py
```

## MariaDB and MySQL 8.4 syntax note

The reserved migration SQL avoids using `WINDOW` as an unquoted alias and uses
portable explicit casts for boolean aggregates. MySQL 8.4 still accepts
`VALUES(column)` inside `ON DUPLICATE KEY UPDATE`, but reports it as deprecated;
the current alert-repair and publication-barrier migrations use that compatible
form. Treat a future removal as a certification blocker and convert those
statements to row aliases only after verifying MariaDB support. The harness must
be executed once against each engine before release.
