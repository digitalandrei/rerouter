# Existing run and telemetry API corrections

Execution endpoints and permissions are unchanged. Confirmed manual work still
requires a fresh actor-bound preview; retries cannot reuse a consumed preview.

## Run summaries and details

`GET /api/reroute-bundles` with no query parameters preserves its legacy array
response. Query requests return `{items, page, per_page, total}`. The server
clamps pages to the available result set and `per_page` to 1–200; Active Runs
requests 25. Each item is a summary. Fetch
`GET /api/reroute-bundles/{id}` for action evidence, persisted inverses, and
the selected recovery child's progress. These endpoints require `view_asset`.

| Parameter | Meaning |
| --- | --- |
| `lifecycle` | `active`, `inactive`, a specific lifecycle, or `all` |
| `logical_only` / `original_only` | Omit recovery children from the source-run list |
| `trigger_type`, `rule_id`, `preset_id` | Existing origin filters |
| `q` | Case-insensitive literal substring of run ID, source name, trigger, lifecycle, or operator email |
| `source_kind` | Source kind, falling back to the legacy trigger type |
| `device` | Literal device-name substring or exact numeric device ID |
| `created_from`, `created_to` | RFC3339 bounds on `created_at`, inclusive lower and exclusive upper bound; malformed bounds return 400 |

Wildcard characters in searches are literal. Filtering and pagination happen
before enrichment. A refresh requests one summary page, then at most the
selected source detail and its recovery detail. Obsolete responses cannot
replace current evidence; a refresh failure leaves visible retained data and
an error message.

`revert.available` and `revert.block_reasons` describe current manual eligibility.
`automatic_recovery_block_reason` describes the unattended-recovery failure
separately. `take_control.available` and its reasons come from the server's
ownership gates. None of these fields authorizes a write: confirmation and
execution revalidate ownership, evidence, and authority transactionally.

## Flow evidence

Completeness is recorded per exporter and closed bucket for interface, port,
ASN, and talker dimensions. Packet and byte availability and sampling confidence
remain separate. Missing historical quality or contributor coverage is unknown.
Selector absence becomes zero only with complete required evidence. A dropped
talker tail does not invalidate intact interface totals. The configured bucket
width remains the rate denominator.

## Internal decision and recovery records

A decision's observation cursor, transition, event, alert, and automatic attempt
marker commit before preparation starts. Recovery associations identify every
source activation; device quarantine may have several source members. Successful
inverse evidence closes only its original mutation. Incomplete records preserve
uncertainty and ownership until read-only reconciliation proves the state.

All timing changes remain proposals. The dry-run report emits ordered requests
only when affected rules are clear and automatic execution is disarmed; it never
emits an arming request. See [release preparation](hardening-release.md).
