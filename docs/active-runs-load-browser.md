# Active Runs offline browser load check

`frontend/tests/active-runs-load-browser.mjs` serves the current `frontend/dist`
from an ephemeral loopback HTTP server and supplies fully mocked API responses.
It never contacts a controller, database, router, or external network endpoint.

The fixture contains 150 actual summary objects and implements literal server-
side search, source/device filtering, page clamping, and 25-row pagination. Run
150 has a separately fetched recovery child. The harness checks two normal
refresh cycles at the product's five-second interval, requiring one list request
and at most two detail requests per cycle regardless of the 150-row total. It
then exercises search, page and device filters, aborts a deliberately delayed
list response, and verifies that a failed selected-detail refresh leaves the
retained dialog evidence visible.

Run it with:

```bash
REROUTER_PLAYWRIGHT_ROOT=/tmp/rerouter-browser-20260917/node_modules/playwright \
REROUTER_BROWSER_ARTIFACTS=/tmp/rerouter-hardening-20260920/browser-load \
node frontend/tests/active-runs-load-browser.mjs
```

## 20 September 2026 result

- Build tested: `frontend/dist` generated at 13:04 local workspace time.
- Result: pass.
- Fixture runs: 150; page size: 25.
- Two observed normal cycles: 3 requests each (list + source detail + recovery detail).
- Whole scenario: 24 bundle requests, 183,210 response bytes.
- Delayed request: 6,501 ms, aborted once; maximum server-side overlap was 2
  while that already-aborted handler completed.
- Normal mocked response latency: 0–2 ms; whole-scenario average including the
  artificial delay: 272 ms.
- Browser JS heap: 16,001,954 bytes used / 31,415,938 bytes allocated.
- Browser main-process RSS: 94,700 KiB.
- Scenario wall time: 18,723 ms.

Artifacts:

- `/tmp/rerouter-hardening-20260920/browser-load/active-runs-report.json`
- `/tmp/rerouter-hardening-20260920/browser-load/active-runs-requests.json`
- `/tmp/rerouter-hardening-20260920/browser-load/active-runs.png`

The RSS value is the direct Chromium browser process visible to the harness;
renderer subprocess memory remains represented by the browser heap measurement,
not added to that RSS number.
