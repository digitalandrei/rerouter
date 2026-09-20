#!/usr/bin/env node
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const playwrightRoot = process.env.REROUTER_PLAYWRIGHT_ROOT ?? "/tmp/rerouter-browser-20260917/node_modules/playwright";
const { chromium } = await import(pathToFileURL(path.join(playwrightRoot, "index.mjs")).href);
const dist = path.resolve("frontend/dist");
const artifacts = process.env.REROUTER_BROWSER_ARTIFACTS ?? "/tmp/rerouter-hardening-20260920/browser-load";
const now = Date.now();
const runs = Array.from({ length: 150 }, (_, index) => {
  const id = 150 - index;
  return {
    id, rule_id: id % 3 === 0 ? 7 : null, trigger_type: id % 2 ? "manual" : "automatic",
    state: "succeeded", execution_state: "succeeded", lifecycle_state: "active", active: true,
    remaining_mutations: 1, remaining_changes: 1, unknown_effects: 0,
    failure_policy: "abort_and_compensate", total_actions: 1, completed_actions: 1,
    failure_reason: null, started_at: new Date(now - id * 60_000).toISOString(), finished_at: null,
    created_at: new Date(now - id * 60_000).toISOString(), triggered_by: id % 2 ? "ops@example.test" : null,
    source: { kind: id % 5 === 0 ? "preset" : "manual", name: `edge_${id}`, preset_name: id % 5 === 0 ? `Saved ${id}` : undefined },
    affected_devices: [{ id: (id % 4) + 1, name: `router-${(id % 4) + 1}` }],
    revert: { available: true, block_reasons: [], noop: false }, take_control: { available: true, block_reasons: [] },
    latest_recovery_bundle_id: id === 150 ? 1000 : null,
    latest_recovery: id === 150 ? { id: 1000, parent_bundle_id: 150, state: "running", total_actions: 1, completed_actions: 0, started_at: new Date().toISOString(), finished_at: null, failure_reason: null } : null,
  };
});
const details = new Map(runs.map((run) => [run.id, { ...run, actions: [{ reroute_id: run.id + 10_000, position: 0, device_id: run.affected_devices[0].id, device_name: run.affected_devices[0].name, state: "succeeded", failure_reason: null, template_display_name: "Fixture action" }], still_applied_reroute_ids: [run.id + 10_000] }]));
details.set(1000, { ...details.get(150), id: 1000, parent_bundle_id: 150, latest_recovery_bundle_id: null, latest_recovery: null, trigger_type: "rollback", state: "running", execution_state: "running", lifecycle_state: "recovery_running", completed_actions: 0, actions: [{ reroute_id: null, position: 0, device_id: 3, device_name: "router-3", state: "running", failure_reason: null, template_display_name: "Restore fixture" }], still_applied_reroute_ids: [] });

const requests = [];
let activeApi = 0, maxActiveApi = 0, delayNeedle = null, failNextDetail = false;
function sendJson(res, value, status = 200) {
  const encoded = Buffer.from(JSON.stringify(value));
  res.writeHead(status, { "content-type": "application/json", "content-length": encoded.length, "cache-control": "no-store" });
  res.end(encoded); return encoded.length;
}
function filterRuns(url) {
  const q = (url.searchParams.get("q") ?? "").toLowerCase();
  const device = (url.searchParams.get("device") ?? "").toLowerCase();
  const source = url.searchParams.get("source_kind") ?? "";
  return runs.filter((run) => {
    const haystack = `${run.id} ${run.source.preset_name ?? run.source.name ?? ""} ${run.trigger_type} ${run.lifecycle_state} ${run.triggered_by ?? ""}`.toLowerCase();
    return (!q || haystack.includes(q)) && (!source || (run.source.kind ?? run.trigger_type) === source)
      && (!device || run.affected_devices.some((item) => String(item.id) === device || item.name.toLowerCase().includes(device)));
  });
}
async function api(req, res, url, record) {
  if (url.pathname === "/api/auth/me") return sendJson(res, { id: 1, email: "ops@example.test", name: "Operator", roles: ["operator"], permissions: ["view_asset", "trigger_manual_reroute", "acknowledge_uncertain_reroute"] });
  if (url.pathname === "/api/status") return sendJson(res, { operating_mode: "observe", devices_total: 4, devices_reachable: 4, interfaces_monitored: 4, active_rule_matches: 0, alerts_24h: 0, telemetry_stale_count: 0 });
  if (url.pathname === "/api/settings") return sendJson(res, { operating_mode: "observe", automatic_actions_enabled: false, global_lock: false });
  if (url.pathname === "/api/rules") return sendJson(res, []);
  if (url.pathname === "/api/alerts") return sendJson(res, { rows: [], total: 0, limit: 50, offset: 0 });
  if (url.pathname === "/api/reroute-bundles") {
    if (delayNeedle && url.searchParams.get("q") === delayNeedle) await new Promise((resolve) => setTimeout(resolve, 6500));
    const filtered = filterRuns(url), perPage = Math.min(200, Math.max(1, Number(url.searchParams.get("per_page") ?? 25)));
    const pages = Math.max(1, Math.ceil(filtered.length / perPage));
    const page = Math.min(pages, Math.max(1, Number(url.searchParams.get("page") ?? 1)));
    return sendJson(res, { items: filtered.slice((page - 1) * perPage, page * perPage), page, per_page: perPage, total: filtered.length });
  }
  const match = url.pathname.match(/^\/api\/reroute-bundles\/(\d+)$/);
  if (match) {
    if (failNextDetail && Number(match[1]) !== 1000) { failNextDetail = false; return sendJson(res, { error: "fixture detail failure" }, 503); }
    const value = details.get(Number(match[1])); return value ? sendJson(res, value) : sendJson(res, { error: "not found" }, 404);
  }
  return sendJson(res, { error: `unmocked ${req.method} ${url.pathname}` }, 404);
}

const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" };
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname.startsWith("/api/")) {
    const record = { method: req.method, path: url.pathname, query: Object.fromEntries(url.searchParams), started_at: Date.now(), finished_at: null, duration_ms: null, bytes: 0, aborted: false, status: null };
    requests.push(record); activeApi += 1; maxActiveApi = Math.max(maxActiveApi, activeApi);
    req.on("aborted", () => { record.aborted = true; }); res.on("close", () => { if (!res.writableEnded) record.aborted = true; });
    const originalEnd = res.end.bind(res); res.end = (chunk, ...args) => { if (chunk) record.bytes += Buffer.byteLength(chunk); record.status = res.statusCode; return originalEnd(chunk, ...args); };
    try { await api(req, res, url, record); } catch (error) { if (!res.headersSent) sendJson(res, { error: "fixture failure" }, 500); record.error = String(error); }
    finally { activeApi -= 1; record.finished_at = Date.now(); record.duration_ms = record.finished_at - record.started_at; }
    return;
  }
  let file = path.join(dist, url.pathname === "/" ? "index.html" : url.pathname);
  try { if ((await fs.stat(file)).isDirectory()) file = path.join(file, "index.html"); } catch { file = path.join(dist, "index.html"); }
  const data = await fs.readFile(file); res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" }); res.end(data);
});

await fs.access(path.join(dist, "index.html")); await fs.mkdir(artifacts, { recursive: true });
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, args: ["--enable-precise-memory-info"] });
const started = Date.now();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(`${base}/mitigations?tab=active`);
  await page.getByText("Page 1 of 6").waitFor();
  await page.getByRole("button", { name: "Review run 150" }).click();
  await page.getByText("Restore fixture").waitFor();
  const normalStart = requests.length;
  await page.waitForTimeout(10_700);
  const normal = requests.slice(normalStart).filter((item) => item.path.startsWith("/api/reroute-bundles"));
  const fiveSecondBuckets = new Map();
  for (const item of normal) { const bucket = Math.floor((item.started_at - requests[normalStart]?.started_at) / 4500); fiveSecondBuckets.set(bucket, (fiveSecondBuckets.get(bucket) ?? 0) + 1); }
  if (normal.filter((item) => item.path === "/api/reroute-bundles").length < 2) throw new Error("two normal refresh cycles were not observed");
  if ([...fiveSecondBuckets.values()].some((count) => count > 3)) throw new Error(`refresh exceeded three requests: ${JSON.stringify([...fiveSecondBuckets])}`);

  await page.getByRole("button", { name: "Close", exact: true }).first().click();
  await page.getByLabel("Search active mitigation runs").fill("edge_12");
  await page.getByText("Page 1 of 1").waitFor();
  await page.getByLabel("Search active mitigation runs").fill("");
  await page.getByText("Page 1 of 6").waitFor();
  await page.getByRole("button", { name: "Next" }).click();
  await page.getByText("Page 2 of 6").waitFor();
  await page.getByLabel("Filter by device").fill("router-3");
  await page.getByText("Page 1 of 2").waitFor();

  delayNeedle = "stale";
  await page.getByLabel("Search active mitigation runs").fill("stale");
  await page.waitForTimeout(150);
  await page.getByLabel("Search active mitigation runs").fill("edge_1");
  await page.getByText(/Page 1 of/).waitFor();
  await page.getByRole("button", { name: /Review run/ }).first().click();
  await page.getByRole("dialog").waitFor();
  failNextDetail = true;
  await page.waitForTimeout(5_400);
  await page.getByText(/Selected run could not be refreshed/i).waitFor();
  if (!(await page.getByRole("dialog").isVisible())) throw new Error("selected evidence disappeared after detail error");
  const staleRecord = requests.find((item) => item.path === "/api/reroute-bundles" && item.query.q === "stale");
  for (let attempt = 0; staleRecord && !staleRecord.finished_at && attempt < 70; attempt += 1) await page.waitForTimeout(100);
  if (!staleRecord?.aborted) throw new Error("delayed stale list request was not aborted");

  const heap = await page.evaluate(() => ({ used: performance.memory?.usedJSHeapSize ?? null, total: performance.memory?.totalJSHeapSize ?? null }));
  let browserRssKb = null;
  try {
    const children = (await fs.readFile(`/proc/${process.pid}/task/${process.pid}/children`, "utf8")).trim().split(/\s+/).filter(Boolean);
    const rss = await Promise.all(children.map(async (pid) => Number((await fs.readFile(`/proc/${pid}/status`, "utf8")).match(/^VmRSS:\s+(\d+)/m)?.[1] ?? 0)));
    browserRssKb = rss.reduce((sum, value) => sum + value, 0);
  } catch { browserRssKb = null; }
  const relevant = requests.filter((item) => item.path.startsWith("/api/reroute-bundles"));
  const report = {
    ok: true, fixture_runs: runs.length, page_size: 25, elapsed_ms: Date.now() - started,
    request_count: relevant.length, list_requests: relevant.filter((item) => item.path === "/api/reroute-bundles").length,
    detail_requests: relevant.filter((item) => item.path !== "/api/reroute-bundles").length,
    aborted_requests: relevant.filter((item) => item.aborted).length, max_concurrent_api: maxActiveApi,
    response_bytes: relevant.reduce((sum, item) => sum + item.bytes, 0),
    latency_ms: { max: Math.max(...relevant.map((item) => item.duration_ms ?? 0)), average: Math.round(relevant.reduce((sum, item) => sum + (item.duration_ms ?? 0), 0) / relevant.length) },
    browser_heap: heap, browser_rss_kb: browserRssKb, normal_cycle_requests: normal,
  };
  await fs.writeFile(path.join(artifacts, "active-runs-report.json"), JSON.stringify(report, null, 2));
  await fs.writeFile(path.join(artifacts, "active-runs-requests.json"), JSON.stringify(requests, null, 2));
  await page.screenshot({ path: path.join(artifacts, "active-runs.png"), fullPage: true });
  process.stdout.write(`${JSON.stringify(report)}\n`); await page.close();
} finally {
  await browser.close(); await new Promise((resolve) => server.close(resolve));
}
