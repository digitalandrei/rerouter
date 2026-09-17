#!/usr/bin/env node
import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { pathToFileURL } from "node:url";

const playwrightRoot = process.env.REROUTER_PLAYWRIGHT_ROOT ?? "/tmp/rerouter-browser-20260917/node_modules/playwright";
const { chromium } = await import(pathToFileURL(path.join(playwrightRoot, "index.mjs")).href);
const dist = path.resolve("dist");
const shots = process.env.REROUTER_BROWSER_ARTIFACTS ?? "/tmp/rerouter-browser-20260917";

const templates = [
  { id: 1, name: "null_route_prefix", display_name: "Null-Route Prefix", description: "Drop a prefix", provider_type: "device_cli", mode: "ios_ssh", automatic_allowed: true, parameter_schema: { prefix: { type: "cidr", label: "Prefix", required: true, source: "announced_prefix" } }, plan: {}, verification: {}, rollback_template_id: 2, enabled: true },
  { id: 2, name: "null_route_withdraw", display_name: "Null-Route Withdraw", description: "Remove a drop", provider_type: "device_cli", mode: "ios_ssh", automatic_allowed: true, parameter_schema: { prefix: { type: "cidr", label: "Prefix", required: true, source: "announced_prefix" } }, plan: {}, verification: {}, rollback_template_id: 1, enabled: true },
  { id: 3, name: "bgp_advertise_add", display_name: "BGP Advertise Add", description: "Advertise", provider_type: "device_cli", mode: "ios_ssh", automatic_allowed: true, parameter_schema: { neighbor_ip: { type: "ip", label: "Neighbor", required: true } }, plan: {}, verification: {}, rollback_template_id: null, enabled: true },
  { id: 4, name: "iface_tcp_adjust_mss", display_name: "TCP MSS Clamp", description: "Clamp MSS", provider_type: "device_cli", mode: "ios_ssh", automatic_allowed: true, parameter_schema: { interface: { type: "string", label: "Interface", required: true }, mss: { type: "int", label: "MSS", required: true } }, plan: {}, verification: {}, rollback_template_id: null, enabled: true },
];
const devices = [
  { id: 10, name: "edge-a", hostname: "192.0.2.10", enabled: true, reachable: true, ssh_status: "reachable", automation_stable: true, ssh_recent: true, interface_count: 1 },
  { id: 20, name: "edge-b", hostname: "192.0.2.20", enabled: true, reachable: true, ssh_status: "reachable", automation_stable: true, ssh_recent: true, interface_count: 1 },
];
let presets = [];
let ruleActions = [];
let lastRuleSave = null;
let previewActions = null;
let lastPreviewInput = null;
let bundlePolls = 0;
let triggerOnly = false;
const rule = {
  id: 7, name: "DDoS threshold", target_kind: "interface", interface_id: 1, device_id: 10,
  metric: "rx_bps", metric_aggregation: "single", operator: ">", threshold_value: 1000,
  duration_seconds: 0, consecutive_samples: 1, severity: "critical", enabled: true,
  automatic_reroute_enabled: false, manual_apply_enabled: true, reroute_template_id: null,
  action_count: 0, actions_revision: 1, actions: [], current_state: "clear", current_value: 0,
};

function hydratePreset(preset, detailed = false) {
  return {
    ...preset,
    validation_status: detailed ? "valid" : "needs_preview",
    validation_error: null,
    recent_runs: [],
    actions: preset.actions.map((action, index) => ({
      ...action, id: action.id ?? index + 1, position: index,
      template_name: templates.find((item) => item.id === action.reroute_template_id)?.name,
      template_display_name: templates.find((item) => item.id === action.reroute_template_id)?.display_name,
      device_name: devices.find((item) => item.id === action.device_id)?.name,
    })),
  };
}

function json(res, body, status = 200) {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(JSON.stringify(body));
}

async function body(req) {
  let raw = "";
  for await (const chunk of req) raw += chunk;
  return raw ? JSON.parse(raw) : {};
}

async function api(req, res, url) {
  if (url.pathname === "/api/auth/me") return json(res, { id: 1, email: "ops@example.test", name: "Operator", roles: ["operator"], permissions: ["view_dashboard", "view_asset", ...(triggerOnly ? [] : ["edit_rules"]), "trigger_manual_reroute", "acknowledge_uncertain_reroute"] });
  if (url.pathname === "/api/status") return json(res, { operating_mode: "enforce", devices_total: 2, devices_reachable: 2, interfaces_monitored: 2, active_rule_matches: 0, alerts_24h: 0, telemetry_stale_count: 0 });
  if (url.pathname === "/api/settings") return json(res, { operating_mode: "enforce", automatic_actions_enabled: false, global_lock: false });
  if (url.pathname === "/api/templates") return json(res, templates);
  if (url.pathname === "/api/devices") return json(res, devices);
  if (/^\/api\/devices\/\d+\/bgp-networks$/.test(url.pathname)) return json(res, [{ id: 1, device_id: 10, prefix: "192.0.2.0/24", last_discovered_at: new Date().toISOString() }, { id: 2, device_id: 10, prefix: "203.0.113.0/24", last_discovered_at: new Date().toISOString() }]);
  if (/^\/api\/devices\/\d+\/(bgp-peers|interfaces|route-maps)$/.test(url.pathname)) return json(res, []);
  if (url.pathname === "/api/rtbh-communities") return json(res, []);
  if (url.pathname === "/api/mitigation-presets" && req.method === "GET") return json(res, presets.map((item) => hydratePreset(item)));
  if (url.pathname === "/api/mitigation-presets" && req.method === "POST") {
    const input = await body(req);
    lastPreviewInput = input;
    const created = { id: 101, name: input.name, description: input.description ?? null, revision: 1, archived_at: null, actions: input.actions.map((action, index) => ({ ...action, id: index + 1 })), created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    presets = [created];
    return json(res, hydratePreset(created), 201);
  }
  const presetMatch = url.pathname.match(/^\/api\/mitigation-presets\/(\d+)$/);
  if (presetMatch && req.method === "GET") return json(res, hydratePreset(presets.find((item) => item.id === Number(presetMatch[1])), true));
  if (presetMatch && req.method === "PUT") {
    const input = await body(req);
    const updated = { ...presets[0], ...input, revision: input.revision + 1, updated_at: new Date().toISOString(), actions: input.actions.map((action, index) => ({ ...action, id: index + 11 })) };
    presets = [updated];
    return json(res, hydratePreset(updated));
  }
  if (url.pathname === "/api/manual-mitigations/preview") {
    const input = await body(req);
    previewActions = structuredClone(input.actions);
    return json(res, {
      plan_id: 501,
      preview_token: "preview-token",
      operating_mode: "enforce",
      expires_at: new Date(Date.now() + 300000).toISOString(),
      source: { kind: "preset", preset_id: input.preset_id, preset_name: presets[0]?.name, preset_revision: input.preset_revision },
      results: input.actions.map((action, index) => ({
        executed: false,
        reroute_id: null,
        state: null,
        device_id: action.device_id,
        device_name: devices.find((item) => item.id === action.device_id)?.name,
        message: "Prepared; confirmation required",
        would_run: {
          template_id: action.reroute_template_id,
          template_name: templates.find((item) => item.id === action.reroute_template_id)?.name,
          config_mode: true,
          commands: [`ip route ${action.params.prefix} Null0`],
          verify: { command: `show ip route ${action.params.prefix}`, expect: "Null0", reject: null },
          sequence_pending: false,
        },
        would_run_rollback: { commands: [`no ip route ${action.params.prefix} Null0`] },
        mutation_effect: "pending",
        bundle_position: index,
      })),
    });
  }
  if (url.pathname === "/api/manual-mitigations/apply") return json(res, { bundle_id: 601, async: true }, 202);
  if (url.pathname === "/api/reroute-bundles") return json(res, [{ id: 601, rule_id: null, trigger_type: "manual", state: bundlePolls > 2 ? "succeeded" : "running", failure_policy: "abort_and_compensate", total_actions: previewActions?.length ?? 0, completed_actions: Math.min(bundlePolls, previewActions?.length ?? 0), failure_reason: null, started_at: new Date().toISOString(), finished_at: null, created_at: new Date().toISOString(), actions: [], still_applied_reroute_ids: [], source: { kind: "preset", preset_id: 101, preset_name: presets[0]?.name, preset_revision: 1 } }]);
  if (url.pathname === "/api/reroute-bundles/601") {
    bundlePolls += 1;
    return json(res, { id: 601, rule_id: null, trigger_type: "manual", state: bundlePolls > 2 ? "succeeded" : "running", failure_policy: "abort_and_compensate", total_actions: previewActions?.length ?? 0, completed_actions: bundlePolls > 2 ? previewActions.length : 1, failure_reason: null, started_at: new Date().toISOString(), finished_at: bundlePolls > 2 ? new Date().toISOString() : null, actions: (previewActions ?? []).map((action, index) => ({ reroute_id: bundlePolls > 2 ? 700 + index : null, position: index, device_id: action.device_id, device_name: devices.find((item) => item.id === action.device_id)?.name, state: bundlePolls > 2 ? "succeeded" : index ? "queued" : "running", failure_reason: null, template_display_name: templates.find((item) => item.id === action.reroute_template_id)?.display_name, params: action.params })), still_applied_reroute_ids: [], source: { kind: "preset", preset_id: 101, preset_name: presets[0]?.name, preset_revision: 1 } });
  }
  if (url.pathname === "/api/rules" && req.method === "GET") return json(res, [{ ...rule, actions: ruleActions, action_count: ruleActions.length, actions_revision: rule.actions_revision + (lastRuleSave ? 1 : 0) }]);
  if (url.pathname === "/api/rules/7") return json(res, { ...rule, actions: ruleActions, action_count: ruleActions.length, actions_revision: rule.actions_revision + (lastRuleSave ? 1 : 0) });
  if (url.pathname === "/api/rules/7/actions" && req.method === "PUT") {
    lastRuleSave = await body(req);
    ruleActions = lastRuleSave.actions.map((action, index) => ({ ...action, id: 900 + index, position: index, template_name: templates.find((item) => item.id === action.reroute_template_id)?.name, template_display_name: templates.find((item) => item.id === action.reroute_template_id)?.display_name, device_name: devices.find((item) => item.id === action.device_id)?.name, inventory_state: "ok" }));
    return json(res, { ...rule, actions: ruleActions, action_count: ruleActions.length, actions_revision: 2 });
  }
  if (url.pathname === "/api/alerts") return json(res, { rows: [], total: 0, limit: 50, offset: 0 });
  if (url.pathname === "/api/locks") return json(res, [{ id: 1, scope: "device", scope_ref: "10", reason: "uncertain action", kind: "auto_uncertain", created_at: new Date().toISOString() }]);
  if (url.pathname === "/api/reroutes" && req.method === "GET") return json(res, [
    { id: 801, device_id: 10, device_name: "edge-a", reroute_template_id: 1, template_name: "null_route_prefix", template_display_name: "Null-Route Prefix", trigger_type: "manual", state: "uncertain", reason: "ambiguous transport", success: null, verification_status: "uncertain", failure_reason: "connection closed", rule_id: null, triggered_by: "Operator", started_at: new Date().toISOString(), finished_at: new Date().toISOString(), created_at: new Date().toISOString() },
    { id: 802, device_id: 20, device_name: "edge-b", reroute_template_id: 1, template_name: "null_route_prefix", template_display_name: "Null-Route Prefix", trigger_type: "manual", state: "succeeded", reason: "test rollback", success: true, verification_status: "pass", failure_reason: null, rule_id: null, triggered_by: "Operator", started_at: new Date().toISOString(), finished_at: new Date().toISOString(), created_at: new Date().toISOString(), source: { kind: "preset", preset_name: presets[0]?.name, preset_revision: 1 } },
  ]);
  if (url.pathname === "/api/reroutes/801") return json(res, { ...(await reroute(801)), steps: [], outputs: [], verifications: [] });
  if (url.pathname === "/api/reroutes/802") return json(res, { ...(await reroute(802)), steps: [], outputs: [], verifications: [] });
  if (url.pathname === "/api/reroutes/801/reconcile") return json(res, { ok: false, outcome: "conflict", message: "Router matches neither recorded state." });
  if (url.pathname === "/api/reroutes/802/rollback") {
    const input = await body(req);
    if (input.dry_run) return json(res, { result: { executed: false, state: null, device_id: 20, device_name: "edge-b", message: "Prepared", would_run: { template_id: 2, template_name: "null_route_withdraw", config_mode: true, commands: ["no ip route 192.0.2.0 255.255.255.0 Null0"], verify: null } }, preview_token: "rollback-token" });
    return json(res, { result: { executed: true, reroute_id: 803, state: "failed", device_id: 20, device_name: "edge-b", message: "verification did not confirm removal", mutation_effect: "unknown" }, preview_token: null });
  }
  return json(res, { error: `unmocked ${req.method} ${url.pathname}` }, 404);
}

async function reroute(id) {
  return (id === 801 ? {
    id: 801, device_id: 10, device_name: "edge-a", reroute_template_id: 1, template_name: "null_route_prefix", template_display_name: "Null-Route Prefix", trigger_type: "manual", state: "uncertain", reason: "ambiguous transport", success: null, verification_status: "uncertain", failure_reason: "connection closed", rule_id: null, triggered_by: "Operator", started_at: new Date().toISOString(), finished_at: new Date().toISOString(), created_at: new Date().toISOString(),
  } : {
    id: 802, device_id: 20, device_name: "edge-b", reroute_template_id: 1, template_name: "null_route_prefix", template_display_name: "Null-Route Prefix", trigger_type: "manual", state: "succeeded", reason: "test rollback", success: true, verification_status: "pass", failure_reason: null, rule_id: null, triggered_by: "Operator", started_at: new Date().toISOString(), finished_at: new Date().toISOString(), created_at: new Date().toISOString(), source: { kind: "preset", preset_name: presets[0]?.name, preset_revision: 1 },
  });
}

const mime = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".png": "image/png" };
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  if (url.pathname.startsWith("/api/")) return api(req, res, url);
  let file = path.join(dist, url.pathname === "/" ? "index.html" : url.pathname);
  try {
    const stat = await fs.stat(file);
    if (stat.isDirectory()) file = path.join(file, "index.html");
  } catch {
    file = path.join(dist, "index.html");
  }
  const data = await fs.readFile(file);
  res.writeHead(200, { "content-type": mime[path.extname(file)] ?? "application/octet-stream" });
  res.end(data);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const address = server.address();
const base = `http://127.0.0.1:${address.port}`;
const browser = await chromium.launch({ headless: true });

try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.goto(`${base}/manual-mitigations`);
  await page.getByRole("button", { name: "New mitigation" }).focus();
  await page.keyboard.press("Enter");
  await page.getByLabel("Name").fill("Edge diversion");
  await page.getByLabel("Action template").selectOption("1");
  await page.getByLabel("edge-a").check();
  await page.getByLabel("edge-b").check();
  await page.getByRole("textbox", { name: /^Prefix/ }).first().fill("192.0.2.0/24");
  await page.getByRole("button", { name: "Add to ordered set" }).click();
  await page.getByLabel("Action template").selectOption("3");
  await page.getByLabel("edge-a").check();
  await page.getByLabel("edge-b").check();
  const neighbors = page.getByRole("textbox", { name: /^Neighbor/ });
  await neighbors.nth(0).fill("203.0.113.1");
  await neighbors.nth(1).fill("203.0.113.2");
  await page.getByLabel("Also add MSS clamp per router").check();
  const mssInterfaces = page.getByLabel("MSS interface");
  await mssInterfaces.nth(0).fill("GigabitEthernet0/0");
  await mssInterfaces.nth(1).fill("GigabitEthernet0/1");
  await page.getByRole("button", { name: "Add to ordered set" }).click();
  await page.getByRole("button", { name: "Move action 2 earlier" }).click();
  await page.getByRole("button", { name: "Save complete set" }).click();
  await page.getByText("revision 1", { exact: true }).waitFor();
  if (presets[0].actions[0].device_id !== 20) throw new Error("bulk target ordering was not saved");

  await page.getByTitle("Run this saved mitigation once").click();
  await page.getByLabel("Target router").selectOption("10");
  const overridePrefix = page.getByRole("combobox", { name: /^Prefix/ });
  if (await overridePrefix.inputValue()) throw new Error("router override retained inventory-bound parameters");
  await overridePrefix.selectOption("203.0.113.0/24");
  await page.getByText("temporary override", { exact: true }).waitFor();
  if (presets[0].actions[0].device_id !== 20 || presets[0].actions[0].params.prefix !== "192.0.2.0/24") throw new Error(`override mutated saved preset: ${JSON.stringify(presets[0].actions[0])}`);
  await page.getByRole("button", { name: "Preview exact plan" }).click();
  await page.getByText("Exact server preview").waitFor();
  await page.getByRole("button", { name: "Execute reviewed plan" }).click();
  await page.getByText("Running", { exact: true }).waitFor();
  presets[0].archived_at = new Date().toISOString();
  await page.reload();
  if (!page.url().includes("bundle=601")) throw new Error("accepted bundle identity was lost on reload");
  await page.getByText("All actions succeeded").waitFor({ timeout: 8000 });
  await page.getByText("Edge diversion", { exact: true }).waitFor();
  await page.evaluate(() => {
    window.scrollTo(0, 0);
    document.querySelector("main")?.scrollTo(0, 0);
  });
  await fs.mkdir(shots, { recursive: true });
  await page.screenshot({ path: path.join(shots, "manual-desktop.png"), fullPage: true });
  presets[0].archived_at = null;

  await page.goto(`${base}/rules`);
  await page.getByTitle("Manage mitigation actions").click();
  await page.getByRole("combobox").filter({ has: page.locator("option") }).nth(0).selectOption("101").catch(async () => {
    await page.locator("select").filter({ hasText: "Edge diversion" }).selectOption("101");
  });
  await page.getByRole("button", { name: "Import copy" }).click();
  await page.getByText(/Imported an independent copy/).waitFor();
  if (!lastRuleSave?.preset_id || lastRuleSave.actions.some((action) => action.id != null)) throw new Error("rule import was not an independent copy");

  await page.goto(`${base}/mitigations?tab=history`);
  await page.getByRole("tab", { name: "History" }).click();
  await page.getByRole("button", { name: "View" }).first().click();
  await page.getByRole("button", { name: "Reconcile device state" }).click();
  await page.getByLabel("Operator note").fill("Compared live route state");
  await page.getByRole("button", { name: "Read and reconcile" }).click();
  await page.getByText(/Reconciliation: Conflict/).waitFor();
  await page.getByRole("button", { name: "Close" }).last().click();
  await page.getByRole("button", { name: "View" }).nth(1).click();
  await page.getByRole("button", { name: "Roll back" }).click();
  await page.getByRole("button", { name: "Execute reviewed rollback" }).click();
  await page.getByText("failed", { exact: true }).waitFor();

  triggerOnly = true;
  const presetCount = presets.length;
  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, isMobile: true });
  await mobile.goto(`${base}/manual-mitigations`);
  await mobile.getByText("Manual mitigations", { exact: true }).waitFor();
  await mobile.getByRole("button", { name: "Run once" }).first().click();
  await mobile.getByLabel("Action template").selectOption("1");
  await mobile.getByLabel("edge-a").check();
  await mobile.getByRole("textbox", { name: /^Prefix/ }).fill("192.0.2.44/32");
  await mobile.getByRole("button", { name: "Add to ordered set" }).click();
  if (await mobile.getByRole("button", { name: "Save complete set" }).count()) throw new Error("trigger-only user can save presets");
  await mobile.getByRole("button", { name: "Preview exact plan" }).click();
  await mobile.getByText("Exact server preview").waitFor();
  if (presets.length !== presetCount) throw new Error("ad-hoc run created a preset");
  if (lastPreviewInput.preset_id != null || lastPreviewInput.preset_revision != null) throw new Error("ad-hoc preview carried saved-preset ownership");
  await mobile.screenshot({ path: path.join(shots, "manual-mobile.png"), fullPage: true });
  await mobile.close();
  await page.close();
  process.stdout.write(JSON.stringify({ ok: true, screenshots: [path.join(shots, "manual-desktop.png"), path.join(shots, "manual-mobile.png")] }) + "\n");
} finally {
  await browser.close();
  await new Promise((resolve) => server.close(resolve));
}
