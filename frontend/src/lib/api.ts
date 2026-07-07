/**
 * Typed fetch wrapper for the Rerouter controller API.
 *
 * Contract (docs/architecture.md, docs/security.md):
 * - ONE authenticated REST API under /api/, served by rerouter-controller on
 *   127.0.0.1:9277 and reached exclusively via the Nginx reverse proxy (the
 *   Vite dev server mirrors this proxy — see vite.config.ts).
 * - Same-origin requests only; the session cookie is the sole credential, so
 *   every request uses `credentials: "include"`.
 * - Any 401 outside the auth flow means the session is gone: hard-redirect to
 *   /login so no stale operational data stays on screen.
 */

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly body?: unknown,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// ---------------------------------------------------------------------------
// Domain types — exact field names from the API contract
// ---------------------------------------------------------------------------

export interface User {
  id: number;
  email: string;
  name: string;
  role: string;
  twofa_enrolled: boolean;
  created_at: string;
}

export interface SessionUser {
  id: number;
  email: string;
  name: string;
  roles: string[];
  permissions: string[];
}

export interface LoginResponse {
  /** Always true after a correct password: TOTP is mandatory (RFC 6238). */
  totp_required: boolean;
  /** Present only on first login, before TOTP enrollment is completed. */
  totp_enrollment?: {
    otpauth_url: string;
    secret: string;
  };
}

export interface TotpResponse {
  user: SessionUser;
}

/**
 * Operating mode (docs/reroute-engine.md "Operating mode"):
 * - "observe" (default): safe read-only / alert-only — NO reroute executes,
 *   automatic or manual; alerts carry the actions that WOULD have run. The UI
 *   must show a persistent observe-mode banner.
 * - "enforce": execution allowed, still gated by every other safety rule.
 */
export type OperatingMode = "observe" | "enforce";

export interface SystemSettings {
  operating_mode: OperatingMode;
  automatic_actions_enabled: boolean;
  global_lock: boolean;
  [key: string]: unknown;
}

export interface SystemStatus {
  operating_mode: OperatingMode;
  devices_total: number;
  devices_reachable: number;
  interfaces_monitored: number;
  active_rule_matches: number;
  alerts_24h: number;
  telemetry_stale_count: number;
}

// ---------------------------------------------------------------------------
// SNMP Device types
// ---------------------------------------------------------------------------

export interface Device {
  id: number;
  name: string;
  hostname: string;
  snmp_version: string;
  snmp_port: number;
  enabled: boolean;
  reachable: boolean;
  vendor: string | null;
  model: string | null;
  os_version: string | null;
  sys_name: string | null;
  sys_uptime: string | null;
  last_poll_at: string | null;
  last_error: string | null;
  poll_interval_seconds: number;
  interface_count: number;
  // SSH access captured at onboarding (for future CLI reroute actions; unused in
  // observe mode). Secrets are never returned — only whether one is stored.
  ssh_username: string | null;
  ssh_port: number;
  ssh_auth_method: "password" | "key" | null;
  ssh_configured: boolean;
  // OpenSSH public-key line (not a secret) — shown for enrollment on the router.
  // null until a key is generated in-app or derived from a pasted private key.
  ssh_public_key: string | null;
  // Control-plane reachability for mitigations. SSH is authoritative (a reroute
  // pushes config over SSH); telnet port-open is an informational secondary signal.
  telnet_port: number;
  telnet_reachable: boolean;
  last_telnet_ok_at: string | null;
  last_ssh_ok_at: string | null;
  // Soft "SSH answered lately" hint (60s recency window). The live truth comes
  // from POST /devices/{id}/reachability-test.
  ssh_recent: boolean;
}

/** Result of POST /devices/{id}/reachability-test — the reroute gate's view. */
export interface ReachabilityResult {
  ok: boolean;
  ssh_ok: boolean;
  telnet_open: boolean;
  via_recency: boolean;
  last_ssh_ok_at: string | null;
  ssh_error: string | null;
}

/** Payload for enrolling a device. SSH access is optional (password XOR key). */
export interface DeviceCreate {
  name: string;
  hostname: string;
  snmp_version: string;
  snmp_port: number;
  community: string;
  poll_interval_seconds: number;
  ssh_username?: string;
  ssh_port?: number;
  ssh_auth_method?: "password" | "key";
  ssh_password?: string;
  ssh_private_key?: string;
  ssh_key_passphrase?: string;
  /** With ssh_auth_method "key": generate an in-app keypair instead of pasting
   *  a private key. The created device returns ssh_public_key for enrollment. */
  ssh_generate_key?: boolean;
}

export interface InterfaceMetrics {
  sampled_at: string;
  valid_sample: boolean;
  rx_bps: number;
  tx_bps: number;
  rx_pps: number;
  tx_pps: number;
  rx_util_percent: number;
  tx_util_percent: number;
  in_errors: number;
  out_errors: number;
}

export interface Interface {
  id: number;
  device_id: number;
  if_index: number;
  if_name: string;
  if_descr: string | null;
  if_alias: string | null;
  if_speed_bps: number | null;
  admin_status: string;
  oper_status: string;
  /** Management/transit path: disruptive shutdown/MSS actions are blocked on it. */
  protected: boolean;
  metrics: InterfaceMetrics | null;
}

export interface Sample {
  sampled_at: string;
  rx_bps: number;
  tx_bps: number;
  rx_pps: number;
  tx_pps: number;
  rx_util_percent: number;
  tx_util_percent: number;
  /** Per-interval error counts (errors during this poll interval). */
  in_errors: number;
  out_errors: number;
  /** Per-interval discard counts (packets dropped during this interval). */
  in_discards: number;
  out_discards: number;
  /** Transceiver optics — null for interfaces without a pluggable. */
  temp_c: number | null;
  tx_power_dbm: number | null;
  rx_power_dbm: number | null;
}

// --- Flow telemetry (NetFlow/IPFIX) — read-only second source -------------

/** One ranked row from /api/devices/{id}/flows/top. Fields beyond the common
 *  aggregate vary by dimension (talkers / ports / traffic). Counts are raw
 *  (sampled); est_* are scaled by the effective sampling rate. */
export interface FlowTopRow {
  est_bytes: number;
  est_pkts: number;
  raw_bytes: number;
  raw_pkts: number;
  sampling_rate: number;
  estimated: boolean;
  low_confidence: boolean;
  direction: "ingress" | "egress";
  // talkers
  src_addr?: string;
  dst_addr?: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol?: number;
  // ports
  port?: number;
  port_kind?: "src" | "dst";
  // as
  asn?: number;
  as_kind?: "src" | "dst";
  // traffic
  if_index?: number;
  interface_id?: number | null;
  if_name?: string;
}

export type FlowDimension = "talkers" | "ports" | "as" | "traffic";

export interface FlowTopResponse {
  dimension: FlowDimension;
  minutes: number;
  interface_filtered: boolean;
  rows: FlowTopRow[];
}

/** One (interface, direction) the searched 5-tuple was observed on. */
export interface FlowDetailIface {
  if_index: number;
  if_name?: string | null;
  direction: "ingress" | "egress";
  device_id: number;
  est_bytes: number;
  est_pkts: number;
  raw_bytes: number;
  raw_pkts: number;
  sampling_rate: number;
  estimated: boolean;
  low_confidence: boolean;
  first_seen: string;
  last_seen: string;
}

export interface FlowDetailResponse {
  minutes: number;
  src_addr: string;
  dst_addr: string;
  src_port?: number | null;
  dst_port?: number | null;
  protocol: number;
  interfaces: FlowDetailIface[];
}

export interface FlowExporter {
  id: number;
  source_addr: string;
  observation_domain: number;
  configured_sampling_rate: number | null;
  reported_sampling_rate: number | null;
  snmp_derived_rate: number | null;
  effective_sampling_rate: number;
  sampling_source: "config" | "reported" | "snmp_derived" | "default" | "unknown";
  sampling_confidence: "high" | "low";
  snmp_xcal_ratio: number | null;
  last_packet_at: string | null;
  template_count: number;
  datagrams_total: number;
  dropped_no_template: number;
  dropped_malformed: number;
}

export interface DeviceTestResult {
  ok: boolean;
  vendor?: string;
  model?: string;
  os_version?: string;
  error?: string;
}

export interface SshCommandResult {
  command: string;
  output: string;
}

export interface SshTestResult {
  ok: boolean;
  fingerprint?: string;
  pinned_now?: boolean;
  results?: SshCommandResult[];
  error?: string;
}

/** One command-access probe result (Settings → command access). */
export interface CapabilityCheck {
  name: string;
  command: string;
  ok: boolean;
  detail: string;
}

export interface BgpPeer {
  id: number;
  device_id: number;
  peer_remote_addr: string;
  peer_remote_as: number | null;
  local_as: number | null;
  peer_state: string | null;
  peer_admin_status: string | null;
  label: string | null;
  /** Outbound route-map's prefix-list, discovered over SSH (bgp_advertise_*). */
  out_prefix_list: string | null;
  /** Currently-applied inbound/outbound route-map names (discovered over SSH);
   *  the Route-Map Change picker suggests these and snapshots them for revert. */
  in_route_map: string | null;
  out_route_map: string | null;
  last_polled_at: string | null;
}

export interface BgpNetwork {
  id: number;
  device_id: number;
  prefix: string;
  last_discovered_at: string | null;
}

export interface RtbhCommunity {
  id: number;
  label: string;
  kind: string; // "standard" | "large"
  community: string;
  tag: number;
}

// ---------------------------------------------------------------------------
// Rules and Alerts
// ---------------------------------------------------------------------------

/** An email alert recipient. `event_types` is ["*"] for "all events". */
export interface NotificationRecipient {
  id: number;
  email: string;
  verified: boolean;
  event_types: string[];
}

/** A Teams incoming-webhook endpoint (URL is never returned to the client). */
export interface WebhookEndpoint {
  id: number;
  name: string;
  enabled: boolean;
  event_types: string[];
}

export interface RuleAction {
  id: number;
  reroute_template_id: number;
  template_name: string;
  template_display_name: string | null;
  device_id: number;
  device_name: string;
  params: Record<string, unknown>;
  enabled: boolean;
  position: number;
  /** "flow_dst_host" = resolve the null-route/blackhole host (/32 or /128) from
   *  the rule's flows at fire/apply time; null/absent = static prefix in params. */
  auto_target?: string | null;
}

/** Comparison operators accepted by the rules API (backend rules.rs validation). */
export type RuleOperator = ">" | "<" | ">=" | "<=" | "==" | "!=";

export interface Rule {
  id: number;
  name: string;
  target_kind: "interface" | "interface_group";
  interface_id: number | null;
  device_id: number | null;
  metric: string;
  /** 'single' (per-interface) or 'sum' (summed across member_interface_ids). */
  metric_aggregation?: "single" | "sum";
  /** Member interface ids for a summed rule (may span devices). */
  member_interface_ids?: number[];
  // Flow-metric selector (null for SNMP interface metrics).
  flow_direction?: "ingress" | "egress" | null;
  flow_protocol?: number | null;
  flow_port?: number | null;
  flow_port_kind?: "src" | "dst" | null;
  operator: RuleOperator;
  threshold_value: number;
  duration_seconds: number;
  consecutive_samples: number;
  recovery_mode?: "auto" | "threshold" | "manual";
  recovery_threshold_value?: number | null;
  recovery_window_seconds?: number | null;
  recovery_consecutive_samples?: number | null;
  severity: string;
  enabled: boolean;
  automatic_reroute_enabled: boolean;
  /** Opt-in: operators may manually apply this rule's actions from a firing alert
   *  (off by default). Still gated like any manual reroute at apply time. */
  manual_apply_enabled: boolean;
  reroute_template_id: number | null;
  action_count?: number;
  actions?: RuleAction[];
  // Resolved target labels + live evaluation snapshot (from rule_states).
  interface_name?: string | null;
  device_name?: string | null;
  current_state?: "clear" | "matching" | "firing" | null;
  current_value?: number | null;
  last_evaluated_at?: string | null;
  // Live progression toward firing (from rule_states).
  consecutive_match_count?: number | null;
  first_matched_at?: string | null;
}

export interface Alert {
  id: number;
  event_type: string;
  severity: string;
  device_id: number | null;
  interface_id: number | null;
  rule_id: number | null;
  device_name: string | null;
  interface_name: string | null;
  rule_name: string | null;
  created_at: string;
  payload: Record<string, unknown>;
}

export interface AlertPage {
  rows: Alert[];
  total: number;
  limit: number;
  offset: number;
}

// ---------------------------------------------------------------------------
// Legacy types kept for Reroutes/ManualReroute/Audit pages (placeholders)
// ---------------------------------------------------------------------------

export type RerouteState =
  | "planned"
  | "pending"
  | "running"
  | "verifying"
  | "succeeded"
  | "failed"
  | "uncertain";

export interface Reroute {
  id: number;
  device_id: number | null;
  device_name: string | null;
  reroute_template_id: number | null;
  template_name: string | null;
  template_display_name: string | null;
  trigger_type: string;
  state: RerouteState;
  reason: string | null;
  success: boolean | null;
  verification_status: string | null;
  failure_reason: string | null;
  rule_id: number | null;
  triggered_by: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface RerouteStep {
  step_number: number;
  description: string | null;
  mode: string | null;
  state: string;
}
export interface RerouteOutput {
  step_number: number;
  request: string | null;
  response: string | null;
  status: string | null;
}
export interface RerouteVerification {
  method: string;
  expected: string | null;
  observed: string | null;
  result: string;
}
export interface RerouteDetail extends Reroute {
  steps: RerouteStep[];
  outputs: RerouteOutput[];
  verifications: RerouteVerification[];
}

/** Result of executing/previewing one action against one device. */
export interface RerouteResult {
  executed: boolean;
  reroute_id?: number | null;
  state?: string | null;
  message: string;
  blocked_reason?: string | null;
  would_run?: RenderedPlan | null;
  /** Rollback (undo) command set for `would_run`, shown in observe/dry-run
   *  previews so the action can be reversed by hand. null when none. */
  would_run_rollback?: RenderedPlan | null;
  device_id: number;
  device_name?: string | null;
  /** Set on a rule-apply result for a flow auto-target action: the resolved host
   *  CIDR (/32 or /128) and whether the flow sampling was low-confidence. */
  auto_target?: string | null;
  auto_target_low_confidence?: boolean;
}

export interface ManualReroutePayload {
  template_id: number;
  targets: { device_id: number; params: Record<string, unknown> }[];
  reason?: string;
  dry_run?: boolean;
}

export interface Lock {
  id: number;
  scope: string;
  scope_ref: string | null;
  reason: string | null;
  kind: string;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Reroute action templates (the allowlisted, parameterized mitigations)
// ---------------------------------------------------------------------------

export interface TemplateParamSpec {
  type: string; // "ip" | "cidr" | "asn" | "int" | "string"
  label?: string;
  required?: boolean;
  // UI prefill hint: "bgp_local_as" | "bgp_peer" | "announced_prefix" | "rtbh_tag"
  //   | "interface_name" | "peer_out_prefix_list" | "route_map" | "bgp_direction"
  source?: string;
  // this param must be a subprefix of the named param's CIDR (AWS-SG style)
  subprefix_of?: string;
  // closed set of allowed values -> rendered as a dropdown (e.g. direction in|out)
  enum?: string[];
}

export interface Template {
  id: number;
  name: string;
  display_name: string | null;
  description: string | null;
  provider_type: string;
  mode: string;
  automatic_allowed: boolean;
  parameter_schema: Record<string, TemplateParamSpec>;
  plan: unknown;
  verification: unknown;
  rollback_template_id: number | null;
  enabled: boolean;
}

export interface RenderedPlan {
  template_id: number;
  template_name: string;
  config_mode: boolean;
  commands: string[];
  verify: { command: string; expect: string | null; reject: string | null } | null;
}

export interface RenderResult {
  ok: boolean;
  plan?: RenderedPlan;
  // The rollback (undo) command set, so an operator can see — and if needed run
  // by hand — exactly what reverses this action. null when the template has no
  // paired rollback template.
  rollback?: RenderedPlan | null;
  error?: string;
}

export interface AuditEntry {
  id: number;
  actor: string;
  action: string;
  subject: string;
  ip: string;
  created_at: string;
  details: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Core request helper
// ---------------------------------------------------------------------------

// Paths whose 401 is handled by the caller (the auth forms / the session probe)
// rather than by the global "session gone -> /login" redirect. `/api/auth/me` is
// the mount-time session probe: a 401 there just means "anonymous", so it must
// NOT trigger a redirect — otherwise the /login page probes, 401s, redirects to
// /login, and loops.
const NO_REDIRECT_PATHS = [
  "/api/auth/login",
  "/api/auth/totp",
  "/api/auth/me",
];

async function request<T>(
  path: string,
  options: { method?: string; body?: unknown } = {},
): Promise<T> {
  const { method = "GET", body } = options;

  const res = await fetch(path, {
    method,
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (
    res.status === 401 &&
    !NO_REDIRECT_PATHS.includes(path) &&
    window.location.pathname !== "/login"
  ) {
    // Session expired or revoked: leave the app entirely. (Never redirect when
    // already on /login — that would loop.)
    window.location.assign("/login");
    throw new ApiError(401, "Session expired");
  }

  let payload: unknown = undefined;
  const text = await res.text();
  if (text.length > 0) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = text;
    }
  }

  if (!res.ok) {
    const message =
      typeof payload === "object" && payload !== null && "error" in payload
        ? String((payload as { error: unknown }).error)
        : `${res.status} ${res.statusText}`;
    throw new ApiError(res.status, message, payload);
  }

  return payload as T;
}

// ---------------------------------------------------------------------------
// Canonical endpoint helpers (one per contract endpoint)
// ---------------------------------------------------------------------------

export const api = {
  auth: {
    login: (email: string, password: string, remember = false) =>
      request<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: { email, password, remember },
      }),
    totp: (code: string) =>
      request<TotpResponse>("/api/auth/totp", {
        method: "POST",
        body: { code },
      }),
    logout: () => request<void>("/api/auth/logout", { method: "POST" }),
    me: () => request<SessionUser>("/api/auth/me"),
  },

  status: () => request<SystemStatus>("/api/status"),

  devices: {
    list: () => request<Device[]>("/api/devices"),
    get: (id: number) => request<Device>(`/api/devices/${id}`),
    create: (device: DeviceCreate) =>
      request<Device>("/api/devices", { method: "POST", body: device }),
    update: (id: number, device: Partial<Device>) =>
      request<Device>(`/api/devices/${id}`, { method: "PUT", body: device }),
    remove: (id: number) =>
      request<void>(`/api/devices/${id}`, { method: "DELETE" }),
    test: (id: number) =>
      request<DeviceTestResult>(`/api/devices/${id}/test`, { method: "POST" }),
    discover: (id: number) =>
      request<{ discovered: number }>(`/api/devices/${id}/discover`, {
        method: "POST",
      }),
    sshTest: (id: number) =>
      request<SshTestResult>(`/api/devices/${id}/ssh-test`, { method: "POST" }),
    generateKey: (id: number) =>
      request<{ ok: boolean; public_key: string; fingerprint: string }>(
        `/api/devices/${id}/ssh-generate-key`,
        { method: "POST" },
      ),
    sshCapabilities: (id: number) =>
      request<{ ok: boolean; checks?: CapabilityCheck[]; error?: string }>(
        `/api/devices/${id}/ssh-capabilities`,
        { method: "POST" },
      ),
    /** The "can we mitigate this device right now?" check. Refreshes telnet and
     *  runs the SSH reachability decision the reroute gate uses (live probe
     *  unless SSH answered in the last 60s). */
    reachabilityTest: (id: number) =>
      request<ReachabilityResult>(`/api/devices/${id}/reachability-test`, {
        method: "POST",
      }),
    interfaces: (id: number) =>
      request<Interface[]>(`/api/devices/${id}/interfaces`),
    bgpPeers: (id: number) =>
      request<BgpPeer[]>(`/api/devices/${id}/bgp-peers`),
    routeMaps: (id: number) =>
      request<string[]>(`/api/devices/${id}/route-maps`),
    discoverBgp: (id: number) =>
      request<{ discovered: number }>(`/api/devices/${id}/discover-bgp`, {
        method: "POST",
      }),
    bgpNetworks: (id: number) =>
      request<BgpNetwork[]>(`/api/devices/${id}/bgp-networks`),
    discoverPrefixes: (id: number) =>
      request<{ discovered: number }>(`/api/devices/${id}/discover-prefixes`, {
        method: "POST",
      }),
    updateBgpPeer: (deviceId: number, peerId: number, label: string | null) =>
      request<{ ok: boolean }>(`/api/devices/${deviceId}/bgp-peers/${peerId}`, {
        method: "PATCH",
        body: { label },
      }),
  },

  interfaces: {
    get: (id: number) => request<Interface>(`/api/interfaces/${id}`),
    metrics: (id: number, minutes?: number) =>
      request<Sample[]>(
        `/api/interfaces/${id}/metrics${minutes !== undefined ? `?minutes=${minutes}` : ""}`,
      ),
    setProtected: (id: number, protectedFlag: boolean) =>
      request<{ ok: boolean; protected: boolean }>(
        `/api/interfaces/${id}/protected`,
        { method: "PATCH", body: JSON.stringify({ protected: protectedFlag }) },
      ),
  },

  flows: {
    top: (
      deviceId: number,
      opts: {
        dimension: FlowDimension;
        minutes?: number;
        metric?: "bytes" | "pkts";
        interfaceId?: number;
        portKind?: "src" | "dst";
        asKind?: "src" | "dst";
      },
    ) => {
      const p = new URLSearchParams({ dimension: opts.dimension });
      if (opts.minutes !== undefined) p.set("minutes", String(opts.minutes));
      if (opts.metric) p.set("metric", opts.metric);
      if (opts.interfaceId !== undefined) p.set("interface_id", String(opts.interfaceId));
      if (opts.portKind) p.set("port_kind", opts.portKind);
      if (opts.asKind) p.set("as_kind", opts.asKind);
      return request<FlowTopResponse>(`/api/devices/${deviceId}/flows/top?${p.toString()}`);
    },
    exporters: (deviceId: number) =>
      request<FlowExporter[]>(`/api/devices/${deviceId}/flow-exporters`),
    search: (opts: {
      deviceId?: number;
      src?: string;
      dst?: string;
      port?: number;
      protocol?: number;
      ifIndex?: number;
      minutes?: number;
      metric?: "bytes" | "pkts";
      limit?: number;
    }) => {
      const p = new URLSearchParams();
      if (opts.deviceId !== undefined) p.set("device_id", String(opts.deviceId));
      if (opts.src) p.set("src", opts.src);
      if (opts.dst) p.set("dst", opts.dst);
      if (opts.port !== undefined) p.set("port", String(opts.port));
      if (opts.protocol !== undefined) p.set("protocol", String(opts.protocol));
      if (opts.ifIndex !== undefined) p.set("if_index", String(opts.ifIndex));
      if (opts.minutes !== undefined) p.set("minutes", String(opts.minutes));
      if (opts.metric) p.set("metric", opts.metric);
      if (opts.limit !== undefined) p.set("limit", String(opts.limit));
      return request<{ minutes: number; rows: FlowTopRow[] }>(
        `/api/flows/search?${p.toString()}`,
      );
    },
    suggest: (field: "src" | "dst" | "port", q: string, deviceId?: number) => {
      const p = new URLSearchParams({ field, q });
      if (deviceId !== undefined) p.set("device_id", String(deviceId));
      return request<string[]>(`/api/flows/suggest?${p.toString()}`);
    },
    detail: (opts: {
      deviceId?: number;
      src: string;
      dst: string;
      srcPort?: number | null;
      dstPort?: number | null;
      protocol: number;
      minutes?: number;
    }) => {
      const p = new URLSearchParams();
      if (opts.deviceId !== undefined) p.set("device_id", String(opts.deviceId));
      p.set("src", opts.src);
      p.set("dst", opts.dst);
      if (opts.srcPort != null) p.set("src_port", String(opts.srcPort));
      if (opts.dstPort != null) p.set("dst_port", String(opts.dstPort));
      p.set("protocol", String(opts.protocol));
      if (opts.minutes !== undefined) p.set("minutes", String(opts.minutes));
      return request<FlowDetailResponse>(`/api/flows/detail?${p.toString()}`);
    },
  },

  rules: {
    list: () => request<Rule[]>("/api/rules"),
    get: (id: number) => request<Rule>(`/api/rules/${id}`),
    create: (rule: Omit<Rule, "id"> & { interface_ids?: number[] }) =>
      request<Rule>("/api/rules", { method: "POST", body: rule }),
    update: (id: number, rule: Partial<Rule>) =>
      request<Rule>(`/api/rules/${id}`, { method: "PUT", body: rule }),
    remove: (id: number) =>
      request<void>(`/api/rules/${id}`, { method: "DELETE" }),
    clear: (id: number) =>
      request<{ ok: boolean; cleared: boolean }>(`/api/rules/${id}/clear`, {
        method: "POST",
      }),
    /** Manually apply a firing rule's configured actions (the supervised
     *  alternative to automatic execution). Gated server-side: requires the
     *  rule's manual_apply_enabled, the rule to be firing, and (to actually
     *  execute) enforce mode + trigger_manual_reroute. In observe mode each
     *  result carries the would-run plan and nothing executes. */
    apply: (id: number, body?: { reason?: string; dry_run?: boolean }) =>
      request<{ results: RerouteResult[] }>(`/api/rules/${id}/apply`, {
        method: "POST",
        body: body ?? {},
      }),
    addAction: (
      ruleId: number,
      body: {
        reroute_template_id: number;
        device_id: number;
        params: Record<string, unknown>;
        /** "flow_dst_host" to auto-target the attacked dst IP (flow rules only). */
        auto_target?: string | null;
      },
    ) => request<Rule>(`/api/rules/${ruleId}/actions`, { method: "POST", body }),
    removeAction: (ruleId: number, actionId: number) =>
      request<Rule>(`/api/rules/${ruleId}/actions/${actionId}`, {
        method: "DELETE",
      }),
  },

  templates: {
    list: () => request<Template[]>("/api/templates"),
    get: (id: number) => request<Template>(`/api/templates/${id}`),
    render: (id: number, params: Record<string, unknown>) =>
      request<RenderResult>(`/api/templates/${id}/render`, {
        method: "POST",
        body: { params },
      }),
  },

  rtbh: {
    list: () => request<RtbhCommunity[]>("/api/rtbh-communities"),
    create: (body: { label: string; kind?: string; community: string; tag: number }) =>
      request<RtbhCommunity[]>("/api/rtbh-communities", { method: "POST", body }),
    remove: (id: number) =>
      request<{ ok: boolean }>(`/api/rtbh-communities/${id}`, { method: "DELETE" }),
  },

  alerts: {
    list: (opts?: { limit?: number; offset?: number; days?: number }) => {
      const p = new URLSearchParams();
      if (opts?.limit !== undefined) p.set("limit", String(opts.limit));
      if (opts?.offset !== undefined) p.set("offset", String(opts.offset));
      if (opts?.days !== undefined) p.set("days", String(opts.days));
      const qs = p.toString();
      return request<AlertPage>(`/api/alerts${qs ? `?${qs}` : ""}`);
    },
  },

  reroutes: {
    list: () => request<Reroute[]>("/api/reroutes"),
    get: (id: number) => request<RerouteDetail>(`/api/reroutes/${id}`),
    manual: (payload: ManualReroutePayload) =>
      request<{ results: RerouteResult[] }>("/api/reroutes/manual", {
        method: "POST",
        body: payload,
      }),
    cancel: (id: number) =>
      request<{ ok: boolean }>(`/api/reroutes/${id}/cancel`, { method: "POST" }),
    acknowledgeUncertain: (id: number, note: string) =>
      request<{ ok: boolean }>(`/api/reroutes/${id}/acknowledge-uncertain`, {
        method: "POST",
        body: { note },
      }),
    rollback: (id: number) =>
      request<RerouteResult>(`/api/reroutes/${id}/rollback`, { method: "POST" }),
  },

  users: {
    list: () => request<User[]>("/api/users"),
    create: (payload: {
      email: string;
      name: string;
      role: string;
      password: string;
    }) => request<User>("/api/users", { method: "POST", body: payload }),
    update: (id: number, payload: { name?: string; role?: string }) =>
      request<User>(`/api/users/${id}`, { method: "PUT", body: payload }),
    remove: (id: number) =>
      request<{ ok: true }>(`/api/users/${id}`, { method: "DELETE" }),
    reset2fa: (id: number) =>
      request<{ ok: true }>(`/api/users/${id}/reset-2fa`, { method: "POST" }),
  },

  audit: {
    list: () => request<AuditEntry[]>("/api/audit"),
  },

  notifications: {
    eventTypes: () => request<string[]>("/api/notifications/event-types"),
    recipients: () =>
      request<NotificationRecipient[]>("/api/notifications/recipients"),
    addRecipient: (body: { email: string; event_types: string[] }) =>
      request<{ id: number }>("/api/notifications/recipients", {
        method: "POST",
        body,
      }),
    removeRecipient: (id: number) =>
      request<{ ok: boolean }>(`/api/notifications/recipients/${id}`, {
        method: "DELETE",
      }),
    testRecipient: (id: number) =>
      request<{ ok: boolean }>(`/api/notifications/recipients/${id}/test`, {
        method: "POST",
      }),
    webhooks: () => request<WebhookEndpoint[]>("/api/notifications/webhooks"),
    addWebhook: (body: { name: string; url: string; event_types: string[] }) =>
      request<{ id: number }>("/api/notifications/webhooks", {
        method: "POST",
        body,
      }),
    removeWebhook: (id: number) =>
      request<{ ok: boolean }>(`/api/notifications/webhooks/${id}`, {
        method: "DELETE",
      }),
    testWebhook: (id: number) =>
      request<{ ok: boolean }>(`/api/notifications/webhooks/${id}/test`, {
        method: "POST",
      }),
  },

  locks: {
    list: () => request<Lock[]>("/api/locks"),
    setGlobal: (reason: string) =>
      request<void>("/api/locks/global", { method: "POST", body: { reason } }),
    clearGlobal: () =>
      request<void>("/api/locks/global", { method: "DELETE" }),
  },

  settings: {
    get: () => request<SystemSettings>("/api/settings"),
    // `password` + `totp_code` are the step-up re-auth the server requires when
    // ARMING the system (operating_mode -> enforce, or automatic_actions_enabled
    // -> true). Ignored for all other/safe changes.
    put: (settings: Partial<SystemSettings> & { password?: string; totp_code?: string }) =>
      request<SystemSettings>("/api/settings", {
        method: "PUT",
        body: settings,
      }),
  },
};
