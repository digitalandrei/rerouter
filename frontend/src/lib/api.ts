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
  enabled_for_monitoring: boolean;
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
}

export interface DeviceTestResult {
  ok: boolean;
  vendor?: string;
  model?: string;
  os_version?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Rules and Alerts
// ---------------------------------------------------------------------------

export interface Rule {
  id: number;
  name: string;
  target_kind: "interface" | "asset";
  interface_id: number | null;
  device_id: number | null;
  asset_id: number | null;
  metric: string;
  operator: ">" | "<";
  threshold_value: number;
  duration_seconds: number;
  consecutive_samples: number;
  severity: string;
  enabled: boolean;
  automatic_reroute_enabled: boolean;
  reroute_template_id: number | null;
}

export interface Alert {
  id: number;
  event_type: string;
  severity: string;
  device_id: number | null;
  interface_id: number | null;
  asset_id: number | null;
  rule_id: number | null;
  created_at: string;
  payload: Record<string, unknown>;
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
  asset_id: number;
  provider_id: number;
  template: string;
  parameters: Record<string, unknown>;
  state: RerouteState;
  safety_level: string;
  reason: string | null;
  initiated_by: string;
  created_at: string;
  updated_at: string;
}

export interface ManualReroutePayload {
  asset_id: number;
  provider_id: number;
  template: string;
  parameters: Record<string, unknown>;
  reason: string;
  confirmation: string;
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
  "/api/auth/reauth",
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
    login: (email: string, password: string) =>
      request<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: { email, password },
      }),
    totp: (code: string) =>
      request<TotpResponse>("/api/auth/totp", {
        method: "POST",
        body: { code },
      }),
    logout: () => request<void>("/api/auth/logout", { method: "POST" }),
    me: () => request<SessionUser>("/api/auth/me"),
    /** Fresh password+TOTP, required before high-safety reroutes. */
    reauth: (password: string, code: string) =>
      request<void>("/api/auth/reauth", {
        method: "POST",
        body: { password, code },
      }),
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
    interfaces: (id: number) =>
      request<Interface[]>(`/api/devices/${id}/interfaces`),
  },

  interfaces: {
    get: (id: number) => request<Interface>(`/api/interfaces/${id}`),
    update: (id: number, data: { enabled_for_monitoring: boolean }) =>
      request<Interface>(`/api/interfaces/${id}`, {
        method: "PUT",
        body: data,
      }),
    metrics: (id: number, minutes?: number) =>
      request<Sample[]>(
        `/api/interfaces/${id}/metrics${minutes !== undefined ? `?minutes=${minutes}` : ""}`,
      ),
  },

  rules: {
    list: () => request<Rule[]>("/api/rules"),
    get: (id: number) => request<Rule>(`/api/rules/${id}`),
    create: (rule: Omit<Rule, "id">) =>
      request<Rule>("/api/rules", { method: "POST", body: rule }),
    update: (id: number, rule: Partial<Rule>) =>
      request<Rule>(`/api/rules/${id}`, { method: "PUT", body: rule }),
    remove: (id: number) =>
      request<void>(`/api/rules/${id}`, { method: "DELETE" }),
  },

  alerts: {
    list: () => request<Alert[]>("/api/alerts"),
  },

  // Legacy reroute endpoints kept for placeholder pages
  reroutes: {
    list: () => request<Reroute[]>("/api/reroutes"),
    manual: (payload: ManualReroutePayload) =>
      request<Reroute>("/api/reroutes/manual", {
        method: "POST",
        body: payload,
      }),
    cancel: (id: number) =>
      request<Reroute>(`/api/reroutes/${id}/cancel`, { method: "POST" }),
    acknowledgeUncertain: (id: number, note: string) =>
      request<Reroute>(`/api/reroutes/${id}/acknowledge-uncertain`, {
        method: "POST",
        body: { note },
      }),
  },

  audit: {
    list: () => request<AuditEntry[]>("/api/audit"),
  },

  locks: {
    setGlobal: (reason: string) =>
      request<void>("/api/locks/global", { method: "POST", body: { reason } }),
    clearGlobal: () =>
      request<void>("/api/locks/global", { method: "DELETE" }),
  },

  settings: {
    get: () => request<SystemSettings>("/api/settings"),
    put: (settings: Partial<SystemSettings>) =>
      request<SystemSettings>("/api/settings", {
        method: "PUT",
        body: settings,
      }),
  },
};
