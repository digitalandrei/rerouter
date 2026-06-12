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
// Domain types (shape mirrors backend-rust API responses; refine as the
// controller endpoints solidify).
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

export type TelemetryFreshness = "live" | "cached" | "degraded" | "unknown";

export interface Asset {
  id: number;
  name: string;
  kind: "prefix" | "ip" | "service";
  value: string;
  acknowledged: boolean;
  locked: boolean;
  telemetry_freshness: TelemetryFreshness;
  reachability: string;
}

export interface Provider {
  id: number;
  name: string;
  kind: "cloudflare" | "bgp_rtbh" | "flowspec" | "scrubber";
  reachability: string;
}

export interface DetectionRule {
  id: number;
  asset_id: number;
  name: string;
  enabled: boolean;
  automatic_reroute_enabled: boolean;
  reroute_template_id: number | null;
}

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
  /** Validated server-side against the template's parameter schema. */
  parameters: Record<string, unknown>;
  /** Mandatory free-text reason; audited (docs/doctrine.md §9). */
  reason: string;
  /** Typed confirmation phrase for high-safety templates (docs/doctrine.md §8). */
  confirmation: string;
}

export interface Alert {
  id: number;
  event_type: string;
  asset_id: number | null;
  rule_id: number | null;
  created_at: string;
  payload: Record<string, unknown>;
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
  healthy: boolean;
  operating_mode: OperatingMode;
  telemetry: TelemetryFreshness;
  global_lock: boolean;
  active_reroutes: number;
  unresolved_uncertain: number;
}

// ---------------------------------------------------------------------------
// Core request helper
// ---------------------------------------------------------------------------

const AUTH_PATHS = ["/api/auth/login", "/api/auth/totp", "/api/auth/reauth"];

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

  if (res.status === 401 && !AUTH_PATHS.includes(path)) {
    // Session expired or revoked: leave the app entirely.
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
    /** Fresh password+TOTP, required before high-safety reroutes. */
    reauth: (password: string, code: string) =>
      request<void>("/api/auth/reauth", {
        method: "POST",
        body: { password, code },
      }),
  },

  health: () => request<{ ok: boolean }>("/api/health"),
  status: () => request<SystemStatus>("/api/status"),

  assets: {
    list: () => request<Asset[]>("/api/assets"),
    get: (id: number) => request<Asset>(`/api/assets/${id}`),
    create: (asset: Partial<Asset>) =>
      request<Asset>("/api/assets", { method: "POST", body: asset }),
    update: (id: number, asset: Partial<Asset>) =>
      request<Asset>(`/api/assets/${id}`, { method: "PUT", body: asset }),
    remove: (id: number) =>
      request<void>(`/api/assets/${id}`, { method: "DELETE" }),
    testTelemetry: (id: number) =>
      request<unknown>(`/api/assets/${id}/test/telemetry`, { method: "POST" }),
    rediscover: (id: number) =>
      request<unknown>(`/api/assets/${id}/rediscover`, { method: "POST" }),
    live: (id: number) => request<unknown>(`/api/assets/${id}/live`),
  },

  providers: {
    list: () => request<Provider[]>("/api/providers"),
    get: (id: number) => request<Provider>(`/api/providers/${id}`),
    create: (provider: Partial<Provider>) =>
      request<Provider>("/api/providers", { method: "POST", body: provider }),
    update: (id: number, provider: Partial<Provider>) =>
      request<Provider>(`/api/providers/${id}`, {
        method: "PUT",
        body: provider,
      }),
    remove: (id: number) =>
      request<void>(`/api/providers/${id}`, { method: "DELETE" }),
  },

  rules: {
    list: () => request<DetectionRule[]>("/api/rules"),
    get: (id: number) => request<DetectionRule>(`/api/rules/${id}`),
    create: (rule: Partial<DetectionRule>) =>
      request<DetectionRule>("/api/rules", { method: "POST", body: rule }),
    update: (id: number, rule: Partial<DetectionRule>) =>
      request<DetectionRule>(`/api/rules/${id}`, { method: "PUT", body: rule }),
    remove: (id: number) =>
      request<void>(`/api/rules/${id}`, { method: "DELETE" }),
  },

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

  alerts: {
    list: () => request<Alert[]>("/api/alerts"),
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
