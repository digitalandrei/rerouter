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

export const AUTH_RETURN_TO_KEY = "rerouter.auth.returnTo";

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
  /** Present exactly once, after first-factor enrollment is confirmed. */
  recovery_codes?: string[];
}

/**
 * Operating mode (docs/reroute-engine.md "Operating mode"):
 * - "observe" (default): autonomous response is disabled. Authorized manual
 *   runs and reverts still require exact server preparation. Reviewed actions
 *   use one-use plans; direct actions publish durable bundles first.
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
  // Last periodic SSH-probe outcome — the display state. A reroute pushes config
  // over SSH, so this gates a mitigation.
  //   "reachable"    — answered at privileged EXEC (#) AND the account can run every
  //                    command a reroute needs (all command-access checks pass).
  //   "no_privilege" — SSH works but the account can't do the work: not privilege 15,
  //                    OR reached # but was denied a required command (parser view).
  //   "unreachable"  — could not connect / authenticate.
  //   "unknown"      — not probed yet.
  ssh_status: "reachable" | "no_privilege" | "unreachable" | "unknown";
  // The last probe's message — for no_privilege, the exact denied commands.
  last_ssh_error: string | null;
  last_ssh_ok_at: string | null;
  // Automation stability: when SSH became (and stayed) reachable, and whether it
  // has been reachable long enough (>=1 min) for AUTOMATIC mitigations to resume.
  // While false, auto reroutes targeting this device are held; manual is allowed.
  ssh_reachable_since: string | null;
  automation_stable: boolean;
  // The reroute gate's 60s recency short-circuit (SSH answered in the last minute).
  // A stricter internal signal; the reachability-test gives the live truth.
  ssh_recent: boolean;
}

/** Result of POST /devices/{id}/reachability-test — the reroute gate's view. */
export interface ReachabilityResult {
  ok: boolean;
  ssh_ok: boolean;
  ssh_status: "reachable" | "no_privilege" | "unreachable" | "unknown";
  stable: boolean;
  via_recency: boolean;
  last_ssh_ok_at: string | null;
  ssh_reachable_since: string | null;
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

// --- Flow telemetry (NetFlow/IPFIX) ---------------------------------------

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
  dropped_bucket_backlog: number;
  quality_bucket_ts: string | null;
  iface_complete: boolean | null;
  port_complete: boolean | null;
  asn_complete: boolean | null;
  talker_complete: boolean | null;
  iface_dropped: number | null;
  port_dropped: number | null;
  asn_dropped: number | null;
  talker_dropped: number | null;
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
  /** Peer liveness inside the SNMP freshness window. Absent on API builds that
   *  predate the field — callers must treat `undefined` as fresh, never stale. */
  inventory_fresh?: boolean;
  /** When out_prefix_list / in_route_map / out_route_map were last read over
   *  SSH; null = never discovered, undefined = API build without the field. */
  route_context_discovered_at?: string | null;
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
  /** Do these saved params still validate against freshly discovered inventory?
   *  "drifted" = the router's route-map / prefix-list / neighbour moved under
   *  them. Absent on API builds that predate the check — read as "ok". */
  inventory_state?: "ok" | "drifted";
  /** Concrete, operator-actionable reason for the drift (names the neighbour /
   *  prefix-list to re-pick). Rendered verbatim — never paraphrased. */
  inventory_drift_reason?: string | null;
  /** When the drift check last ran; null = never checked, undefined = API build
   *  without the field. */
  inventory_checked_at?: string | null;
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
  /** Whether a recovered rule may autonomously revert the run it owns. Clear
   *  detection criteria remain configured independently in recovery_mode. */
  automatic_revert_enabled: boolean;
  /** Opt-in: operators may manually run this rule's defined actions (off by
   *  default). Still gated like any manual reroute at apply time. */
  manual_apply_enabled: boolean;
  reroute_template_id: number | null;
  action_count?: number;
  actions?: RuleAction[];
  /** Optimistic revision for atomic replacement/import of the complete action set. */
  actions_revision?: number;
  // Resolved target labels + live evaluation snapshot (from rule_states).
  interface_name?: string | null;
  device_name?: string | null;
  current_state?: "clear" | "matching" | "firing" | "recovered_awaiting_revert" | null;
  current_value?: number | null;
  last_evaluated_at?: string | null;
  // Live progression toward firing (from rule_states).
  consecutive_match_count?: number | null;
  first_matched_at?: string | null;
  /** Set by the controller when inventory drift on an attached action forced
   *  `automatic_reroute_enabled` to 0. The rule keeps detecting and alerting;
   *  only unattended execution was switched off. Re-arming is never automatic —
   *  it goes back through the normal arming gate. null/absent = not disarmed. */
  auto_disarmed_at?: string | null;
  auto_disarmed_reason?: string | null;
  active_run_id?: number | null;
  active_run_count?: number;
}

export interface Alert {
  id: number;
  event_type: string;
  severity: string;
  device_id: number | null;
  interface_id: number | null;
  rule_id: number | null;
  bundle_id?: number | null;
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
  bundle_id?: number | null;
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
  source_preset_id?: number | null;
  source_preset_name?: string | null;
  source_preset_revision?: number | null;
  source?: ActionSource | null;
  verification_mode?: VerificationMode;
  routing_verified?: boolean;
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
  reconcile_available: boolean;
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
  before_state?: unknown;
  after_state?: unknown;
  verification_states?: unknown[];
  mutation_effect?: "changed" | "noop" | "pending" | "unknown";
  predicted_noop?: boolean;
}

export interface ManualReroutePayload {
  template_id: number;
  targets: { device_id: number; params: Record<string, unknown> }[];
  reason?: string;
  dry_run?: boolean;
  preview_token?: string;
}

export interface ActionResultsResponse {
  results: RerouteResult[];
  /** Short-lived, actor-bound, single-use authority in either operating mode. */
  preview_token?: string | null;
}

export interface RuleClearResponse {
  ok: boolean;
  cleared: boolean;
  results?: RerouteResult[];
  preview_token?: string | null;
  bundle_id?: number | null;
  operating_mode?: "observe" | "enforce";
}

export interface ReconcileRerouteResponse {
  ok: boolean;
  outcome: "changed" | "not_applied" | "conflict";
  message: string;
}

/** One ordered action accepted by preset and atomic rule-action APIs. */
export interface ActionDraft {
  id?: number;
  reroute_template_id: number;
  device_id: number;
  params: Record<string, unknown>;
  enabled?: boolean;
  auto_target?: string | null;
}

export interface PresetAction extends ActionDraft {
  template_name?: string;
  template_display_name?: string | null;
  device_name?: string;
  validation_status?: "needs_preview" | "valid" | "invalid";
  validation_error?: string | null;
  checked_at?: string | null;
}

export type PresetRunSummary = Partial<RerouteBundle> & { bundle_id: number; state: string; created_at: string };

export interface MitigationPreset {
  id: number;
  name: string;
  description: string | null;
  revision: number;
  archived_at: string | null;
  actions: PresetAction[];
  created_at: string;
  updated_at: string;
  recent_runs?: PresetRunSummary[];
  active_runs?: PresetRunSummary[];
  validation_status?: "needs_preview" | "valid" | "invalid";
  validation_error?: string | null;
  definition_status?: "draft" | "needs_setup" | "ready";
  missing_references?: string[];
  checked_at?: string | null;
}

export interface ManualMitigationPreview {
  plan_id: number | null;
  preview_token: string | null;
  results: RerouteResult[];
  source?: ActionSource | null;
  expires_at?: string | null;
  operating_mode: "observe" | "enforce";
  projections?: DeviceProjection[];
  revert_after_seconds?: number | null;
  verification_mode?: VerificationMode;
  routing_verified?: boolean;
}

export type VerificationMode = "routing" | "configuration_only";
export interface ManualMitigationCapabilities {
  configuration_test_device_ids: number[];
  configuration_test_templates: string[];
  device_cooldown_until?: Record<string, string>;
}

export interface ManualMitigationAccepted {
  bundle_id: number;
  async: true;
  already_admitted?: boolean;
}

// ---------------------------------------------------------------------------
// Ordered mitigation bundles (plans/015)
//
// One authorized activation of one rule's ordered action set. A confirmed
// apply no longer blocks on ~2 SSH sessions per action: the API returns 202 with
// a bundle id and the run continues server-side. Progress is polled from
// GET /api/reroute-bundles/{id} until the state is terminal.
// ---------------------------------------------------------------------------

/** Bundle lifecycle. Terminal: succeeded | aborted | compensated |
 *  compensation_blocked | failed. */
export type BundleState =
  | "planned"
  | "running"
  | "succeeded"
  | "aborted"
  | "compensating"
  | "compensated"
  | "compensation_blocked"
  | "failed";

const BUNDLE_TERMINAL_STATES: ReadonlySet<string> = new Set([
  "succeeded",
  "aborted",
  "compensated",
  "compensation_blocked",
  "failed",
]);

export function isBundleTerminal(state: string): boolean {
  return BUNDLE_TERMINAL_STATES.has(state);
}

export function configurationOnlyRunStatus(state: string): string {
  switch (state) {
    case "succeeded": return "Configuration verified; routing not verified.";
    case "compensated": return "Configuration verification failed; changes were reverted; routing not verified.";
    case "compensation_blocked": return "Configuration recovery is blocked and needs review; routing not verified.";
    case "failed": case "aborted": return "Configuration verification failed; routing was not verified.";
    default: return "Configuration verification is in progress; routing is not being verified.";
  }
}

export function bundleVerificationMode(bundle: Pick<RerouteBundle, "verification_mode" | "source">): VerificationMode {
  return bundle.verification_mode ?? bundle.source?.verification_mode ?? "routing";
}

export interface RerouteBundleAction {
  /** Null while the durable bundle ledger entry is queued/not yet attempted. */
  reroute_id: number | null;
  /** Execution order within the bundle (rule_actions.position). */
  position: number | null;
  device_id: number;
  device_name: string | null;
  state: string;
  failure_reason: string | null;
  template_display_name: string | null;
  template_name?: string | null;
  params?: Record<string, unknown> | null;
}

export interface RecoveryRunSummary {
  id: number;
  parent_bundle_id: number | null;
  state: BundleState;
  total_actions: number;
  completed_actions: number;
  started_at: string | null;
  finished_at: string | null;
  failure_reason: string | null;
  dismiss?: { available: boolean; confirmation_phrase?: string | null };
}

export interface RunSummary {
  id: number;
  rule_id: number | null;
  trigger_type: string;
  state: BundleState;
  failure_policy: string;
  total_actions: number;
  completed_actions: number;
  failure_reason: string | null;
  started_at: string | null;
  finished_at: string | null;
  /** Siblings that RAN and were NOT reversed. Non-empty means traffic is still
   *  diverted and a manual rollback is required — never hide this. */
  source_preset_id?: number | null;
  source_preset_name?: string | null;
  source_preset_revision?: number | null;
  source?: ActionSource | null;
  created_at?: string;
  triggered_by?: string | null;
  execution_state?: string;
  lifecycle_state?: string;
  active?: boolean;
  remaining_mutations?: number;
  unknown_effects?: number;
  device_ids?: number[];
  device_names?: string[];
  affected_devices?: Array<{ id?: number; name?: string | null; device_id?: number; device_name?: string | null }>;
  remaining_changes?: number;
  parent_bundle_id?: number | null;
  recovery_bundle_id?: number | null;
  latest_recovery_bundle_id?: number | null;
  latest_recovery?: RecoveryRunSummary | null;
  automatic_recovery_block_reason?: string | null;
  recovery_deadline?: string | null;
  automatic_recovery_cancelled_at?: string | null;
  revert?: { available: boolean; block_reasons: string[]; noop?: boolean };
  verification_mode?: VerificationMode;
  routing_verified?: boolean;
  take_control?: { available: boolean; block_reasons: string[] };
}
export interface RunDetail extends RunSummary {
  actions: RerouteBundleAction[];
  still_applied_reroute_ids: number[];
}
export type RerouteBundle = RunDetail;

export interface RerouteBundlePage {
  items: RunSummary[];
  page: number;
  per_page: number;
  total: number;
}

export interface DeviceProjection {
  device_id: number;
  before_config: unknown;
  after_config: unknown;
  revert_config: unknown;
  changes: Array<{ action_index: number; template_name: string; effect: "change" | "already_satisfied" }>;
  completeness: string;
  blockers: string[];
  read_at: string;
}

export interface ActionSetInspection {
  devices: DeviceProjection[];
  blockers: string[];
  prepared_actions: Array<Record<string, unknown>>;
}

export interface RoutingPolicyInventory {
  device_id: number;
  read_at: string | null;
  completeness: "complete" | "partial" | "stale";
  blockers: string[];
  prefix_lists: Array<{ name: string; entries: Array<{ sequence: number; action: "permit" | "deny"; prefix: string; ge?: number; le?: number }>; referenced_by: string[] }>;
  route_maps: Array<{ name: string; clauses: Array<{ sequence: number; action: string; matches: Array<{ kind: string; value: string }>; sets: Array<{ kind: string; value: string }> }>; references: string[] }>;
  peer_bindings: Array<{ neighbor_ip: string; local_asn: number; address_family: "ipv4"; direction: "out"; policy_kind: string; policy_name: string; scope: "direct" | "inherited" | "ambiguous" }>;
}

export interface ActionSource {
  kind: "manual" | "preset" | "rule" | "rollback" | "recovery";
  preset_id?: number | null;
  preset_name?: string | null;
  preset_revision?: number | null;
  rule_id?: number | null;
  name?: string | null;
  verification_mode?: VerificationMode;
  routing_verified?: boolean;
  admission_kind?: "direct";
  preparation_phase?: "published" | "preparing" | "prepared";
  operator_request_id?: string;
}

/** 202 after reviewed confirmation or direct durable admission. */
export interface BundleAcceptedResponse {
  bundle_id: number;
  async: true;
  already_admitted?: boolean;
  state: string;
  total_actions: number;
  failure_policy: string;
  /** Actions that could not be resolved to run at all (already skipped). */
  results: RerouteResult[];
}

/** A rule apply answers with a preview or a durable background bundle handle. */
export type RuleApplyResponse = ActionResultsResponse | BundleAcceptedResponse;

export function isBundleAccepted(
  res: RuleApplyResponse,
): res is BundleAcceptedResponse {
  return (res as BundleAcceptedResponse).async === true;
}

/** 409 body when a bundle does not fit the remaining global rate budget.
 *  All-or-nothing admission: NOTHING was executed. */
export interface BundleNotAdmitted {
  error: "bundle_not_admitted";
  bundle_id: number;
  detail: string;
  total_actions: number;
}

export function asBundleNotAdmitted(body: unknown): BundleNotAdmitted | null {
  if (typeof body !== "object" || body === null) return null;
  const b = body as Partial<BundleNotAdmitted>;
  return b.error === "bundle_not_admitted" && typeof b.bundle_id === "number"
    ? (b as BundleNotAdmitted)
    : null;
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
  type: string; // "ip" | "cidr" | "asn" | "int" | "seq" | "string"
  label?: string;
  required?: boolean;
  // Resolved by the controller at apply time, never entered by an operator (the
  // prefix-list sequence is chosen from a read taken inside the apply session).
  // Rendered read-only; the preview shows "<auto-seq>" in its place.
  deferred?: boolean;
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
  // A command still carries the "<auto-seq>" placeholder: the plan is a faithful
  // preview but not sendable as-is. The controller resolves the prefix-list
  // sequence from a fresh in-session read and re-renders before anything is sent.
  sequence_pending?: boolean;
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
  options: { method?: string; body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  const { method = "GET", body, signal } = options;

  const res = await fetch(path, {
    method,
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
    signal,
  });

  if (
    res.status === 401 &&
    !NO_REDIRECT_PATHS.includes(path) &&
    window.location.pathname !== "/login"
  ) {
    // Session expired or revoked: leave the app entirely. (Never redirect when
    // already on /login — that would loop.)
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    try { window.sessionStorage.setItem(AUTH_RETURN_TO_KEY, returnTo); } catch { /* storage may be disabled */ }
    window.location.assign(`/login?returnTo=${encodeURIComponent(returnTo)}`);
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
    login: (
      email: string,
      password: string,
      remember = false,
      enrollmentCode?: string,
    ) =>
      request<LoginResponse>("/api/auth/login", {
        method: "POST",
        body: {
          email,
          password,
          remember,
          enrollment_code: enrollmentCode || undefined,
        },
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
    /** The "can we mitigate this device right now?" check — runs the SSH
     *  reachability decision the reroute gate uses (live probe unless SSH answered
     *  at privileged EXEC in the last 60s), classified into ssh_status. */
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
    clear: (
      id: number,
      body?: { reason?: string; dry_run?: boolean; preview_token?: string },
    ) =>
      request<RuleClearResponse>(`/api/rules/${id}/clear`, {
        method: "POST",
        body: body ?? {},
      }),
    /** Manually run a rule's configured actions. Both operating modes
     *  require the actor-bound one-use preview token; Observe only disables
     *  autonomous execution. */
    apply: (
      id: number,
      body?: { reason?: string; dry_run?: boolean; preview_token?: string; direct_run?: boolean; request_id?: string },
    ) =>
      request<RuleApplyResponse>(`/api/rules/${id}/apply`, {
        method: "POST",
        body: body ?? {},
      }),
    /** Attach one action. `position` is ALWAYS sent explicitly: execution order
     *  is a safety property (additive actions must be able to run before
     *  destructive ones), and the server defaults it to 0, which would collapse
     *  every action onto one rank. */
    addAction: (
      ruleId: number,
      body: {
        reroute_template_id: number;
        device_id: number;
        params: Record<string, unknown>;
        /** Execution rank; ties break by insertion id (server: ORDER BY position, id). */
        position: number;
        /** "flow_dst_host" to auto-target the attacked dst IP (flow rules only). */
        auto_target?: string | null;
      },
    ) => request<Rule>(`/api/rules/${ruleId}/actions`, { method: "POST", body }),
    removeAction: (ruleId: number, actionId: number) =>
      request<Rule>(`/api/rules/${ruleId}/actions/${actionId}`, {
        method: "DELETE",
      }),
    /**
     * Set the execution order of a rule's whole action set in one request.
     * Order is a safety property — a scrubber bundle must advertise before it
     * withdraws — so positions are renumbered server-side in one transaction
     * rather than by deleting and re-adding rows, which can drop an action when
     * a re-add is refused. `order` must list exactly this rule's action ids.
     */
    reorderActions: (ruleId: number, order: number[]) =>
      request<{ actions: RuleAction[] }>(
        `/api/rules/${ruleId}/actions/reorder`,
        { method: "POST", body: { order } },
      ),
    /** Atomically replace a rule's complete ordered action set. The server
     *  rejects stale revisions and disarms automatic execution on success. */
    saveActions: (
      ruleId: number,
      body: {
        revision: number;
        actions: ActionDraft[];
        preset_id?: number;
        preset_revision?: number;
      },
    ) =>
      request<Rule>(`/api/rules/${ruleId}/actions`, {
        method: "PUT",
        body,
      }),
  },

  mitigationPresets: {
    list: () => request<MitigationPreset[]>("/api/mitigation-presets"),
    get: (id: number): Promise<MitigationPreset> => request<MitigationPreset>(`/api/mitigation-presets/${id}`).then((preset) => ({ ...preset, recent_runs: preset.recent_runs?.map((run) => ({ ...run, source_preset_revision: run.source_preset_revision ?? run.source?.preset_revision })), active_runs: preset.active_runs?.map((run) => ({ ...run, source_preset_revision: run.source_preset_revision ?? run.source?.preset_revision })) } as MitigationPreset)),
    create: (body: { name: string; description?: string; actions: ActionDraft[] }) =>
      request<MitigationPreset>("/api/mitigation-presets", { method: "POST", body }),
    update: (
      id: number,
      body: { name: string; description?: string; revision: number; actions: ActionDraft[] },
    ) => request<MitigationPreset>(`/api/mitigation-presets/${id}`, { method: "PUT", body }),
    remove: (id: number, revision: number) =>
      request<{ ok: true }>(`/api/mitigation-presets/${id}`, {
        method: "DELETE",
        body: { revision },
      }),
  },

  manualMitigations: {
    capabilities: () => request<ManualMitigationCapabilities>("/api/manual-mitigations/capabilities"),
    preview: (body: {
      preset_id?: number;
      preset_revision?: number;
      actions: ActionDraft[];
      reason?: string;
      revert_after_seconds?: number;
      verification_mode?: VerificationMode;
    }) =>
      request<ManualMitigationPreview>("/api/manual-mitigations/preview", {
        method: "POST",
        body,
      }),
    apply: (body: { plan_id: number; preview_token: string }) =>
      request<ManualMitigationAccepted>("/api/manual-mitigations/apply", {
        method: "POST",
        body,
      }),
    run: (body: {
      preset_id?: number;
      preset_revision?: number;
      actions: ActionDraft[];
      reason?: string;
      revert_after_seconds?: number;
      verification_mode?: VerificationMode;
      request_id: string;
    }) => request<ManualMitigationAccepted>("/api/manual-mitigations/run", { method: "POST", body }),
  },

  /** Progress and lifecycle of an ordered mitigation bundle. */
  bundles: {
    list: (opts?: { page?: number; per_page?: number; lifecycle?: string; trigger_type?: string; rule_id?: number; preset_id?: number; logical_only?: boolean; q?: string; source_kind?: string; device?: string; created_from?: string; created_to?: string; signal?: AbortSignal }) => {
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(opts ?? {})) if (key !== "signal" && value !== undefined) query.set(key, String(value));
      return request<RerouteBundlePage | RunSummary[]>(`/api/reroute-bundles${query.size ? `?${query}` : ""}`, { signal: opts?.signal });
    },
    get: (id: number, signal?: AbortSignal) => request<RunDetail>(`/api/reroute-bundles/${id}`, { signal }),
    revert: (id: number, body: { dry_run: boolean; reason?: string; plan_id?: number; preview_token?: string; direct_run?: boolean; request_id?: string }) =>
      request<ManualMitigationPreview | ManualMitigationAccepted>(`/api/reroute-bundles/${id}/revert`, { method: "POST", body }),
    takeControl: (id: number) => request<{ ok: true; bundle_id: number; automatic_recovery_cancelled: true }>(`/api/reroute-bundles/${id}/take-control`, { method: "POST" }),
    dismissRecovery: (id: number, confirmation: string) => request<{ ok: true; bundle_id: number; dismissed?: true; already_dismissed?: true }>(`/api/reroute-bundles/${id}/dismiss-recovery`, { method: "POST", body: { confirmation } }),
  },

  actionSets: {
    inspect: (actions: ActionDraft[]) => request<ActionSetInspection>("/api/action-sets/inspect", { method: "POST", body: { actions } }),
  },

  routingPolicies: {
    get: (deviceId: number) => request<RoutingPolicyInventory>(`/api/devices/${deviceId}/routing-policies`),
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
    list: (opts?: { limit?: number; offset?: number; days?: number; exclude_bundled_action_lifecycle?: boolean }) => {
      const p = new URLSearchParams();
      if (opts?.limit !== undefined) p.set("limit", String(opts.limit));
      if (opts?.offset !== undefined) p.set("offset", String(opts.offset));
      if (opts?.days !== undefined) p.set("days", String(opts.days));
      if (opts?.exclude_bundled_action_lifecycle) p.set("exclude_bundled_action_lifecycle", "true");
      const qs = p.toString();
      return request<AlertPage>(`/api/alerts${qs ? `?${qs}` : ""}`);
    },
  },

  reroutes: {
    list: () => request<Reroute[]>("/api/reroutes"),
    get: (id: number) => request<RerouteDetail>(`/api/reroutes/${id}`),
    manual: (payload: ManualReroutePayload) =>
      request<ActionResultsResponse>("/api/reroutes/manual", {
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
    reconcile: (id: number, note: string) =>
      request<ReconcileRerouteResponse>(`/api/reroutes/${id}/reconcile`, {
        method: "POST",
        body: { note },
      }),
    rollback: (
      id: number,
      body: { reason?: string; dry_run?: boolean; preview_token?: string },
    ) =>
      request<{ result: RerouteResult; preview_token?: string | null }>(
        `/api/reroutes/${id}/rollback`,
        { method: "POST", body },
      ),
  },

  users: {
    list: () => request<User[]>("/api/users"),
    create: (payload: {
      email: string;
      name: string;
      role: string;
      password: string;
    }) =>
      request<User & { enrollment_code: string }>("/api/users", {
        method: "POST",
        body: payload,
      }),
    update: (id: number, payload: { name?: string; role?: string }) =>
      request<User>(`/api/users/${id}`, { method: "PUT", body: payload }),
    remove: (id: number) =>
      request<{ ok: true }>(`/api/users/${id}`, { method: "DELETE" }),
    reset2fa: (id: number) =>
      request<{ ok: true; enrollment_code: string }>(
        `/api/users/${id}/reset-2fa`,
        { method: "POST" },
      ),
  },

  audit: {
    list: () => request<AuditEntry[]>("/api/audit"),
    listPage: (
      params: { actor?: string; action?: string; entity?: string; after?: string; before?: string; page?: number; limit?: number } = {},
      signal?: AbortSignal,
    ) => {
      const query = new URLSearchParams();
      for (const [key, value] of Object.entries(params)) if (value !== undefined && value !== "") query.set(key, String(value));
      return request<{ rows: AuditEntry[]; page: number; limit: number; has_more: boolean }>(`/api/audit${query.size ? `?${query}` : ""}`, { signal });
    },
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
