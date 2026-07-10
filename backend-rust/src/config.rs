//! Controller configuration. Mirrors config.example.toml. Secrets come from the
//! environment, never from this file.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub database: Database,
    #[serde(default)]
    pub auth: Auth,
    pub telemetry: Telemetry,
    pub detection: Detection,
    pub safety: Safety,
    pub reroute: Reroute,
    #[serde(default)]
    pub retention: Retention,
    #[serde(default)]
    pub flow: Flow,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Server {
    /// MUST be a loopback address. Validated in `validate` (both the file and
    /// the built-in-defaults load paths).
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Database {
    pub url_env: String,
}

/// Session / login-throttling knobs. The session-cookie signing secret
/// (SESSION_SECRET) and the credential-encryption key (SECRETS_KEY) come from
/// the environment, never from this file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Auth {
    pub session_ttl_hours: u64,
    /// Session TTL when the user ticks "remember me" at login (default 7 days).
    pub remember_me_ttl_hours: u64,
    /// Absolute inactivity limit for a fully authenticated session.
    pub idle_timeout_minutes: u64,
    /// A password-only session may exist only long enough to complete 2FA.
    pub pre_2fa_ttl_minutes: u64,
    /// Failed logins (per email + real client IP) before lockout.
    pub lockout_threshold: u32,
    pub lockout_minutes: u64,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            session_ttl_hours: 12,
            remember_me_ttl_hours: 168,
            idle_timeout_minutes: 60,
            pre_2fa_ttl_minutes: 10,
            lockout_threshold: 5,
            lockout_minutes: 15,
        }
    }
}

// SMTP is configured entirely via the environment (SMTP_HOST / SMTP_PORT /
// SMTP_USERNAME / SMTP_PASSWORD / SMTP_FROM) — see alerts::mailer.

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Telemetry {
    pub metrics_rollup_seconds: u64,
    pub reachability_interval_seconds: u64,
    pub stale_after_seconds: u64,
    pub jitter_percent: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Detection {
    pub default_consecutive_samples: u32,
    pub default_min_duration_seconds: u64,
    /// Compatibility-only legacy field. Recovery persistence now lives on each
    /// rule (`recovery_*`); presence produces a startup warning.
    #[serde(rename = "hysteresis_seconds")]
    pub deprecated_hysteresis_seconds: Option<u64>,
}

/// Global operating mode. `Observe` is the safe read-only / alert-only posture:
/// NO reroute executes — automatic or manual. Detection still runs, and when a
/// rule fires the alert carries the rendered plan of the actions that *would*
/// have run. The authoritative runtime value lives in
/// `system_settings.operating_mode` (changed from /settings by an admin,
/// audited); this config value is only the startup fallback if that row is
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperatingMode {
    #[default]
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Safety {
    /// SAFETY: defaults to Observe (read-only / alert-only).
    pub operating_mode: OperatingMode,
    pub automatic_actions_enabled: bool,
    /// Global circuit breaker: at most N executed actions per window across all
    /// devices (0 = unlimited).
    pub global_action_rate_limit_count: u32,
    pub global_action_rate_limit_window_seconds: u64,
    /// Per-rule re-fire throttle: after a rule's actions run, that rule is in
    /// cooldown for this long (0 = none).
    pub same_rule_cooldown_seconds: u64,
    /// Per-device throttle: after any action on a device, that device is in
    /// cooldown for this long (0 = none).
    pub same_device_cooldown_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Reroute {
    pub require_verification: bool,
}

/// Retention windows (in days) enforced by the controller's retention cleanup
/// task (see `scheduler::retention_cleanup`). The shipped operational default
/// keeps short-term data for 48 hours (2 days).
///
/// `traffic_samples_days`, `flow_buckets_days`, `alerts_days` and
/// `rule_events_days` are actively pruned — the short-term telemetry + detection
/// history the app is built around. `reroute_logs_days` is advisory and NOT
/// auto-pruned: the reroute action log is the safety trail of traffic-moving
/// actions, is low-volume (nothing executes in observe mode), and its rows are
/// live state-machine state — a non-terminal / `uncertain` reroute holds a device
/// lock — so it needs deliberate state-aware pruning, never a blanket delete.
/// `audit_logs` (the security/admin trail) is likewise never auto-pruned.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Retention {
    /// interface_samples — per-interface SNMP history (was a hardcoded 70 min).
    pub traffic_samples_days: u32,
    /// flow_*_buckets — NetFlow/sFlow per-minute aggregates (was 70 min).
    pub flow_buckets_days: u32,
    /// alerts — detection/reroute/security alert events (was never pruned).
    pub alerts_days: u32,
    /// rule_events — detection history (matched/fired/cleared). Actively pruned.
    pub rule_events_days: u32,
    /// reroute action log. Advisory; NOT auto-pruned (safety trail — see above).
    pub reroute_logs_days: u32,
}

/// NetFlow v9/sFlow v5 collector. A second, passive telemetry source (see
/// docs/flow-telemetry.md). OFF by default. Unlike `server.bind` (loopback-only,
/// enforced in `validate`), the flow listener must receive UDP from the router,
/// so its bind address is operator-chosen — a deliberate, documented exposure.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Flow {
    pub enabled: bool,
    /// Explicit acknowledgement that flow-derived rules may trigger automatic
    /// actions. Off by default even when collection itself is enabled.
    pub automatic_actions_enabled: bool,
    /// UDP bind address for the collector (e.g. a management address reachable
    /// from the exporting router). NOT loopback-restricted. Shared by both the
    /// NetFlow and the sFlow listeners.
    pub bind_addr: String,
    /// NetFlow v9 UDP port (the classic flow listener).
    pub bind_port: u16,
    /// Enable the sFlow v5 listener (a SECOND decoder feeding the same buckets).
    /// Off by default; only binds when `enabled && sflow_enabled`.
    pub sflow_enabled: bool,
    /// UDP port for the sFlow listener (sFlow's default is 6343).
    pub sflow_port: u16,
    /// Only parse datagrams whose source IP resolves to an enrolled device.
    pub allowlist_enrolled_only: bool,
    /// Aggregation bucket width in seconds. (Bucket retention is unified under
    /// [retention].flow_buckets_days — see `scheduler::retention_cleanup`.)
    pub bucket_seconds: u64,
    /// 5-tuples retained per bucket/interface/direction; the tail is truncated
    /// (logged, never silent — the count survives in flow_iface_buckets).
    pub top_k_talkers: usize,
    /// Fallback sampling rate when an exporter reports none and no per-exporter
    /// override is set. A sampled-looking exporter that falls through to this is
    /// flagged low-confidence (blocks flow-driven automatic actions).
    pub default_sampling_rate: u32,
    /// Whole-interface flow estimates must remain within this fraction of the
    /// contemporaneous SNMP rate before they may drive an automatic action.
    pub snmp_corroboration_min_ratio: f64,
    /// Flow estimates (including filtered selectors) may never exceed this
    /// multiple of the contemporaneous SNMP rate for automatic-action trust.
    pub snmp_corroboration_max_ratio: f64,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            enabled: false,
            automatic_actions_enabled: false,
            bind_addr: "0.0.0.0".into(),
            bind_port: 2055,
            sflow_enabled: false,
            sflow_port: 6343,
            allowlist_enrolled_only: true,
            bucket_seconds: 60,
            top_k_talkers: 100,
            default_sampling_rate: 1,
            snmp_corroboration_min_ratio: 0.25,
            snmp_corroboration_max_ratio: 2.0,
        }
    }
}

// Built-in defaults — these MUST mirror config.example.toml exactly. Used when
// the config file is missing (fresh installs before the operator customizes
// anything); `Config::load_or_default` logs a warning in that case.

impl Default for Server {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:9277".into(),
        }
    }
}

impl Default for Database {
    fn default() -> Self {
        Self {
            url_env: "DATABASE_URL".into(),
        }
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self {
            metrics_rollup_seconds: 15,
            // How often the poll loop probes device SSH reachability (a no-command
            // liveness session, ~one login/logout). 3 min by default — light on the
            // device; the scheduler floors this at 60s regardless.
            reachability_interval_seconds: 180,
            stale_after_seconds: 90,
            jitter_percent: 15,
        }
    }
}

impl Default for Detection {
    fn default() -> Self {
        Self {
            default_consecutive_samples: 3,
            default_min_duration_seconds: 30,
            deprecated_hysteresis_seconds: None,
        }
    }
}

impl Default for Safety {
    fn default() -> Self {
        Self {
            // SAFETY: observe (read-only / alert-only), automatic actions OFF.
            operating_mode: OperatingMode::Observe,
            automatic_actions_enabled: false,
            global_action_rate_limit_count: 3,
            global_action_rate_limit_window_seconds: 600,
            same_rule_cooldown_seconds: 900,
            same_device_cooldown_seconds: 300,
        }
    }
}

impl Default for Reroute {
    fn default() -> Self {
        Self {
            require_verification: true,
        }
    }
}

impl Default for Retention {
    fn default() -> Self {
        Self {
            traffic_samples_days: 2,
            flow_buckets_days: 2,
            alerts_days: 2,
            rule_events_days: 2,
            reroute_logs_days: 365,
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw =
            std::fs::read_to_string(path).with_context(|| format!("reading config {path}"))?;
        let cfg: Config = toml::from_str(&raw).context("parsing config.toml")?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Load `path`, or — if the file does not exist — fall back to the built-in
    /// defaults (an exact mirror of config.example.toml) with a warning. A file
    /// that exists but fails to parse is still a hard error.
    pub fn load_or_default(path: &str) -> Result<Self> {
        if std::path::Path::new(path).exists() {
            return Self::load(path);
        }
        tracing::warn!(
            event_type = "config_missing",
            path,
            "config file not found — using built-in defaults (mirror of config.example.toml)"
        );
        let cfg = Self::default();
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        // SAFETY: refuse to start if the API would bind to a non-loopback address.
        let api_bind: std::net::SocketAddr = self
            .server
            .bind
            .parse()
            .context("server.bind must be an IP socket address")?;
        if !api_bind.ip().is_loopback() {
            anyhow::bail!("server.bind must be loopback; refusing to expose the controller API");
        }
        if api_bind.port() == 0 {
            anyhow::bail!("server.bind must use an explicit non-zero port");
        }
        if self.database.url_env.trim().is_empty() {
            anyhow::bail!("database.url_env must not be empty");
        }
        let flow_bind = self
            .flow
            .bind_addr
            .parse::<std::net::IpAddr>()
            .context("flow.bind_addr must be an IP address")?;
        if self.flow.enabled && flow_bind.is_unspecified() {
            anyhow::bail!(
                "flow.bind_addr must be an explicit management address when flow is enabled"
            );
        }
        // flow.bucket_seconds is a divisor in flow rate math; enforce >= 1 here
        // once instead of relying on scattered `.max(1)` guards.
        if self.flow.bucket_seconds == 0 {
            anyhow::bail!("flow.bucket_seconds must be >= 1");
        }
        if self.flow.enabled && self.flow.bind_port == 0 {
            anyhow::bail!("flow.bind_port must be non-zero when flow is enabled");
        }
        if self.flow.enabled && self.flow.sflow_enabled && self.flow.sflow_port == 0 {
            anyhow::bail!("flow.sflow_port must be non-zero when sFlow is enabled");
        }
        if self.flow.enabled
            && self.flow.sflow_enabled
            && self.flow.bind_port == self.flow.sflow_port
        {
            anyhow::bail!("flow.bind_port and flow.sflow_port must be different");
        }
        if self.flow.automatic_actions_enabled && !self.flow.allowlist_enrolled_only {
            anyhow::bail!("flow automatic actions require flow.allowlist_enrolled_only = true");
        }
        if self.flow.top_k_talkers == 0 || self.flow.top_k_talkers > 65_536 {
            anyhow::bail!("flow.top_k_talkers must be in 1..=65536");
        }
        if self.flow.default_sampling_rate == 0 {
            anyhow::bail!("flow.default_sampling_rate must be >= 1");
        }
        let min = self.flow.snmp_corroboration_min_ratio;
        let max = self.flow.snmp_corroboration_max_ratio;
        if !min.is_finite() || !max.is_finite() || min <= 0.0 || min > 1.0 || max < 1.0 || min > max
        {
            anyhow::bail!("flow SNMP corroboration ratios must satisfy 0 < min <= 1 <= max");
        }
        if self.auth.session_ttl_hours == 0
            || self.auth.remember_me_ttl_hours == 0
            || self.auth.idle_timeout_minutes == 0
            || self.auth.pre_2fa_ttl_minutes == 0
        {
            anyhow::bail!("auth session and 2FA timeouts must be non-zero");
        }
        if self.auth.remember_me_ttl_hours < self.auth.session_ttl_hours {
            anyhow::bail!("auth.remember_me_ttl_hours must not be shorter than session_ttl_hours");
        }
        if self.auth.lockout_threshold == 0 || self.auth.lockout_minutes == 0 {
            anyhow::bail!("auth lockout threshold and duration must be non-zero");
        }
        if self.safety.global_action_rate_limit_count > 0
            && self.safety.global_action_rate_limit_window_seconds == 0
        {
            anyhow::bail!("the global action rate-limit window must be non-zero");
        }
        if self.telemetry.stale_after_seconds == 0
            || self.telemetry.reachability_interval_seconds == 0
            || self.telemetry.metrics_rollup_seconds == 0
        {
            anyhow::bail!(
                "telemetry rollup, freshness, and reachability intervals must be non-zero"
            );
        }
        if self.telemetry.jitter_percent > 90 {
            anyhow::bail!("telemetry.jitter_percent must be in 0..=90");
        }
        if self.detection.default_consecutive_samples == 0
            || self.detection.default_min_duration_seconds == 0
            || self.detection.default_min_duration_seconds > u32::MAX as u64
        {
            anyhow::bail!("detection defaults must be non-zero and fit their rule columns");
        }
        if self.detection.deprecated_hysteresis_seconds.is_some() {
            tracing::warn!(
                event_type = "deprecated_config_key",
                key = "detection.hysteresis_seconds",
                "ignored: configure recovery persistence on each rule instead"
            );
        }
        Ok(())
    }

    pub fn database_url(&self) -> Result<String> {
        std::env::var(&self.database.url_env)
            .with_context(|| format!("env {} not set", self.database.url_env))
    }
}

#[cfg(test)]
mod tests {
    use super::Config;

    #[test]
    fn shipped_example_parses_and_validates() {
        let cfg: Config = toml::from_str(include_str!("../config.example.toml"))
            .expect("parse config.example.toml");
        cfg.validate().expect("validate config.example.toml");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let raw = include_str!("../config.example.toml").replace(
            "automatic_actions_enabled = false",
            "automatic_actions_enabled = false\nautomatic_action_enabled = true",
        );
        assert!(toml::from_str::<Config>(&raw).is_err());
    }

    #[test]
    fn conflicting_flow_ports_are_rejected() {
        let mut cfg = Config::default();
        cfg.flow.enabled = true;
        cfg.flow.bind_addr = "192.0.2.10".into();
        cfg.flow.sflow_enabled = true;
        cfg.flow.sflow_port = cfg.flow.bind_port;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn enabled_flow_rejects_wildcard_bind() {
        let mut cfg = Config::default();
        cfg.flow.enabled = true;
        assert!(cfg.validate().is_err());
        cfg.flow.bind_addr = "192.0.2.10".into();
        assert!(cfg.validate().is_ok());
    }
}
