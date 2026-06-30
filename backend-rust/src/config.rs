//! Controller configuration. Mirrors config.example.toml. Secrets come from the
//! environment, never from this file.

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
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
pub struct Server {
    /// MUST be a loopback address. Validated in `validate` (both the file and
    /// the built-in-defaults load paths).
    pub bind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Database {
    pub url_env: String,
}

/// Session / login-throttling knobs. The session-cookie signing secret
/// (SESSION_SECRET) and the credential-encryption key (SECRETS_KEY) come from
/// the environment, never from this file.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Auth {
    pub session_ttl_hours: u64,
    /// Session TTL when the user ticks "remember me" at login (default 7 days).
    pub remember_me_ttl_hours: u64,
    /// Failed logins (per email + real client IP) before lockout.
    pub lockout_threshold: u32,
    pub lockout_minutes: u64,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            session_ttl_hours: 12,
            remember_me_ttl_hours: 168,
            lockout_threshold: 5,
            lockout_minutes: 15,
        }
    }
}

// SMTP is configured entirely via the environment (SMTP_HOST / SMTP_PORT /
// SMTP_USERNAME / SMTP_PASSWORD / SMTP_FROM) — see alerts::mailer.

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Telemetry {
    pub metrics_rollup_seconds: u64,
    pub reachability_interval_seconds: u64,
    pub stale_after_seconds: u64,
    pub jitter_percent: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Detection {
    pub default_consecutive_samples: u32,
    pub default_min_duration_seconds: u64,
    pub hysteresis_seconds: u64,
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
#[serde(default)]
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
#[serde(default)]
pub struct Reroute {
    pub require_verification: bool,
}

/// Retention windows enforced by the controller's cleanup task
/// (TODO(milestone 2): the task itself).
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Retention {
    pub traffic_samples_days: u32,
    pub rule_events_days: u32,
    pub reroute_logs_days: u32,
}

/// NetFlow/IPFIX flow collector. A SECOND, read-only telemetry source (see
/// docs/flow-telemetry.md). OFF by default. Unlike `server.bind` (loopback-only,
/// enforced in `validate`), the flow listener must receive UDP from the router,
/// so its bind address is operator-chosen — a deliberate, documented exposure.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Flow {
    pub enabled: bool,
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
    /// Retain ~the last hour of aggregated buckets (mirrors interface_samples).
    pub retention_minutes: i64,
    /// Aggregation bucket width in seconds.
    pub bucket_seconds: u64,
    /// 5-tuples retained per bucket/interface/direction; the tail is truncated
    /// (logged, never silent — the count survives in flow_iface_buckets).
    pub top_k_talkers: usize,
    /// Fallback sampling rate when an exporter reports none and no per-exporter
    /// override is set. A sampled-looking exporter that falls through to this is
    /// flagged low-confidence (blocks flow-driven automatic actions).
    pub default_sampling_rate: u32,
}

impl Default for Flow {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: "0.0.0.0".into(),
            bind_port: 2055,
            sflow_enabled: false,
            sflow_port: 6343,
            allowlist_enrolled_only: true,
            retention_minutes: 70,
            bucket_seconds: 60,
            top_k_talkers: 100,
            default_sampling_rate: 1,
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
            reachability_interval_seconds: 15,
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
            hysteresis_seconds: 30,
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
            traffic_samples_days: 7,
            rule_events_days: 90,
            reroute_logs_days: 365,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: Server::default(),
            database: Database::default(),
            auth: Auth::default(),
            telemetry: Telemetry::default(),
            detection: Detection::default(),
            safety: Safety::default(),
            reroute: Reroute::default(),
            retention: Retention::default(),
            flow: Flow::default(),
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
        if !self.server.bind.starts_with("127.") && !self.server.bind.starts_with("[::1]") {
            anyhow::bail!("server.bind must be loopback; refusing to expose the controller API");
        }
        Ok(())
    }

    pub fn database_url(&self) -> Result<String> {
        std::env::var(&self.database.url_env)
            .with_context(|| format!("env {} not set", self.database.url_env))
    }
}
