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
}

#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    /// MUST be a loopback address. Validated in `load`.
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
    /// Failed logins (per email + real client IP) before lockout.
    pub lockout_threshold: u32,
    pub lockout_minutes: u64,
}

impl Default for Auth {
    fn default() -> Self {
        Self { session_ttl_hours: 12, lockout_threshold: 5, lockout_minutes: 15 }
    }
}

// SMTP is configured entirely via the environment (SMTP_HOST / SMTP_PORT /
// SMTP_USERNAME / SMTP_PASSWORD / SMTP_FROM) — see alerts::mailer.

#[derive(Debug, Clone, Deserialize)]
pub struct Telemetry {
    pub flow_listen: String,
    pub default_sampling_rate: u32,
    pub metrics_rollup_seconds: u64,
    pub reachability_interval_seconds: u64,
    pub cloudflare_poll_seconds: u64,
    pub stale_after_seconds: u64,
    pub jitter_percent: u8,
}

#[derive(Debug, Clone, Deserialize)]
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
pub struct Safety {
    /// SAFETY: defaults to Observe (read-only / alert-only).
    #[serde(default)]
    pub operating_mode: OperatingMode,
    pub automatic_actions_enabled: bool,
    pub global_action_rate_limit_count: u32,
    pub global_action_rate_limit_window_seconds: u64,
    pub same_rule_cooldown_seconds: u64,
    pub same_asset_cooldown_seconds: u64,
    pub same_prefix_provider_cooldown_seconds: u64,
    pub mark_running_actions_uncertain_on_startup: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Reroute {
    pub default_blackhole_expiry_seconds: u64,
    pub require_verification: bool,
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {path}"))?;
        let cfg: Config = toml::from_str(&raw).context("parsing config.toml")?;

        // SAFETY: refuse to start if the API would bind to a non-loopback address.
        if !cfg.server.bind.starts_with("127.") && !cfg.server.bind.starts_with("[::1]") {
            anyhow::bail!("server.bind must be loopback; refusing to expose the controller API");
        }
        Ok(cfg)
    }

    pub fn database_url(&self) -> Result<String> {
        std::env::var(&self.database.url_env)
            .with_context(|| format!("env {} not set", self.database.url_env))
    }
}
