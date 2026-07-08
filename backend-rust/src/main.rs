//! Rerouter controller — entrypoint.
//!
//! Long-lived async service that ingests traffic telemetry, evaluates DDoS
//! detection rules, executes safe reroutes, and owns authentication (sessions +
//! TOTP 2FA), RBAC, and email alerting. See ../docs/architecture.md.
//!
//! Deployment is self-contained: `rerouter-controller --install` lays down
//! /srv/rerouter (binary, .env template, config.toml) plus the systemd unit;
//! the operator fills in .env and starts the service. Startup order:
//! env-file -> config (defaults if missing) -> DB credential preflight ->
//! migrate-if-needed (fresh DB gets schema + seeds) -> recovery/dispatcher/
//! scheduler/API.
//!
//! SAFETY: on startup, any reroute left in pending/running/verifying is marked
//! `uncertain` and its asset is locked until verified or acknowledged. Automatic
//! reroutes are disabled by default. See ../docs/state-recovery.md.

use rerouter_controller::{alerts, api, config, db, install, reroute, scheduler, telemetry};

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rerouter-controller")]
struct Cli {
    /// Path to config.toml. If the file is missing, built-in defaults (an exact
    /// mirror of config.example.toml) are used with a warning.
    #[arg(
        long,
        env = "REROUTER_CONFIG",
        default_value = "/srv/rerouter/config.toml"
    )]
    config: String,

    /// .env file loaded into the process environment at startup. Variables
    /// already set in the environment always win. Missing file = warning.
    #[arg(long, default_value = "/srv/rerouter/.env")]
    env_file: String,

    /// Load and validate the config (loopback-bind check included), then exit.
    #[arg(long)]
    check: bool,

    /// Run ONLY the DB credential preflight and exit (nonzero on failure).
    #[arg(long)]
    check_db: bool,

    /// Apply pending sqlx migrations (backend-rust/migrations/) and exit.
    #[arg(long)]
    migrate: bool,

    /// Re-apply the idempotent starter reroute-template seeds and exit.
    #[arg(long)]
    seed_templates: bool,

    /// Install the controller: binary + .env template + config.toml under
    /// <prefix>/srv/rerouter, systemd unit under <prefix>/etc/systemd/system.
    /// Idempotent — re-running upgrades binary and unit only.
    #[arg(long)]
    install: bool,

    /// Filesystem prefix for --install (default "/"; e.g. --prefix /tmp/x for testing).
    #[arg(long, default_value = "/")]
    prefix: String,

    /// Create the initial admin user (idempotent on email) and exit.
    /// Email/name/password come from the flags below, ADMIN_* env vars, or an
    /// interactive prompt. Requires a working DB connection.
    #[arg(long)]
    create_admin: bool,

    /// Admin email for --create-admin.
    #[arg(long, env = "ADMIN_EMAIL")]
    admin_email: Option<String>,

    /// Admin display name for --create-admin.
    #[arg(long, env = "ADMIN_NAME")]
    admin_name: Option<String>,

    /// Admin password for --create-admin (min 12 chars; never logged).
    #[arg(long, env = "ADMIN_PASSWORD")]
    admin_password: Option<String>,

    /// Debug: SNMP-walk an OID prefix on a device (by id, using its stored
    /// creds), print `oid = value`, and exit. For exploring agent MIBs.
    #[arg(long)]
    snmp_walk: Option<u64>,

    /// OID prefix for --snmp-walk (default ENTITY-MIB entPhysicalName).
    #[arg(long, default_value = "1.3.6.1.2.1.47.1.1.1.1.7")]
    oid: String,

    /// Debug: run the read-only SSH connectivity probe against a device (by id,
    /// using its stored creds) — the same `show version`/`show clock` the UI
    /// "Test SSH" button runs — print the result, and exit. Mirrors the
    /// /api/devices/{id}/ssh-test endpoint for headless diagnosis.
    #[arg(long)]
    ssh_test: Option<u64>,

    /// Debug: run the SSH capability probe against a device (by id) — the same
    /// config reads + no-op config-mode entry the UI "Command access / Check
    /// access" panel runs — print per-check ok/denied, and exit. Mirrors the
    /// /api/devices/{id}/ssh-capabilities endpoint for headless diagnosis.
    #[arg(long)]
    ssh_caps: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().json().init();

    let cli = Cli::parse();

    // Installer needs neither env nor config nor DB.
    if cli.install {
        return install::run_install(&cli.prefix);
    }

    // a. --env-file via dotenvy. Process env always wins (dotenvy never
    // overrides already-set variables); a missing file is only a warning.
    if std::path::Path::new(&cli.env_file).exists() {
        dotenvy::from_path(&cli.env_file)
            .map_err(|e| anyhow::anyhow!("loading env file {}: {e}", cli.env_file))?;
        tracing::info!(event_type = "env_file_loaded", path = %cli.env_file, "env file loaded (process env wins)");
    } else {
        tracing::warn!(
            event_type = "env_file_missing",
            path = %cli.env_file,
            "env file not found — relying on the process environment"
        );
    }

    // b. config: missing file -> built-in defaults + warning; loopback-bind
    // validation applies to both paths.
    let cfg = config::Config::load_or_default(&cli.config)?;
    tracing::info!(event_type = "startup", bind = %cfg.server.bind, "rerouter-controller starting");

    if cli.check {
        tracing::info!("config OK");
        return Ok(());
    }

    // c. DB credential preflight (~5s budget) — before ANYTHING touches the DB.
    // One clear actionable line on failure; the password is never printed.
    let pool = match db::preflight_connect(&cfg).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!(
                "rerouter-controller: {e:#} — fix DATABASE_URL in {} and retry",
                cli.env_file
            );
            std::process::exit(1);
        }
    };
    if cli.check_db {
        tracing::info!(
            event_type = "check_db_ok",
            "database credential preflight passed"
        );
        println!("database connection OK");
        return Ok(());
    }

    // d. Seed if not present: a fresh database (no applied migrations) gets the
    // full schema + seeds (roles/permissions, starter templates, and
    // system_settings incl. operating_mode=observe); otherwise this is an
    // idempotent upgrade / "schema up to date" no-op. The controller owns the
    // schema — this runs before startup recovery.
    db::migrate(&pool).await?;

    if cli.migrate {
        tracing::info!(event_type = "migrate_done", "migrations applied; exiting");
        return Ok(());
    }
    if cli.seed_templates {
        // Seeds ship as idempotent migrations (INSERT IGNORE), so they were
        // just (re)applied above. TODO(milestone 3): re-seed deliberately
        // deleted templates outside the migration history.
        tracing::info!(
            event_type = "seed_templates_done",
            "starter template seeds applied; exiting"
        );
        return Ok(());
    }
    if cli.create_admin {
        install::create_admin(&pool, cli.admin_email, cli.admin_name, cli.admin_password).await?;
        return Ok(());
    }
    if let Some(dev_id) = cli.snmp_walk {
        telemetry::snmp::debug_walk(&pool, dev_id, &cli.oid).await?;
        return Ok(());
    }
    if let Some(dev_id) = cli.ssh_test {
        let commands = vec![
            "show version | include (Version|uptime is)".to_string(),
            "show clock".to_string(),
        ];
        match rerouter_controller::ssh::run_commands(&pool, dev_id, &commands).await {
            Ok(outcome) => {
                println!(
                    "SSH OK (device {dev_id}); host key {} ({})",
                    outcome.fingerprint,
                    if outcome.pinned_now {
                        "pinned now — first contact"
                    } else {
                        "matches pinned"
                    }
                );
                for r in &outcome.results {
                    println!("\n$ {}\n{}", r.command, r.output);
                }
            }
            Err(e) => {
                eprintln!("SSH FAILED (device {dev_id}): {e:#}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    if let Some(dev_id) = cli.ssh_caps {
        match rerouter_controller::ssh::probe_capabilities(&pool, dev_id).await {
            Ok(checks) => {
                println!("Command access probe (device {dev_id}):");
                for c in &checks {
                    println!(
                        "  [{}] {} ({})",
                        if c.ok { "OK " } else { "DENY" },
                        c.name,
                        c.command
                    );
                    if !c.ok && !c.detail.is_empty() {
                        println!("        -> {}", c.detail);
                    }
                }
            }
            Err(e) => {
                eprintln!("Command access probe FAILED (device {dev_id}): {e:#}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    // e. SAFETY: resolve crash-time state before doing anything live.
    reroute::state_machine::recover_on_startup(&pool).await?;

    // Reset the device stability clocks: after a restart a device must be freshly
    // re-confirmed SSH-reachable for the stability window before AUTOMATIC
    // mitigations resume (manual is unaffected). The poll loop re-establishes it.
    reroute::reachability::reset_stability(&pool).await;

    // Internal alert dispatcher (replaces any external queue worker): polls the
    // alerts table and sends email via SMTP. Never blocks the control plane.
    alerts::spawn_dispatcher(pool.clone(), cfg.clone());

    // Spawn telemetry ingestion + per-asset scheduler.
    scheduler::run(pool.clone(), cfg.clone()).await?;

    // Serve the loopback-only /api/ (blocks). Public access only via the Nginx
    // /api proxy behind Cloudflare. With --features embed-ui the same listener
    // also serves the embedded SPA.
    api::serve(pool, cfg).await?;

    Ok(())
}
