//! Rerouter controller — entrypoint.
//!
//! Long-lived async service that ingests traffic telemetry, evaluates DDoS
//! detection rules, executes safe reroutes, and owns authentication (sessions +
//! TOTP 2FA), RBAC, and email alerting. See ../docs/architecture.md.
//!
//! SAFETY: on startup, any reroute left in pending/running/verifying is marked
//! `uncertain` and its asset is locked until verified or acknowledged. Automatic
//! reroutes are disabled by default. See ../docs/state-recovery.md.

mod config;
mod db;
mod auth;
mod alerts;
mod telemetry;
mod detection;
mod reroute;
mod providers;
mod api;
mod scheduler;

use anyhow::Result;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "rerouter-controller")]
struct Cli {
    /// Path to config.toml
    #[arg(long, env = "REROUTER_CONFIG", default_value = "/etc/rerouter/config.toml")]
    config: String,

    /// Run subcommand and exit (e.g. config check) — placeholder for v1.
    #[arg(long)]
    check: bool,

    /// Apply pending sqlx migrations (backend-rust/migrations/) and exit.
    #[arg(long)]
    migrate: bool,

    /// Re-apply the idempotent starter reroute-template seeds and exit.
    #[arg(long)]
    seed_templates: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().json().init();

    let cli = Cli::parse();
    let cfg = config::Config::load(&cli.config)?;
    tracing::info!(event_type = "startup", bind = %cfg.server.bind, "rerouter-controller starting");

    if cli.check {
        tracing::info!("config OK");
        return Ok(());
    }

    let pool = db::connect(&cfg).await?;

    // The controller owns the schema: apply pending migrations before anything
    // touches the database (including startup recovery).
    db::MIGRATOR.run(&pool).await?;

    if cli.migrate {
        tracing::info!(event_type = "migrate_done", "migrations applied; exiting");
        return Ok(());
    }
    if cli.seed_templates {
        // Seeds ship as idempotent migrations (INSERT IGNORE), so they were
        // just (re)applied above. TODO(milestone 3): re-seed deliberately
        // deleted templates outside the migration history.
        tracing::info!(event_type = "seed_templates_done", "starter template seeds applied; exiting");
        return Ok(());
    }

    // SAFETY: resolve crash-time state before doing anything live.
    reroute::state_machine::recover_on_startup(&pool, &cfg).await?;

    // Internal alert dispatcher (replaces any external queue worker): polls the
    // alerts table and sends email via SMTP. Never blocks the control plane.
    alerts::spawn_dispatcher(pool.clone(), cfg.clone());

    // Spawn telemetry ingestion + per-asset scheduler.
    scheduler::run(pool.clone(), cfg.clone()).await?;

    // Serve the loopback-only /api/ (blocks). Public access only via the Nginx
    // /api proxy behind Cloudflare.
    api::serve(pool, cfg).await?;

    Ok(())
}
