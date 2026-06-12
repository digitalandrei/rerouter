//! Database access (sqlx / MariaDB). The schema is owned by this crate:
//! backend-rust/migrations/ (sqlx migrations, applied on startup or via
//! --migrate) is the single source of schema truth. Reference documentation
//! lives in ../docs/database.md.

use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::{Executor, MySqlPool};

use crate::config::Config;

/// Compile-time embedded migrations from backend-rust/migrations/.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Credential preflight budget — fail fast with a clear message instead of
/// hanging on an unreachable or misconfigured MariaDB.
const PREFLIGHT_TIMEOUT: Duration = Duration::from_secs(5);

/// DB credential preflight + pool construction. Runs before anything else
/// touches the database. On failure the error names the user/host/database
/// that was attempted and why — NEVER the password.
pub async fn preflight_connect(cfg: &Config) -> Result<MySqlPool> {
    let url = cfg.database_url()?;
    let target = describe_url(&url);

    // Force every pooled connection's session time zone to UTC. The schema uses
    // TIMESTAMP columns and the code reads/writes them as UTC (UTC_TIMESTAMP(),
    // chrono::DateTime<Utc>); sqlx decodes TIMESTAMP -> DateTime<Utc> assuming the
    // session is +00:00, so we set it explicitly rather than trust the server's
    // default tz.
    let connect = MySqlPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(PREFLIGHT_TIMEOUT)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                conn.execute("SET time_zone = '+00:00'").await?;
                Ok(())
            })
        })
        .connect(&url);

    let pool = match tokio::time::timeout(PREFLIGHT_TIMEOUT, connect).await {
        Ok(Ok(pool)) => pool,
        Ok(Err(e)) => anyhow::bail!("cannot connect to MariaDB as {target}: {e}"),
        Err(_) => anyhow::bail!(
            "cannot connect to MariaDB as {target}: timed out after {}s (server down or unreachable?)",
            PREFLIGHT_TIMEOUT.as_secs()
        ),
    };

    tracing::info!(event_type = "db_connected", target = %target, "MariaDB pool ready");
    Ok(pool)
}

/// Apply pending migrations, logging whether this is a fresh database (no
/// applied migrations yet — schema + seeds get created, including the safe
/// operating_mode=observe default in system_settings) or an upgrade/no-op.
pub async fn migrate(pool: &MySqlPool) -> Result<()> {
    // No _sqlx_migrations table (query error) or zero rows => fresh database.
    let applied_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .unwrap_or(0);
    if applied_before == 0 {
        tracing::info!(event_type = "db_fresh", "fresh database — creating schema and seeds");
    }

    MIGRATOR.run(pool).await.context("applying sqlx migrations")?;

    let applied_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(pool)
        .await
        .context("counting applied migrations")?;
    let newly_applied = applied_after - applied_before;
    if newly_applied > 0 {
        tracing::info!(
            event_type = "db_migrated",
            applied = newly_applied,
            total = applied_after,
            "applied {newly_applied} migration(s) ({applied_after} total)"
        );
    } else {
        tracing::info!(event_type = "db_schema_current", total = applied_after, "schema up to date");
    }
    Ok(())
}

/// Human description of a mysql:// URL with the password REDACTED — safe for
/// logs and error messages.
fn describe_url(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((_, rest)) => rest,
        None => return "<unparseable DATABASE_URL>".into(),
    };
    // userinfo@host[:port]/db — everything between the first ':' in userinfo
    // and the '@' is the password; never include it.
    let (user, host_db) = match rest.rsplit_once('@') {
        Some((userinfo, host_db)) => {
            let user = userinfo.split_once(':').map_or(userinfo, |(u, _)| u);
            (user, host_db)
        }
        None => ("<no user>", rest),
    };
    let (host, db) = match host_db.split_once('/') {
        Some((host, db)) => (host, db.split(['?', '#']).next().unwrap_or(db)),
        None => (host_db, "<no database>"),
    };
    format!("user '{user}' @ {host}, database '{db}'")
}

// TODO(milestone 1): typed query helpers for assets, providers, statuses,
// metrics_current, traffic_samples. Persist action-state transitions inside a
// transaction together with the step output (see ../docs/state-recovery.md).
