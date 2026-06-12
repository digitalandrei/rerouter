//! Database access (sqlx / MariaDB). The schema is owned by this crate:
//! backend-rust/migrations/ (sqlx migrations, applied on startup or via
//! --migrate) is the single source of schema truth. Reference documentation
//! lives in ../docs/database.md.

use anyhow::Result;
use sqlx::migrate::Migrator;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;

use crate::config::Config;

/// Compile-time embedded migrations from backend-rust/migrations/.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub async fn connect(cfg: &Config) -> Result<MySqlPool> {
    let url = cfg.database_url()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await?;
    tracing::info!(event_type = "db_connected", "MariaDB pool ready");
    Ok(pool)
}

// TODO(milestone 1): typed query helpers for assets, providers, statuses,
// metrics_current, traffic_samples. Persist action-state transitions inside a
// transaction together with the step output (see ../docs/state-recovery.md).
