//! Test-only migration runner for fresh and historical-schema upgrade checks.
//! It never starts the controller or its telemetry/execution workers.

use anyhow::{ensure, Context, Result};
use sqlx::{mysql::MySqlConnectOptions, mysql::MySqlPoolOptions, Executor};
use std::{path::Path, str::FromStr, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let directory = args
        .next()
        .context("usage: verify_test_migrations MIGRATION_DIRECTORY [FIXTURE_SQL]")?;
    let fixture = args.next();
    ensure!(args.next().is_none(), "too many arguments");
    let raw = std::env::var("REROUTER_TEST_DATABASE_URL")
        .context("REROUTER_TEST_DATABASE_URL is required")?;
    let options = MySqlConnectOptions::from_str(&raw).context("invalid test database URL")?;
    let database = options
        .get_database()
        .context("test database is required")?
        .to_owned();
    let username = options.get_username().to_owned();
    ensure!(
        database.starts_with("rerouter_test_")
            && (database.contains("_fresh_") || database.contains("_upgrade_")),
        "migration verification requires a dedicated fresh/upgrade test schema"
    );
    ensure!(
        username != "root" && username.contains("test"),
        "restricted test account required"
    );
    ensure!(
        matches!(options.get_host(), "localhost" | "127.0.0.1"),
        "use the existing local service or task-owned loopback tunnel"
    );
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(5))
        .after_connect(|connection, _| {
            Box::pin(async move {
                connection.execute("SET time_zone='+00:00'").await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .context("connecting restricted migration test database")?;
    let (actual_db, actual_user): (String, String) =
        sqlx::query_as("SELECT DATABASE(),CURRENT_USER()")
            .fetch_one(&pool)
            .await?;
    ensure!(
        actual_db == database && actual_user.split('@').next() == Some(username.as_str()),
        "unexpected database identity"
    );
    let grants: Vec<String> = sqlx::query_scalar("SHOW GRANTS").fetch_all(&pool).await?;
    ensure!(
        grants
            .iter()
            .all(|grant| !grant.contains(" ON *.* ") || grant.starts_with("GRANT USAGE ")),
        "global test privileges are forbidden"
    );

    let migrator = sqlx::migrate::Migrator::new(Path::new(&directory)).await?;
    migrator.run(&pool).await?;
    if let Some(path) = fixture {
        let sql = std::fs::read_to_string(path).context("reading trusted test fixture")?;
        sqlx::raw_sql(&sql)
            .execute(&pool)
            .await
            .context("seeding migration test fixture")?;
    }
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success=1")
        .fetch_one(&pool)
        .await?;
    ensure!(
        applied as usize == migrator.iter().count(),
        "migration count differs from supplied manifest"
    );
    println!(
        "{}",
        serde_json::json!({"database":database,"migrations":applied,"status":"passed"})
    );
    pool.close().await;
    Ok(())
}
