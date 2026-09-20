//! Database access (sqlx / MariaDB). The schema is owned by this crate:
//! backend-rust/migrations/ (sqlx migrations, applied on startup or via
//! --migrate) is the single source of schema truth. Reference documentation
//! lives in ../docs/database.md.

use std::ops::Deref;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use sqlx::migrate::Migrator;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use sqlx::{Executor, MySqlConnection, MySqlPool};

use crate::config::Config;

pub mod advisory;

/// Compile-time embedded migrations from backend-rust/migrations/.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// MySQL advisory-lock names are server-global, not schema-local. Resolve every
/// logical lock label through the selected database name so colocated Rerouter
/// installations and their dedicated test schemas never contend. The `rrt:`
/// prefix plus 60 SHA-256 hex characters is exactly MySQL's 64-byte limit.
pub async fn scoped_advisory_lock_name(
    conn: &mut MySqlConnection,
    logical_label: &str,
) -> Result<String> {
    sqlx::query_scalar("SELECT CONCAT('rrt:', LEFT(SHA2(CONCAT(DATABASE(), ':', ?), 256), 60))")
        .bind(logical_label)
        .fetch_one(conn)
        .await
        .context("deriving database-scoped advisory lock name")
}

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
        tracing::info!(
            event_type = "db_fresh",
            "fresh database — creating schema and seeds"
        );
    }

    MIGRATOR
        .run(pool)
        .await
        .context("applying sqlx migrations")?;

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
        tracing::info!(
            event_type = "db_schema_current",
            total = applied_after,
            "schema up to date"
        );
    }
    Ok(())
}

/// Unit tests share one disposable schema and run concurrently. Serialize its
/// first migration pass because MySQL DDL and SQLx's migration-row insert are
/// not atomic together on a brand-new database.
#[doc(hidden)]
pub async fn migrate_test_schema(pool: &MySqlPool) -> Result<()> {
    let mut lock_conn = pool
        .acquire()
        .await
        .context("acquiring migration lock connection")?;
    let lock_name = scoped_advisory_lock_name(&mut lock_conn, "test:migrate").await?;
    lock_conn.close_on_drop();
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 30)")
        .bind(&lock_name)
        .fetch_one(&mut *lock_conn)
        .await
        .context("acquiring test migration lock")?;
    if acquired != Some(1) {
        anyhow::bail!("timed out acquiring test migration lock");
    }

    let migration_result = MIGRATOR.run(pool).await.context("running test migrations");
    let released: Option<i64> = sqlx::query_scalar("SELECT RELEASE_LOCK(?)")
        .bind(&lock_name)
        .fetch_one(&mut *lock_conn)
        .await
        .context("releasing test migration lock")?;
    if released != Some(1) {
        anyhow::bail!("test migration lock was not owned at release");
    }
    migration_result
}

/// Integration-test pool plus the detached connection that owns the global test
/// serialization lock. Public only so `tests/` crates and in-module DB tests use
/// one fail-loud safety boundary.
#[doc(hidden)]
pub struct TestDatabase {
    pool: MySqlPool,
    _serial_lock: MySqlConnection,
}

impl Deref for TestDatabase {
    type Target = MySqlPool;

    fn deref(&self) -> &Self::Target {
        &self.pool
    }
}

impl TestDatabase {
    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }
}

/// Connect to `REROUTER_TEST_DATABASE_URL`, refusing privileged accounts and
/// non-test database names. Missing configuration is a test failure, never a
/// silent skip. Pure tests remain available with `cargo test --lib` filters that
/// do not invoke DB-backed cases.
#[doc(hidden)]
pub async fn connect_test_database() -> TestDatabase {
    let raw = std::env::var("REROUTER_TEST_DATABASE_URL").expect(
        "REROUTER_TEST_DATABASE_URL is required for DB integration tests; use filtered pure unit tests when MariaDB coverage is intentionally out of scope",
    );
    let options = MySqlConnectOptions::from_str(&raw)
        .expect("REROUTER_TEST_DATABASE_URL must be a valid mysql:// URL");
    let database = options
        .get_database()
        .expect("REROUTER_TEST_DATABASE_URL must name a database")
        .to_ascii_lowercase();
    let username = options.get_username().to_ascii_lowercase();
    assert!(
        database == "rerouter_test" || database.starts_with("rerouter_test_"),
        "refusing DB tests against non-dedicated database {database:?}; expected rerouter_test or rerouter_test_*"
    );
    assert!(
        username != "root" && username.contains("test"),
        "refusing DB tests as privileged/non-test account {username:?}"
    );

    let pool = MySqlPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(10))
        .after_connect(|conn, _| {
            Box::pin(async move {
                conn.execute("SET time_zone = '+00:00'").await?;
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .expect("connect dedicated test database");
    let actual_db: String = sqlx::query_scalar("SELECT DATABASE()")
        .fetch_one(&pool)
        .await
        .expect("read connected database name");
    let actual_user: String = sqlx::query_scalar("SELECT CURRENT_USER()")
        .fetch_one(&pool)
        .await
        .expect("read connected database account");
    assert_eq!(actual_db.to_ascii_lowercase(), database);
    assert!(
        actual_user.split('@').next().is_some_and(|user| {
            let user = user.to_ascii_lowercase();
            user.contains("test") && user != "root"
        }),
        "server authenticated DB tests as unsafe account {actual_user:?}"
    );

    let mut pooled = pool
        .acquire()
        .await
        .expect("acquire test-suite lock connection");
    let lock_name = scoped_advisory_lock_name(&mut pooled, "test:suite")
        .await
        .expect("derive test-suite lock name");
    let acquired: Option<i64> = sqlx::query_scalar("SELECT GET_LOCK(?, 60)")
        .bind(&lock_name)
        .fetch_one(&mut *pooled)
        .await
        .expect("acquire cross-suite test database lock");
    assert_eq!(
        acquired,
        Some(1),
        "timed out serializing DB integration tests"
    );
    let serial_lock = pooled.detach();
    migrate_test_schema(&pool)
        .await
        .expect("migrate dedicated test schema");
    TestDatabase {
        pool,
        _serial_lock: serial_lock,
    }
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
