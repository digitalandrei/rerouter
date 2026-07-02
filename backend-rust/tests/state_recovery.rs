//! Startup crash-recovery (doctrine + docs/state-recovery.md): on boot, any
//! reroute left in a non-terminal state (pending/running/verifying) becomes
//! `uncertain` and LOCKS its device until an admin acknowledges it. We never
//! assume "nothing happened" after a crash.
//!
//! This is a DB integration test. It runs only when DATABASE_URL points at a
//! MariaDB the test may migrate + write to (CI provides one); without it the
//! test skips so the unit suite still passes locally. It cleans up its rows so
//! repeated runs stay isolated.

use rerouter_controller::db::MIGRATOR;
use sqlx::mysql::MySqlPoolOptions;
use sqlx::MySqlPool;

/// Connect + migrate, or `None` when DATABASE_URL is unset (skip).
async fn pool_or_skip() -> Option<MySqlPool> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let pool = MySqlPoolOptions::new()
        .max_connections(4)
        .connect(&url)
        .await
        .expect("connect to DATABASE_URL");
    MIGRATOR.run(&pool).await.expect("run migrations");
    Some(pool)
}

#[tokio::test]
async fn in_flight_reroute_becomes_uncertain_and_locks_the_device() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping state-recovery integration test");
        return;
    };

    // Seed a device and an in-flight (running) reroute against it.
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, ?)")
        .bind("recovery-test")
        .bind("203.0.113.7")
        .execute(&pool)
        .await
        .expect("insert device")
        .last_insert_id();
    let reroute_id = sqlx::query(
        "INSERT INTO reroutes (device_id, trigger_type, state) VALUES (?, 'manual', 'running')",
    )
    .bind(device_id)
    .execute(&pool)
    .await
    .expect("insert in-flight reroute")
    .last_insert_id();

    // Run startup recovery (mandatory since b86269a — no config knob / cfg arg).
    rerouter_controller::reroute::state_machine::recover_on_startup(&pool)
        .await
        .expect("recover_on_startup");

    // The reroute must now be uncertain — never silently "succeeded".
    let state: String = sqlx::query_scalar("SELECT state FROM reroutes WHERE id = ?")
        .bind(reroute_id)
        .fetch_one(&pool)
        .await
        .expect("load reroute state");
    assert_eq!(
        state, "uncertain",
        "in-flight reroute should become uncertain"
    );

    // And the device must be locked (an active, uncleared device-scoped lock).
    let active_locks: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM locks WHERE scope = 'device' AND scope_ref = ? AND cleared_at IS NULL",
    )
    .bind(device_id.to_string())
    .fetch_one(&pool)
    .await
    .expect("count device locks");
    assert!(active_locks >= 1, "device should be locked after recovery");

    // Cleanup (children first; FKs cascade from devices but be explicit on locks).
    let _ = sqlx::query("DELETE FROM reroutes WHERE id = ?")
        .bind(reroute_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM locks WHERE scope = 'device' AND scope_ref = ?")
        .bind(device_id.to_string())
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await;
}
