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

/// The acknowledge handler clears the acknowledged reroute's lock via
/// `locks.reroute_id`, with a legacy fallback that matches auto-lock rows by
/// their `reroute #<id> ...` reason (for rows created before the correlation
/// column existed). That fallback must anchor on the exact id: acknowledging
/// reroute #S must NOT clear a legacy lock for #S-with-more-digits (e.g. #12
/// vs #123). This mirrors the exact UPDATE the handler runs.
#[tokio::test]
async fn acknowledge_lock_clear_does_not_match_a_longer_reroute_id() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping lock-anchor integration test");
        return;
    };

    // Ids chosen far outside the auto-increment range so they cannot collide
    // with real reroute rows from parallel tests. `long` string-prefixes `short`
    // with a digit (not a space) right after `short` — the collision we forbid.
    let short: u64 = 990_012;
    let long: u64 = 9_900_123;

    // Two legacy locks (reroute_id NULL — the only rows the fallback can hit).
    let short_lock = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reroute_id, reason, kind) \
         VALUES ('asset', 'anchor-test', NULL, ?, 'auto_uncertain')",
    )
    .bind(format!(
        "reroute #{short} was in-flight at restart; outcome unknown"
    ))
    .execute(&pool)
    .await
    .expect("insert short legacy lock")
    .last_insert_id();
    let long_lock = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reroute_id, reason, kind) \
         VALUES ('asset', 'anchor-test', NULL, ?, 'auto_uncertain')",
    )
    .bind(format!(
        "reroute #{long} was in-flight at restart; outcome unknown"
    ))
    .execute(&pool)
    .await
    .expect("insert long legacy lock")
    .last_insert_id();

    // A real reroute + a correlated lock, to exercise the primary (reroute_id) arm.
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, ?)")
        .bind("anchor-test")
        .bind("203.0.113.8")
        .execute(&pool)
        .await
        .expect("insert device")
        .last_insert_id();
    let reroute_id = sqlx::query(
        "INSERT INTO reroutes (device_id, trigger_type, state) VALUES (?, 'manual', 'uncertain')",
    )
    .bind(device_id)
    .execute(&pool)
    .await
    .expect("insert reroute")
    .last_insert_id();
    let correlated_lock = sqlx::query(
        "INSERT INTO locks (scope, scope_ref, reroute_id, reason, kind) \
         VALUES ('asset', ?, ?, 'manual device lock', 'auto_uncertain')",
    )
    .bind(device_id.to_string())
    .bind(reroute_id)
    .execute(&pool)
    .await
    .expect("insert correlated lock")
    .last_insert_id();

    // The exact UPDATE the acknowledge handler runs (src/api/reroutes.rs).
    let clear = |id: u64| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "UPDATE locks SET cleared_at = UTC_TIMESTAMP(), cleared_by = ? \
                 WHERE cleared_at IS NULL AND \
                   (reroute_id = ? OR (reroute_id IS NULL AND kind IN ('auto_crash','auto_uncertain') \
                     AND (reason = CONCAT('reroute #', ?) \
                          OR reason LIKE CONCAT('reroute #', ?, ' %'))))",
            )
            .bind(Option::<u64>::None) // cleared_by
            .bind(id)
            .bind(id)
            .bind(id)
            .execute(&pool)
            .await
            .expect("run lock-clear update")
            .rows_affected()
        }
    };

    // Acknowledging #short must clear ONLY the #short legacy lock.
    let affected = clear(short).await;
    assert_eq!(
        affected, 1,
        "clearing #{short} should affect exactly one lock"
    );

    let is_cleared = |lock_id: u64| {
        let pool = pool.clone();
        async move {
            let cleared: i64 =
                sqlx::query_scalar("SELECT cleared_at IS NOT NULL FROM locks WHERE id = ?")
                    .bind(lock_id)
                    .fetch_one(&pool)
                    .await
                    .expect("load lock cleared_at");
            cleared != 0
        }
    };

    assert!(
        is_cleared(short_lock).await,
        "the #{short} legacy lock should be cleared"
    );
    assert!(
        !is_cleared(long_lock).await,
        "the #{long} legacy lock must NOT be cleared by acknowledging #{short}"
    );
    assert!(
        !is_cleared(correlated_lock).await,
        "the correlated lock (reroute_id != {short}) must NOT be cleared yet"
    );

    // Acknowledging the real reroute clears its correlated lock via the first arm.
    let affected = clear(reroute_id).await;
    assert_eq!(
        affected, 1,
        "clearing the real reroute should affect exactly its correlated lock"
    );
    assert!(
        is_cleared(correlated_lock).await,
        "the correlated lock should clear via the reroute_id arm"
    );

    // Cleanup.
    let _ = sqlx::query("DELETE FROM locks WHERE id IN (?, ?, ?)")
        .bind(short_lock)
        .bind(long_lock)
        .bind(correlated_lock)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM reroutes WHERE id = ?")
        .bind(reroute_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await;
}
