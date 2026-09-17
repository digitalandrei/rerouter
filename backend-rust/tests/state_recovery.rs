//! Startup crash-recovery (doctrine + docs/state-recovery.md): on boot, any
//! reroute left in a non-terminal state (pending/running/verifying) becomes
//! `uncertain` and LOCKS its device until an admin acknowledges it. We never
//! assume "nothing happened" after a crash.
//!
//! This is a DB integration test. It runs only when REROUTER_TEST_DATABASE_URL points at a
//! dedicated test schema. Missing or unsafe configuration fails the suite.
//! Tests serialize their database work and clean up their own rows.

mod common;

#[tokio::test]
async fn in_flight_reroute_becomes_uncertain_and_locks_the_device() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();

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
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();

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

#[tokio::test]
async fn interrupted_cross_device_bundle_quarantines_every_owned_or_ambiguous_device() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let suffix = uuid::Uuid::new_v4();
    let device_a = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '192.0.2.10')")
        .bind(format!("recovery-bundle-a-{suffix}"))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let device_b = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '192.0.2.11')")
        .bind(format!("recovery-bundle-b-{suffix}"))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let bundle_id = sqlx::query(
        "INSERT INTO reroute_bundles \
            (trigger_type, state, failure_policy, total_actions, completed_actions) \
         VALUES ('manual', 'running', 'abort_and_compensate', 2, 1)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    let succeeded = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, bundle_id, bundle_position, trigger_type, state, mutation_effect, \
             started_at, finished_at, success) \
         VALUES (?, ?, 0, 'manual', 'succeeded', 'changed', UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)",
    )
    .bind(device_a)
    .bind(bundle_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    let interrupted = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, bundle_id, bundle_position, trigger_type, state, mutation_effect, started_at) \
         VALUES (?, ?, 1, 'manual', 'running', 'pending', UTC_TIMESTAMP())",
    )
    .bind(device_b)
    .bind(bundle_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();

    rerouter_controller::reroute::state_machine::recover_on_startup(&pool)
        .await
        .unwrap();
    rerouter_controller::reroute::bundle::recover_on_startup(&pool)
        .await
        .unwrap();

    let bundle_state: String = sqlx::query_scalar("SELECT state FROM reroute_bundles WHERE id = ?")
        .bind(bundle_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(bundle_state, "compensation_blocked");
    let windows: Vec<(u64, String)> = sqlx::query_as(
        "SELECT device_id, phase FROM device_change_windows \
         WHERE bundle_id = ? ORDER BY device_id",
    )
    .bind(bundle_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        windows,
        vec![
            (device_a, "uncertain".into()),
            (device_b, "uncertain".into())
        ]
    );
    let alerted: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE dedup_key = ? AND severity = 'critical'",
    )
    .bind(format!("reroute_bundle_interrupted:{bundle_id}"))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(alerted, 1);
    let ids: Vec<u64> = sqlx::query_scalar(
        "SELECT id FROM reroutes WHERE bundle_id = ? AND mutation_effect IN ('changed','unknown') ORDER BY id",
    )
    .bind(bundle_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(ids, vec![succeeded, interrupted]);

    sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM locks WHERE reroute_id IN (?, ?)")
        .bind(succeeded)
        .bind(interrupted)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroutes WHERE bundle_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM alerts WHERE dedup_key = ?")
        .bind(format!("reroute_bundle_interrupted:{bundle_id}"))
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM audit_logs WHERE entity_type = 'reroute_bundle' AND entity_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id IN (?, ?)")
        .bind(device_a)
        .bind(device_b)
        .execute(&pool)
        .await
        .ok();
}
