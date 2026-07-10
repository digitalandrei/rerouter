//! Device reachability for mitigations (reroute preflight gate). A reroute pushes
//! config over SSH, so `reachable_for_mitigation` decides on SSH: it must answer at
//! privileged EXEC, OR have answered within the last 60s (the recency short-circuit
//! that avoids re-probing / tripping the device's SSH throttle). The outcome is
//! classified into ssh_status (reachable / no_privilege / unreachable).
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB the test
//! may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::db::MIGRATOR;
use rerouter_controller::reroute::reachability::{self, STATUS_REACHABLE, STATUS_UNREACHABLE};
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
async fn unreachable_ssh_blocks_but_recent_contact_passes_without_probing() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping reachability integration test");
        return;
    };

    // A device with SSH pointed at a closed port and NO recent SSH contact. There
    // is nothing to connect to, so the live liveness probe fails (unreachable).
    let device_id =
        sqlx::query("INSERT INTO devices (name, hostname, ssh_port) VALUES (?, '127.0.0.1', 1)")
            .bind("reachability-test")
            .execute(&pool)
            .await
            .expect("insert device")
            .last_insert_id();

    // Helper: read the persisted ssh_status display column.
    let ssh_status = |pool: MySqlPool| async move {
        sqlx::query_scalar::<_, String>("SELECT ssh_status FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .expect("read ssh_status")
    };

    // 1) No recent contact + unreachable SSH -> ssh_ok = false (the gate refuses a
    //    reroute up front). The classified failure is persisted to the display.
    let r = reachability::reachable_for_mitigation(&pool, device_id).await;
    assert!(!r.ssh_ok, "unreachable SSH must not pass the gate");
    assert_eq!(r.ssh_status, STATUS_UNREACHABLE);
    assert!(
        !r.via_recency,
        "no recent contact -> a live probe was attempted"
    );
    assert!(
        r.ssh_error.is_some(),
        "a probe failure should carry a reason"
    );
    assert_eq!(ssh_status(pool.clone()).await, STATUS_UNREACHABLE);

    // 1b) The periodic probe records the same classified outcome.
    assert_eq!(
        reachability::probe_ssh_and_store(&pool, device_id).await,
        STATUS_UNREACHABLE,
        "periodic probe of an unreachable device -> unreachable"
    );

    // 2) Recency short-circuit: stamp a fresh privileged contact, then the decision
    //    passes WITHOUT probing (via_recency) — even though SSH is still unreachable.
    //    This is the "sau în ultimul minut a răspuns" rule + the SSH-throttle guard.
    reachability::stamp_ssh_ok(&pool, device_id)
        .await
        .expect("persist SSH success");
    assert_eq!(
        ssh_status(pool.clone()).await,
        STATUS_REACHABLE,
        "stamp_ssh_ok marks the device reachable"
    );
    let r = reachability::reachable_for_mitigation(&pool, device_id).await;
    assert!(r.ssh_ok, "a contact within 60s should satisfy the gate");
    assert!(
        r.via_recency,
        "recent contact must short-circuit the live probe"
    );
    assert_eq!(r.ssh_status, STATUS_REACHABLE);

    // 3) Stability: a just-reachable device is ssh_ok but NOT stable (auto held).
    //    stamp_ssh_ok started ssh_reachable_since = now, so < 5 min -> not stable.
    assert!(
        !r.stable,
        "a device reachable for <5 min is not stable (auto held)"
    );
    // Backdate the stability clock past the window -> now stable (auto resumes).
    sqlx::query(
        "UPDATE devices SET ssh_reachable_since = UTC_TIMESTAMP() - INTERVAL 6 MINUTE WHERE id = ?",
    )
    .bind(device_id)
    .execute(&pool)
    .await
    .expect("backdate stability clock");
    let r = reachability::reachable_for_mitigation(&pool, device_id).await;
    assert!(r.stable, "reachable for >5 min continuous -> stable");

    // Cleanup (FKs cascade from devices; be explicit for isolation).
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await;
}
