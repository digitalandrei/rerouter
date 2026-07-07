//! Device reachability for mitigations (reroute preflight gate). A reroute pushes
//! config over SSH, so `reachable_for_mitigation` decides on SSH: it must answer,
//! OR have answered within the last 60s (the recency short-circuit that avoids
//! re-probing / tripping the device's SSH throttle). Telnet port-open is an
//! informational secondary signal that never gates.
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB the test
//! may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::db::MIGRATOR;
use rerouter_controller::reroute::reachability;
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
    // is nothing to connect to, so the live liveness probe fails.
    let device_id = sqlx::query(
        "INSERT INTO devices (name, hostname, ssh_port) VALUES (?, '127.0.0.1', 1)",
    )
    .bind("reachability-test")
    .execute(&pool)
    .await
    .expect("insert device")
    .last_insert_id();

    // Helper: read the persisted ssh_reachable display column.
    let ssh_reachable = |pool: MySqlPool| async move {
        sqlx::query_scalar::<_, bool>("SELECT ssh_reachable FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .expect("read ssh_reachable")
    };

    // 1) No recent contact + unreachable SSH -> ssh_ok = false (the gate refuses a
    //    reroute up front; telnet is not consulted for the decision). The failure
    //    is also persisted to the display column.
    let r = reachability::reachable_for_mitigation(&pool, device_id).await;
    assert!(!r.ssh_ok, "unreachable SSH must not pass the gate");
    assert!(!r.via_recency, "no recent contact -> a live probe was attempted");
    assert!(r.ssh_error.is_some(), "a probe failure should carry a reason");
    assert!(
        !ssh_reachable(pool.clone()).await,
        "a failed probe sets ssh_reachable = 0"
    );

    // 1b) The periodic probe records the same outcome (unreachable here).
    assert!(
        !reachability::probe_ssh_and_store(&pool, device_id).await,
        "periodic probe of an unreachable device returns false"
    );
    assert!(!ssh_reachable(pool.clone()).await, "and persists ssh_reachable = 0");

    // 2) Recency short-circuit: stamp a fresh SSH contact, then the decision passes
    //    WITHOUT probing (via_recency) — even though SSH is still unreachable. This
    //    is the "sau în ultimul minut a răspuns" rule and the SSH-throttle guard.
    //    stamp_ssh_ok also marks the device SSH-reachable for the display.
    reachability::stamp_ssh_ok(&pool, device_id).await;
    assert!(
        ssh_reachable(pool.clone()).await,
        "stamp_ssh_ok sets ssh_reachable = 1"
    );
    let r = reachability::reachable_for_mitigation(&pool, device_id).await;
    assert!(r.ssh_ok, "a contact within 60s should satisfy the gate");
    assert!(r.via_recency, "recent contact must short-circuit the live probe");

    // 3) Telnet probe (informational). Bind a listener and point the device's
    //    telnet port at it: the port-open probe sets telnet_reachable = 1 and
    //    stamps last_telnet_ok_at. This signal never gates a reroute.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind telnet stub");
    let telnet_port = listener.local_addr().unwrap().port();
    sqlx::query("UPDATE devices SET telnet_port = ? WHERE id = ?")
        .bind(telnet_port)
        .bind(device_id)
        .execute(&pool)
        .await
        .expect("set telnet_port");

    reachability::probe_telnet(&pool, device_id).await;
    let (telnet_reachable, last_telnet_ok_at): (bool, Option<chrono::DateTime<chrono::Utc>>) =
        sqlx::query_as("SELECT telnet_reachable, last_telnet_ok_at FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_one(&pool)
            .await
            .expect("read telnet columns");
    assert!(telnet_reachable, "open telnet port -> telnet_reachable = 1");
    assert!(
        last_telnet_ok_at.is_some(),
        "an open telnet port stamps last_telnet_ok_at"
    );
    drop(listener);

    // Cleanup (FKs cascade from devices; be explicit for isolation).
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await;
}
