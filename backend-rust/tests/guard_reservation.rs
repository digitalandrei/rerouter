//! Reservation critical-section safety re-checks. `reserve_and_persist` runs the
//! authoritative gate under the per-device advisory lock: a global maintenance
//! lock or a per-device admin lock set AFTER the lock-free early check must still
//! stop the action at this last gate (TOCTOU close). Both reads fail closed, and a
//! blocked reservation must not leave a `reroutes` row behind.
//!
//! DB integration test — runs only when DATABASE_URL points at a MariaDB the test
//! may migrate + write to; skips otherwise. Cleans up its rows.

use rerouter_controller::config::Config;
use rerouter_controller::db::MIGRATOR;
use rerouter_controller::reroute::executor::ActionRequest;
use rerouter_controller::reroute::guard::{self, BlockReason};
use rerouter_controller::reroute::locks;
use rerouter_controller::reroute::templates::{RenderedPlan, Template};
use serde_json::json;
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

/// A minimal manual `ActionRequest` for `device_id`. The reservation short-circuits
/// on the lock gates before it ever needs a valid template, so `template.id = 0`
/// (no `reroute_templates` row) is fine for the blocked cases under test.
fn manual_request(device_id: u64) -> ActionRequest {
    ActionRequest {
        device_id,
        template: Template {
            id: 0,
            name: "null_route_prefix".into(),
            display_name: None,
            description: None,
            provider_type: "device_cli".into(),
            mode: "ios_ssh".into(),
            automatic_allowed: false,
            parameter_schema: json!({}),
            plan: json!({}),
            verification: json!({}),
            rollback_template_id: None,
            v6_sibling_template_id: None,
            enabled: true,
        },
        params: json!({}),
        trigger_type: "manual",
        rule_id: None,
        rule_event_id: None,
        rollback_of_reroute_id: None,
        user_id: None,
        actor_context: None,
        reason: Some("guard reservation test".into()),
        defer_cooldown: false,
    }
}

fn plan() -> RenderedPlan {
    RenderedPlan {
        template_id: 0,
        template_name: "null_route_prefix".into(),
        config_mode: true,
        commands: vec!["ip route 192.0.2.1 255.255.255.255 Null0".into()],
        verify: None,
    }
}

async fn set_maintenance_lock(pool: &MySqlPool, value: &str) {
    sqlx::query(
        "INSERT INTO system_settings (`key`, `value`) VALUES ('global_maintenance_lock', ?) \
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
    )
    .bind(value)
    .execute(pool)
    .await
    .expect("set global_maintenance_lock");
}

async fn reroute_count(pool: &MySqlPool, device_id: u64) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM reroutes WHERE device_id = ?")
        .bind(device_id)
        .fetch_one(pool)
        .await
        .expect("count reroutes")
}

#[tokio::test]
async fn reservation_rechecks_maintenance_and_device_locks() {
    let Some(pool) = pool_or_skip().await else {
        eprintln!("DATABASE_URL not set — skipping guard reservation integration test");
        return;
    };
    let cfg = Config::default();

    let device_id = sqlx::query(
        "INSERT INTO devices (name, hostname) VALUES ('guard-reservation-test', '127.0.0.1')",
    )
    .execute(&pool)
    .await
    .expect("insert device")
    .last_insert_id();

    let req = manual_request(device_id);
    let rendered = plan();

    // 1) Global maintenance lock set (after any early check) blocks at the reservation.
    set_maintenance_lock(&pool, "true").await;
    let r = guard::reserve_and_persist(&pool, &cfg, &req, &rendered).await;
    assert_eq!(
        r,
        Err(BlockReason::MaintenanceLock),
        "maintenance lock must block inside the reservation critical section"
    );
    assert_eq!(
        reroute_count(&pool, device_id).await,
        0,
        "a maintenance-blocked reservation must not insert a reroute"
    );

    // 2) Clear maintenance, lock the device instead — still blocked, still no row.
    set_maintenance_lock(&pool, "false").await;
    let lock_id = locks::create(
        &pool,
        "device",
        Some(&device_id.to_string()),
        None,
        "manual",
        "guard reservation test lock",
        None,
    )
    .await
    .expect("create device lock");

    let r = guard::reserve_and_persist(&pool, &cfg, &req, &rendered).await;
    assert_eq!(
        r,
        Err(BlockReason::DeviceLocked),
        "an uncleared device lock must block inside the reservation critical section"
    );
    assert_eq!(
        reroute_count(&pool, device_id).await,
        0,
        "a device-locked reservation must not insert a reroute"
    );

    // Cleanup.
    let _ = sqlx::query("DELETE FROM locks WHERE id = ?")
        .bind(lock_id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await;
}
