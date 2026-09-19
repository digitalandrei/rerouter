mod common;

use chrono::{Duration, Utc};
use rerouter_controller::{config::Config, detection::engine};

#[tokio::test]
async fn awaiting_revert_holds_through_quiet_samples_and_takeover_then_rearms_without_reapply() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    let device =
        sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,'192.0.2.244',0)")
            .bind(format!("awaiting-{}", uuid::Uuid::new_v4()))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let rule=sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,automatic_reroute_enabled,automatic_revert_enabled) VALUES('awaiting ownership',?,?,'rx_bps','>',100,0,1,'auto',0,0)").bind(device).bind(interface).execute(pool).await.unwrap().last_insert_id();
    sqlx::query(
        "INSERT INTO rule_states(rule_id,current_state,last_metric_value) VALUES(?,'firing',200)",
    )
    .bind(rule)
    .execute(pool)
    .await
    .unwrap();
    let bundle=sqlx::query("INSERT INTO reroute_bundles(rule_id,trigger_type,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,automatic_recovery_cancelled_at) VALUES(?,'automatic','succeeded','abort_and_compensate',1,1,'active',1,UTC_TIMESTAMP())").bind(rule).execute(pool).await.unwrap().last_insert_id();
    let reroute=sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,rule_id,trigger_type,state,mutation_effect) VALUES(?,0,?,?,'automatic','succeeded','changed')").bind(bundle).bind(device).bind(rule).execute(pool).await.unwrap().last_insert_id();
    let base = Utc::now() - Duration::seconds(20);
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,0)").bind(interface).bind(device).bind(base).execute(pool).await.unwrap();
    let cfg = Config::default();
    engine::evaluate_device(pool, &cfg, device).await.unwrap();
    for tick in 1..=3 {
        sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
            .bind(base + Duration::seconds(tick))
            .bind(interface)
            .execute(pool)
            .await
            .unwrap();
        engine::evaluate_device(pool, &cfg, device).await.unwrap();
    }
    let held: String = sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
        .bind(rule)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(held, "recovered_awaiting_revert");
    sqlx::query(
        "UPDATE interface_metrics_current SET sampled_at=?,rx_bps=200 WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(4))
    .bind(interface)
    .execute(pool)
    .await
    .unwrap();
    engine::evaluate_device(pool, &cfg, device).await.unwrap();
    let refired: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(refired, "firing");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE rule_id=?")
        .bind(rule)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(
        count, 1,
        "renewed attack must not duplicate the owned activation"
    );
    // Enabling automatic revert does not override a prior manual takeover.
    sqlx::query("UPDATE rules SET automatic_revert_enabled=1 WHERE id=?")
        .bind(rule)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=?,rx_bps=0 WHERE interface_id=?")
        .bind(base + Duration::seconds(5))
        .bind(interface)
        .execute(pool)
        .await
        .unwrap();
    engine::evaluate_device(pool, &cfg, device).await.unwrap();
    let held_auto: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(held_auto, "recovered_awaiting_revert");
    // Once a verified whole-run inverse closes ownership, a direct new attack
    // takes the normal firing edge rather than being suppressed by the marker.
    let inverse=sqlx::query("INSERT INTO reroutes(device_id,rule_id,trigger_type,state,mutation_effect,rollback_of_reroute_id) VALUES(?,?,'rollback','succeeded','changed',?)").bind(device).bind(rule).bind(reroute).execute(pool).await.unwrap().last_insert_id();
    let manual_owned=sqlx::query("INSERT INTO reroutes(device_id,rule_id,trigger_type,state,mutation_effect) VALUES(?,?,'manual','succeeded','changed')").bind(device).bind(rule).execute(pool).await.unwrap().last_insert_id();
    sqlx::query(
        "UPDATE interface_metrics_current SET sampled_at=?,rx_bps=200 WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(6))
    .bind(interface)
    .execute(pool)
    .await
    .unwrap();
    assert_eq!(
        engine::evaluate_device(pool, &cfg, device).await.unwrap(),
        0,
        "manual rule ownership must hold the marker"
    );
    let manual_inverse=sqlx::query("INSERT INTO reroutes(device_id,rule_id,trigger_type,state,mutation_effect,rollback_of_reroute_id) VALUES(?,?,'rollback','succeeded','changed',?)").bind(device).bind(rule).bind(manual_owned).execute(pool).await.unwrap().last_insert_id();
    sqlx::query("UPDATE rule_states SET current_state='recovered_awaiting_revert' WHERE rule_id=?")
        .bind(rule)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
        .bind(base + Duration::seconds(7))
        .bind(interface)
        .execute(pool)
        .await
        .unwrap();
    let fired = engine::evaluate_device(pool, &cfg, device).await.unwrap();
    let after_inverse: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        fired, 1,
        "state after verified inverse and direct attack: {after_inverse}"
    );
    sqlx::query("DELETE FROM reroutes WHERE id IN (?,?)")
        .bind(manual_inverse)
        .bind(manual_owned)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(inverse)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id=?")
        .bind(reroute)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(bundle)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rules WHERE id=?")
        .bind(rule)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}
