//! Persistence must advance on observations, not repeated scheduler evaluations.
mod common;

use chrono::{Duration, Utc};
use rerouter_controller::{config::Config, detection::engine};

#[tokio::test]
async fn repeated_samples_and_stale_gaps_cannot_fire_or_clear_an_incident() {
    let pool = common::test_database().await;
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(&*pool)
        .await
        .unwrap();
    let device =
        sqlx::query("INSERT INTO devices(name,hostname,enabled) VALUES(?,'192.0.2.250',0)")
            .bind(format!("evidence-{}", uuid::Uuid::new_v4()))
            .execute(&*pool)
            .await
            .unwrap()
            .last_insert_id();
    let interface = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,1)")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap()
        .last_insert_id();
    let rule=sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,operator,threshold_value,duration_seconds,consecutive_samples, \
        recovery_mode,recovery_threshold_value,recovery_consecutive_samples,automatic_reroute_enabled) \
        VALUES('Observation evidence',?,?,'rx_bps','>',100,0,3,'threshold',50,2,0)")
        .bind(device).bind(interface).execute(&*pool).await.unwrap().last_insert_id();
    let base = Utc::now() - Duration::seconds(20);
    sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,200)")
        .bind(interface).bind(device).bind(base).execute(&*pool).await.unwrap();
    let cfg = Config::default();
    for _ in 0..3 {
        assert_eq!(
            engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
            0
        );
    }
    let state: (String, u32) = sqlx::query_as(
        "SELECT current_state,consecutive_match_count FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(state, ("matching".into(), 1));
    for tick in 1..=2 {
        sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
            .bind(base + Duration::seconds(tick))
            .bind(interface)
            .execute(&*pool)
            .await
            .unwrap();
        assert_eq!(
            engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
            usize::from(tick == 2)
        );
    }
    // Invalid evidence resets unproved progress but must preserve a firing
    // incident; a subsequent matching sample cannot demote it to matching.
    sqlx::query("UPDATE interface_metrics_current SET valid_sample=0 WHERE interface_id=?")
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    sqlx::query(
        "UPDATE interface_metrics_current SET valid_sample=1,sampled_at=? WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(3))
    .bind(interface)
    .execute(&*pool)
    .await
    .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    let current: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(current, "firing");
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=?,rx_bps=0 WHERE interface_id=?")
        .bind(base + Duration::seconds(4))
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    for _ in 0..3 {
        engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    }
    let recovery: (String, u32) = sqlx::query_as(
        "SELECT current_state,recovery_consecutive FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(recovery, ("firing".into(), 1));
    sqlx::query("UPDATE interface_metrics_current SET sampled_at=? WHERE interface_id=?")
        .bind(base + Duration::seconds(5))
        .bind(interface)
        .execute(&*pool)
        .await
        .unwrap();
    engine::evaluate_device(&pool, &cfg, device).await.unwrap();
    let current: String =
        sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
            .bind(rule)
            .fetch_one(&*pool)
            .await
            .unwrap();
    assert_eq!(current, "clear");
    // A controller/stale-data gap cannot inherit a previously started window.
    let old = Utc::now() - Duration::hours(1);
    sqlx::query("UPDATE rules SET duration_seconds=60,consecutive_samples=0 WHERE id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("UPDATE rule_states SET current_state='matching',first_matched_at=?,last_observation_at=?,last_observation_json=? WHERE rule_id=?")
        .bind(old).bind(old).bind(sqlx::types::Json(serde_json::json!({interface.to_string():old}))).bind(rule).execute(&*pool).await.unwrap();
    sqlx::query(
        "UPDATE interface_metrics_current SET sampled_at=?,rx_bps=200 WHERE interface_id=?",
    )
    .bind(base + Duration::seconds(6))
    .bind(interface)
    .execute(&*pool)
    .await
    .unwrap();
    assert_eq!(
        engine::evaluate_device(&pool, &cfg, device).await.unwrap(),
        0
    );
    let state: (String, u32) = sqlx::query_as(
        "SELECT current_state,consecutive_match_count FROM rule_states WHERE rule_id=?",
    )
    .bind(rule)
    .fetch_one(&*pool)
    .await
    .unwrap();
    assert_eq!(state, ("matching".into(), 1));
    sqlx::query("DELETE FROM alerts WHERE rule_id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM rules WHERE id=?")
        .bind(rule)
        .execute(&*pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(&*pool)
        .await
        .unwrap();
}
