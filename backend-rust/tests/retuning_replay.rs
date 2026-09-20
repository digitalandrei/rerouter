//! Timestamped replay through the real detector with unchanged evidence values.
mod common;

use chrono::{Duration, Utc};
use futures_util::FutureExt;
use rerouter_controller::{config::Config, detection::engine};
use serde_json::json;
use std::process::Command;

async fn replay(
    pool: &sqlx::MySqlPool,
    aggregate: bool,
    cadence: i64,
    rollup: i64,
    fire_count: u32,
    recovery_count: Option<u32>,
    duration: u32,
) -> (i64, i64) {
    let device = sqlx::query("INSERT INTO devices(name,hostname,enabled,poll_interval_seconds) VALUES(?,'192.0.2.248',0,?)")
        .bind(format!("retune-replay-{}", uuid::Uuid::new_v4())).bind(cadence)
        .execute(pool).await.unwrap().last_insert_id();
    let mut interfaces = Vec::new();
    for index in 1..=if aggregate { 2 } else { 1 } {
        let id = sqlx::query("INSERT INTO device_interfaces(device_id,if_index) VALUES(?,?)")
            .bind(device)
            .bind(index)
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
        interfaces.push(id);
    }
    let rule = sqlx::query("INSERT INTO rules(name,device_id,interface_id,metric,metric_aggregation,operator,threshold_value,duration_seconds,consecutive_samples,recovery_mode,recovery_threshold_value,recovery_consecutive_samples,recovery_window_seconds,automatic_reroute_enabled,automatic_revert_enabled) VALUES('Retuning replay',?,?,'rx_bps',?,'>',100,?,?,'threshold',50,?,?,0,0)")
        .bind(if aggregate { None } else { Some(device) })
        .bind(if aggregate { None } else { Some(interfaces[0]) })
        .bind(if aggregate { "sum" } else { "single" })
        .bind(duration).bind(fire_count).bind(recovery_count).bind(duration)
        .execute(pool).await.unwrap().last_insert_id();
    if aggregate {
        for id in &interfaces {
            sqlx::query(
                "INSERT INTO rule_interfaces(rule_id,interface_id,device_id) VALUES(?,?,?)",
            )
            .bind(rule)
            .bind(id)
            .bind(device)
            .execute(pool)
            .await
            .unwrap();
        }
    }
    let mut cfg = Config::default();
    cfg.telemetry.stale_after_seconds = 2000;
    cfg.telemetry.metrics_rollup_seconds = rollup as u64;
    let origin = Utc::now() - Duration::seconds(1000);
    let mut firing = None;
    let mut recovered = None;
    for elapsed in (0..=720).step_by(5) {
        for interface in &interfaces {
            // A sum cannot advance faster than its slowest member, even while
            // evaluations and the other member continue every five seconds.
            let member_period = cadence;
            if elapsed % member_period == 0 {
                sqlx::query("INSERT INTO interface_metrics_current(interface_id,device_id,sampled_at,valid_sample,rx_bps) VALUES(?,?,?,1,?) ON DUPLICATE KEY UPDATE sampled_at=VALUES(sampled_at),rx_bps=VALUES(rx_bps)")
                    .bind(interface).bind(device).bind(origin + Duration::seconds(elapsed))
                    .bind(if elapsed < 300 { 200f64 } else { 0f64 })
                    .execute(pool).await.unwrap();
            }
        }
        if aggregate && elapsed % rollup == 0 {
            engine::evaluate_aggregate_rules(pool, &cfg).await.unwrap();
        } else if !aggregate && elapsed % cadence == 0 {
            engine::evaluate_device(pool, &cfg, device).await.unwrap();
        }
        let state: String =
            sqlx::query_scalar("SELECT current_state FROM rule_states WHERE rule_id=?")
                .bind(rule)
                .fetch_one(pool)
                .await
                .unwrap();
        if state == "firing" && firing.is_none() {
            firing = Some(elapsed);
        }
        if state == "clear" && firing.is_some() {
            recovered = Some(elapsed);
            break;
        }
    }
    let result = (
        firing.expect("replay must fire"),
        recovered.expect("replay must recover"),
    );
    sqlx::query("DELETE FROM alerts WHERE rule_id=?")
        .bind(rule)
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
    result
}

fn retuned_counts(
    aggregate: bool,
    old_period: i64,
    new_period: i64,
    rollup: i64,
    fire_count: u32,
    recovery_count: Option<u32>,
    duration: u32,
) -> (u32, Option<u32>) {
    let token = uuid::Uuid::new_v4().to_string();
    let interfaces = if aggregate {
        json!([{"id":11,"device_id":1},{"id":12,"device_id":1}])
    } else {
        json!([{"id":11,"device_id":1}])
    };
    let members = if aggregate {
        json!([11, 12])
    } else {
        json!([])
    };
    let snapshot = json!({
        "captured_at":"2026-09-20T10:00:00Z",
        "metrics_rollup_seconds":rollup,
        "settings":{"operating_mode":"observe","automatic_actions_enabled":false},
        "owned_run_rule_ids":[],
        "devices":[{"id":1,"poll_interval_seconds":old_period}],
        "interfaces":interfaces,
        "rules":[{
            "id":1,"metric":"rx_bps","interface_id":if aggregate { serde_json::Value::Null } else { json!(11) },
            "metric_aggregation":if aggregate { "sum" } else { "single" },
            "member_interface_ids":members,"consecutive_samples":fire_count,
            "recovery_mode":"threshold","recovery_consecutive_samples":recovery_count,
            "duration_seconds":duration,"recovery_window_seconds":duration,
            "threshold_value":100,"recovery_threshold_value":50,"current_state":"clear",
            "automatic_reroute_enabled":false,"automatic_revert_enabled":false
        }]
    });
    let path = std::env::temp_dir().join(format!("rerouter-retune-{token}.json"));
    std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
    let script =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../scripts/retune-sample-counts.py");
    let output = Command::new("python3")
        .arg(script)
        .arg(&path)
        .arg("--poll-interval")
        .arg(format!("1={new_period}"))
        .output()
        .unwrap();
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "retune tool failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let request = report["apply_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["path"] == "/api/rules/1");
    let Some(body) = request.map(|request| &request["body"]) else {
        return (fire_count, recovery_count);
    };
    let next_recovery = if body.get("recovery_consecutive_samples").is_some() {
        body["recovery_consecutive_samples"]
            .as_u64()
            .map(|value| value as u32)
    } else {
        recovery_count
    };
    (
        body["consecutive_samples"].as_u64().unwrap() as u32,
        next_recovery,
    )
}

#[tokio::test]
async fn faster_single_and_aggregate_collection_preserves_sample_and_duration_windows() {
    let db = common::test_database().await;
    let prior_mode: String =
        sqlx::query_scalar("SELECT `value` FROM system_settings WHERE `key`='operating_mode'")
            .fetch_one(db.pool())
            .await
            .unwrap();
    let prior_auto: String = sqlx::query_scalar(
        "SELECT `value` FROM system_settings WHERE `key`='automatic_actions_enabled'",
    )
    .fetch_one(db.pool())
    .await
    .unwrap();
    let outcome = std::panic::AssertUnwindSafe(async {
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(db.pool()).await.unwrap();
    sqlx::query("UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'")
        .execute(db.pool()).await.unwrap();
    let mut before = Vec::new(); let mut after = Vec::new();
    for (scenario, aggregate, old_period, new_period, rollup, count, recovery, duration) in [
        ("single_counts", false, 30, 10, 10, 3, Some(2), 0),
        ("aggregate_member_dominated", true, 60, 20, 10, 3, Some(2), 0),
        ("aggregate_rollup_dominated", true, 20, 10, 30, 3, Some(2), 0),
        ("single_null_recovery_fallback", false, 30, 10, 10, 3, None, 0),
        (
            "single_explicit_duration_disabled_counts",
            false,
            30,
            10,
            10,
            0,
            Some(0),
            60,
        ),
        (
            "aggregate_explicit_duration_disabled_counts",
            true,
            60,
            20,
            10,
            0,
            Some(0),
            60,
        ),
    ] {
        let (new_count, new_recovery) = retuned_counts(aggregate, old_period, new_period, rollup, count, recovery, duration);
        let old = replay(db.pool(), aggregate, old_period, rollup, count, recovery, duration).await;
        let new = replay(
            db.pool(),
            aggregate,
            new_period,
            rollup,
            new_count,
            new_recovery,
            duration,
        )
        .await;
        assert!(
            new.0 >= old.0,
            "{scenario}: firing shortened {old:?} -> {new:?}"
        );
        assert!(
            new.1 >= old.1,
            "{scenario}: recovery shortened {old:?} -> {new:?}"
        );
        for (transition, old_at, new_at, window_start) in
            [("fired", old.0, new.0, 0), ("recovered", old.1, new.1, 300)]
        {
            before.push(json!({"scenario_id":scenario,"rule_id":1,"transition":transition,"elapsed_seconds":old_at,"window_start_seconds":window_start}));
            after.push(json!({"scenario_id":scenario,"rule_id":1,"transition":transition,"elapsed_seconds":new_at,"window_start_seconds":window_start}));
        }
    }
    println!(
        "HARDENING_REPLAY {}",
        json!({"before":before,"after":after})
    );
    }).catch_unwind().await;
    let _ = sqlx::query("UPDATE system_settings SET `value`=? WHERE `key`='operating_mode'")
        .bind(prior_mode)
        .execute(db.pool())
        .await;
    let _ =
        sqlx::query("UPDATE system_settings SET `value`=? WHERE `key`='automatic_actions_enabled'")
            .bind(prior_auto)
            .execute(db.pool())
            .await;
    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}
