//! Read-only presentation contract for logical mitigation runs and dashboard
//! alert de-noising. Fixtures write only to the dedicated test schema; no SSH,
//! router, notification, or execution path is invoked.

mod common;

use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::Router;
use axum_extra::extract::cookie::{Key, SignedCookieJar};
use rerouter_controller::{api, auth::sessions, config::Config};
use serde_json::{json, Value};
use sqlx::MySqlPool;
use tower::ServiceExt;

async fn viewer(pool: &MySqlPool, key: &Key) -> (u64, String, String) {
    let email = format!("run-summary-{}@example.test", uuid::Uuid::new_v4());
    let id = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('Run summary fixture',?,'unused')",
    )
    .bind(&email)
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    sqlx::query(
        "INSERT INTO role_user(role_id,user_id) SELECT id,? FROM roles WHERE name='viewer'",
    )
    .bind(id)
    .execute(pool)
    .await
    .unwrap();
    let (session, _) = sessions::create(pool, id, "127.0.0.1", "run-summary-test", 1)
        .await
        .unwrap();
    let token = sessions::mark_totp_verified_and_rotate(pool, session)
        .await
        .unwrap();
    let response = SignedCookieJar::new(key.clone())
        .add(sessions::build_cookie(token, time::Duration::hours(1)))
        .into_response();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    (id, email, cookie)
}

async fn get(app: &Router, cookie: &str, path: &str) -> (StatusCode, Value) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header("cookie", cookie)
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"raw":String::from_utf8_lossy(&bytes)})),
    )
}

#[tokio::test]
async fn one_original_run_owns_summary_lifecycle_and_dashboard_action_events_are_optional() {
    let db = common::test_database().await;
    let pool = db.pool().clone();
    let key = Key::from(&[83_u8; 64]);
    let (user, email, cookie) = viewer(&pool, &key).await;
    let app = api::router(api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: key,
    });
    let suffix = uuid::Uuid::new_v4().simple().to_string();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.240')")
        .bind(format!("run-summary-router-{suffix}"))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let preset =
        sqlx::query("INSERT INTO mitigation_presets(name,created_by,updated_by) VALUES(?,?,?)")
            .bind(format!("run-summary-preset-{suffix}"))
            .bind(user)
            .bind(user)
            .execute(&pool)
            .await
            .unwrap()
            .last_insert_id();
    let source = json!({"kind":"preset","preset_id":preset,"preset_name":format!("run-summary-preset-{suffix}"),
        "preset_revision":3,"verification_mode":"configuration_only","routing_verified":false});
    let root = sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at,finished_at) \
        VALUES('manual',?,'succeeded','abort_and_compensate',2,2,'active',2,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(user).bind(sqlx::types::Json(&source)).execute(&pool).await.unwrap().last_insert_id();
    let child_source = json!({"kind":"bundle_revert","original_bundle_id":root,"preset_id":preset,
        "verification_mode":"configuration_only","routing_verified":false});
    let child = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json) \
        VALUES(?,'manual',?,'succeeded','abort_and_compensate',1,1,'active',1,?)")
        .bind(root).bind(user).bind(sqlx::types::Json(&child_source)).execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=? WHERE id=?")
        .bind(child)
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    // The active source run is older than the five-row recent-history window.
    // Current state must come from active_runs, not from recent_runs.
    let mut newer_inactive = Vec::new();
    for _ in 0..6 {
        newer_inactive.push(sqlx::query("INSERT INTO reroute_bundles(trigger_type,triggered_by_user_id,state,failure_policy,total_actions,completed_actions,lifecycle_state,remaining_mutations,source_json,started_at,finished_at) \
            VALUES('manual',?,'succeeded','abort_and_compensate',0,0,'inactive',0,?,UTC_TIMESTAMP(),UTC_TIMESTAMP())")
            .bind(user).bind(sqlx::types::Json(&source)).execute(&pool).await.unwrap().last_insert_id());
    }
    let changed = sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,0,?,'manual','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(root).bind(device).execute(&pool).await.unwrap().last_insert_id();
    let unknown = sqlx::query("INSERT INTO reroutes(bundle_id,bundle_position,device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,1,?,'manual','uncertain','unknown',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(root).bind(device).execute(&pool).await.unwrap().last_insert_id();
    let standalone = sqlx::query("INSERT INTO reroutes(device_id,trigger_type,state,mutation_effect,started_at,finished_at) \
        VALUES(?,'manual','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).execute(&pool).await.unwrap().last_insert_id();

    let marker = format!("run-summary-{suffix}");
    for (event, reroute) in [("reroute_started", changed), ("reroute_succeeded", changed)] {
        sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES(?,'info',?,?,?)")
            .bind(event).bind(device).bind(sqlx::types::Json(json!({"reroute_id":reroute,"marker":marker})))
            .bind(format!("{marker}:{event}:{reroute}")).execute(&pool).await.unwrap();
    }
    sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES('reroute_succeeded','info',?,?,?)")
        .bind(device).bind(sqlx::types::Json(json!({"reroute_id":standalone,"marker":marker})))
        .bind(format!("{marker}:standalone")).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO alerts(event_type,severity,payload_json,dedup_key) VALUES('rule_fired','warning',?,?)")
        .bind(sqlx::types::Json(json!({"marker":marker}))).bind(format!("{marker}:rule"))
        .execute(&pool).await.unwrap();
    // The newest row is bundled noise. A one-row dashboard request must skip
    // it in SQL instead of paging it first and returning no useful event.
    sqlx::query("INSERT INTO alerts(event_type,severity,device_id,payload_json,dedup_key) VALUES('reroute_uncertain','critical',?,?,?)")
        .bind(device).bind(sqlx::types::Json(json!({"reroute_id":unknown,"marker":marker})))
        .bind(format!("{marker}:uncertain:{unknown}")).execute(&pool).await.unwrap();

    let (status, active) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?lifecycle=active&page=1&per_page=200",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{active}");
    let active_items = active["items"].as_array().unwrap();
    let summary = active_items
        .iter()
        .find(|item| item["id"] == root)
        .expect("original active run");
    assert!(
        !active_items.iter().any(|item| item["id"] == child),
        "recovery child must not be a second active mitigation"
    );
    assert_eq!(summary["execution_state"], "succeeded");
    assert_eq!(summary["lifecycle_state"], "active");
    assert_eq!(summary["remaining_mutations"], 2);
    assert_eq!(summary["remaining_changes"], 1);
    assert_eq!(summary["unknown_effects"], 1);
    assert_eq!(summary["affected_devices"][0]["id"], device);
    assert_eq!(summary["triggered_by"], email);
    assert_eq!(summary["recovery_bundle_id"], child);
    assert_eq!(summary["verification_mode"], "configuration_only");
    assert_eq!(summary["revert"]["available"], false);
    assert!(summary["revert"]["block_reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason.as_str().unwrap_or_default().contains("unknown")));

    let (_, logical) = get(
        &app,
        &cookie,
        "/api/reroute-bundles?original_only=true&page=1&per_page=200",
    )
    .await;
    assert!(logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == root));
    assert!(!logical["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == child));
    let (_, detail) = get(&app, &cookie, &format!("/api/reroute-bundles/{root}")).await;
    assert!(detail["created_at"].is_string(), "{detail}");
    assert_eq!(
        detail["still_applied_reroute_ids"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let (_, preset_value) = get(&app, &cookie, &format!("/api/mitigation-presets/{preset}")).await;
    assert_eq!(
        preset_value["recent_runs"].as_array().unwrap().len(),
        5,
        "{preset_value}"
    );
    assert!(
        !preset_value["recent_runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["bundle_id"] == root),
        "older active run is deliberately outside recent history"
    );
    assert_eq!(
        preset_value["active_runs"].as_array().unwrap().len(),
        1,
        "{preset_value}"
    );
    assert_eq!(preset_value["active_runs"][0]["bundle_id"], root);
    assert_eq!(preset_value["active_runs"][0]["remaining_mutations"], 2);
    assert!(
        !preset_value["active_runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["bundle_id"] == child),
        "recovery child must stay nested under its source run"
    );

    let (_, raw) = get(&app, &cookie, "/api/alerts?limit=200").await;
    let raw_marker = raw["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["payload"]["marker"] == marker)
        .collect::<Vec<_>>();
    assert_eq!(
        raw_marker.len(),
        5,
        "raw alert history must remain complete"
    );
    assert_eq!(
        raw_marker
            .iter()
            .find(|row| row["payload"]["reroute_id"] == changed)
            .unwrap()["bundle_id"],
        root
    );
    let (_, dashboard) = get(
        &app,
        &cookie,
        "/api/alerts?limit=200&exclude_bundle_action_events=true",
    )
    .await;
    let dashboard_marker = dashboard["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["payload"]["marker"] == marker)
        .collect::<Vec<_>>();
    assert_eq!(
        dashboard_marker.len(),
        2,
        "only bundled per-action lifecycle events are hidden"
    );
    assert!(dashboard_marker
        .iter()
        .any(|row| row["payload"]["reroute_id"] == standalone));
    assert!(dashboard_marker
        .iter()
        .any(|row| row["event_type"] == "rule_fired"));
    let (_, one_raw) = get(&app, &cookie, "/api/alerts?limit=1").await;
    assert_eq!(one_raw["rows"][0]["event_type"], "reroute_uncertain");
    let (_, one_dashboard) = get(
        &app,
        &cookie,
        "/api/alerts?limit=1&exclude_bundled_action_lifecycle=true",
    )
    .await;
    assert_eq!(
        one_dashboard["rows"][0]["event_type"], "rule_fired",
        "filter must run before LIMIT"
    );

    sqlx::query("DELETE FROM alerts WHERE dedup_key LIKE ?")
        .bind(format!("{marker}%"))
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroutes WHERE id IN (?,?,?)")
        .bind(changed)
        .bind(unknown)
        .bind(standalone)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=NULL WHERE id=?")
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(child)
        .execute(&pool)
        .await
        .unwrap();
    for id in newer_inactive {
        sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
        .bind(root)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigation_presets WHERE id=?")
        .bind(preset)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(&pool)
        .await
        .unwrap();
}
