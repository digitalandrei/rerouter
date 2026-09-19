mod common;

use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use rerouter_controller::{
    api::{self, manual_mitigations},
    auth::sessions::Session,
    config::Config,
    reroute::{bundle::BundleAction, device_plan::PreparationReader, templates},
};
use serde_json::json;

struct CannedReader;
impl PreparationReader for CannedReader {
    fn read_one<'a>(
        &'a self,
        _: u64,
        _: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async { Ok(String::new()) })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move { Ok(vec![String::new(); commands.len()]) })
    }
}

#[tokio::test]
async fn observe_preview_is_exact_authorized_and_never_writes() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    let user = sqlx::query("INSERT INTO users(name,email,password) VALUES('preview',?,'unused')")
        .bind(format!("preview-{}@example.test", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let device=sqlx::query("INSERT INTO devices(name,hostname,ssh_host_fingerprint) VALUES(?,'192.0.2.90','SHA256:canned')")
        .bind(format!("preview-{}",uuid::Uuid::new_v4())).execute(pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO device_bgp_networks(device_id,prefix,last_discovered_at) VALUES(?,'192.0.2.0/24',UTC_TIMESTAMP())").bind(device).execute(pool).await.unwrap();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='null_route_prefix'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, template_id).await.unwrap();
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "test".into(),
    };
    let state = api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: Key::from(&[91; 64]),
    };
    let action = BundleAction {
        device_id: device,
        template,
        params: json!({"prefix":"192.0.2.9/32"}),
        reason: "test".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: None,
        original_reroute_id: None,
    };
    let (status, axum::Json(body)) = manual_mitigations::preview_actions_with_reader(
        &state,
        &actor,
        "manual_mitigation",
        None,
        vec![action],
        json!({"kind":"manual","name":"Run once"}),
        "test".into(),
        json!({"actions":[]}),
        None,
        &CannedReader,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert!(body["preview_token"].is_string());
    assert!(body["projections"][0]["after_config"]
        .as_str()
        .unwrap()
        .contains("255.255.255.255 Null0"));
    let reroutes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE device_id=?")
        .bind(device)
        .fetch_one(pool)
        .await
        .unwrap();
    assert_eq!(reroutes, 0);
    sqlx::query("DELETE FROM execution_plans WHERE user_id=?")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM device_bgp_networks WHERE device_id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
}
