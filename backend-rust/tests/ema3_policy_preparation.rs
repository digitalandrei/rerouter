mod common;

use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use rerouter_controller::api::{self, manual_mitigations, mitigation_presets};
use rerouter_controller::auth::sessions::Session;
use rerouter_controller::config::{Config, LabDevice};
use rerouter_controller::reroute::bundle::BundleAction;
use rerouter_controller::reroute::device_plan::{
    self, DeviceStateSnapshot, PreparationReader, PrepareInput, PreparedSafetyEffect,
    VerificationMode,
};
use rerouter_controller::reroute::preparation::{self, ActionDraft};
use serde_json::json;
use tokio::sync::Mutex;

static SERIAL: Mutex<()> = Mutex::const_new(());

struct Ema3Snapshot;
impl PreparationReader for Ema3Snapshot {
    fn read_one<'a>(
        &'a self,
        _: u64,
        _: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async { anyhow::bail!("unexpected unbatched read") })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move {
            assert_eq!(commands.len(), 3);
            Ok(vec![
            "router bgp 34501\n neighbor 23.45.23.197 remote-as 32787\n address-family ipv4\n neighbor 23.45.23.197 activate\n neighbor 23.45.23.197 prefix-list no-export out\n exit-address-family".into(),
            "route-map prepend-3 permit 100\n set as-path prepend 34501 34501 34501\nroute-map teste-iulian permit 10\n match ip address 10\n set local-preference 201".into(),
            "ip prefix-list no-export seq 10 deny 0.0.0.0/0 le 32\nip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 7 permit 194.102.117.0/24\nip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32".into(),
        ])
        })
    }
}

#[tokio::test]
async fn sanitized_ema3_snapshot_prepares_exact_additive_replacement() {
    let _serial = SERIAL.lock().await;
    let db = common::test_database().await;
    let pool = db.pool();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.242')")
        .bind(format!("ema3-fixture-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='bgp_export_policy_set'")
            .fetch_one(pool)
            .await
            .unwrap();
    let input = PrepareInput {
        device_id: device,
        template_id,
        template_name: "bgp_export_policy_set".into(),
        canonical_params: json!({"neighbor_ip":"23.45.23.197","policy_kind":"prefix_list","policy_name":"pfx-to-viva"}),
    };
    let prepared = device_plan::prepare_actions_read_only_with_reader(
        pool,
        std::slice::from_ref(&input),
        &Ema3Snapshot,
    )
    .await
    .unwrap()
    .remove(0);
    let DeviceStateSnapshot::ExportPolicyAttachment {
        prefix_list: before,
        ..
    } = &prepared.before[0]
    else {
        panic!("typed before")
    };
    assert_eq!(before.as_deref(), Some("no-export"));
    let DeviceStateSnapshot::ExportPolicyAttachment {
        prefix_list: after, ..
    } = &prepared.after[0]
    else {
        panic!("typed after")
    };
    assert_eq!(after.as_deref(), Some("pfx-to-viva"));
    assert_eq!(
        device_plan::prepared_safety_effect(&prepared).unwrap(),
        PreparedSafetyEffect::Additive
    );
    let advertised = prepared
        .verify
        .iter()
        .filter_map(|s| match s {
            DeviceStateSnapshot::BgpAdvertisement {
                prefix,
                present: true,
                ..
            } => Some(prefix.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(advertised.contains(&"194.105.142.0/24"));
    assert!(advertised.contains(&"194.102.117.0/24"));
    let configuration_only = device_plan::prepare_actions_read_only_with_reader_for_mode(
        pool,
        &[input],
        &Ema3Snapshot,
        VerificationMode::ConfigurationOnly,
    )
    .await
    .unwrap()
    .remove(0);
    assert_eq!(
        configuration_only.verification_mode,
        VerificationMode::ConfigurationOnly
    );
    assert!(configuration_only
        .verify
        .iter()
        .all(|state| !matches!(state, DeviceStateSnapshot::BgpAdvertisement { .. })));
    assert!(configuration_only
        .verify
        .iter()
        .any(|state| matches!(state, DeviceStateSnapshot::ExportPolicyAttachment { .. })));
    let inverse = configuration_only.inverse.as_ref().expect("proven inverse");
    assert_eq!(
        inverse.verification_mode,
        VerificationMode::ConfigurationOnly
    );
    assert!(inverse
        .verify
        .iter()
        .all(|state| !matches!(state, DeviceStateSnapshot::BgpAdvertisement { .. })));
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}

#[tokio::test]
async fn saved_export_policy_action_passes_definition_validation_before_typed_preparation() {
    let _serial = SERIAL.lock().await;
    let db = common::test_database().await;
    let pool = db.pool();
    let device = sqlx::query("INSERT INTO devices(name,hostname,ssh_host_fingerprint) VALUES(?,'192.0.2.243','SHA256:readiness-fixture')")
        .bind(format!("ema3-definition-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO device_bgp_peers(device_id,peer_remote_addr,last_polled_at) VALUES(?,'23.45.23.197',UTC_TIMESTAMP())")
        .bind(device).execute(pool).await.unwrap();
    sqlx::query("INSERT INTO routing_policy_snapshots(device_id,inventory_json,completeness,blockers_json,read_at) VALUES(?,?,'complete',JSON_ARRAY(),UTC_TIMESTAMP())")
        .bind(device).bind(sqlx::types::Json(json!({"prefix_lists":[{"name":"pfx-to-viva","entries":[]}],"route_maps":[]}))).execute(pool).await.unwrap();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='bgp_export_policy_set'")
            .fetch_one(pool)
            .await
            .unwrap();
    let result = preparation::validate_drafts(pool, &[ActionDraft {
        id: None, reroute_template_id: template_id, device_id: device,
        params: json!({"neighbor_ip":"23.45.23.197","policy_kind":"prefix_list","policy_name":"pfx-to-viva"}),
        enabled: true, auto_target: None,
    }], false).await;
    assert!(
        result.is_ok(),
        "structured export-policy definition must validate before typed preparation: {result:?}"
    );
    let (template, draft) = result.unwrap().remove(0);
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('readiness fixture',?,'unused')",
    )
    .bind(format!("readiness-{}@example.test", uuid::Uuid::new_v4()))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    let mut cfg = Config::default();
    cfg.safety.configuration_test_devices.push(LabDevice {
        device_id: device,
        host: "192.0.2.243".into(),
        port: 22,
        pinned_host_fingerprint: "SHA256:readiness-fixture".into(),
        action_rate_limit_count: 32,
        action_rate_limit_window_seconds: 600,
    });
    let state = api::AppState {
        pool: pool.clone(),
        config: cfg,
        cookie_key: Key::from(&[7; 64]),
    };
    let actor = Session {
        id: 1,
        user_id: user,
        totp_verified: true,
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "readiness-test".into(),
    };
    let action = BundleAction {
        device_id: device,
        template,
        params: draft.params,
        reason: "readiness".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: None,
        original_reroute_id: None,
    };
    let (status, axum::Json(preview)) = manual_mitigations::preview_actions_with_reader_mode(
        &state,
        &actor,
        "manual_mitigation",
        None,
        vec![action],
        json!({"kind":"manual","name":"Run once"}),
        "readiness".into(),
        json!({"actions":[],"verification_mode":"configuration_only"}),
        None,
        &Ema3Snapshot,
        VerificationMode::ConfigurationOnly,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{preview}");
    let preset = sqlx::query("INSERT INTO mitigation_presets(name,revision) VALUES(?,1)")
        .bind(format!("readiness-preset-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO mitigation_preset_actions(preset_id,reroute_template_id,device_id,params_json,enabled,position) VALUES(?,?,?,?,1,0)").bind(preset).bind(template_id).bind(device).bind(sqlx::types::Json(json!({"neighbor_ip":"23.45.23.197","policy_kind":"prefix_list","policy_name":"pfx-to-viva"}))).execute(pool).await.unwrap();
    let readiness = mitigation_presets::readiness(pool, preset)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(readiness["status"], "ready");
    assert_eq!(readiness.as_object().unwrap().len(), 4);
    sqlx::query(
        "UPDATE reroute_templates SET verification_json=JSON_OBJECT('method','wrong') WHERE id=?",
    )
    .bind(template_id)
    .execute(pool)
    .await
    .unwrap();
    let invalid_marker = preparation::validate_drafts(pool, &[ActionDraft {
        id: None, reroute_template_id: template_id, device_id: device,
        params: json!({"neighbor_ip":"23.45.23.197","policy_kind":"prefix_list","policy_name":"pfx-to-viva"}), enabled:true, auto_target:None,
    }], false).await;
    assert!(
        invalid_marker.is_err(),
        "an empty structured plan without prepared_state must remain rejected"
    );
    sqlx::query("UPDATE reroute_templates SET verification_json=JSON_OBJECT('method','prepared_state') WHERE id=?")
        .bind(template_id).execute(pool).await.unwrap();
    sqlx::query("DELETE FROM routing_policy_snapshots WHERE device_id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    let blocked = mitigation_presets::readiness(pool, preset)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(blocked["status"], "needs_setup");
    assert!(blocked["validation_error"]
        .as_str()
        .unwrap()
        .contains("missing or stale"));
    sqlx::query("DELETE FROM mitigation_preset_actions WHERE preset_id=?")
        .bind(preset)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM mitigation_presets WHERE id=?")
        .bind(preset)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM execution_plans WHERE user_id=?")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}
