mod common;

use rerouter_controller::reroute::device_plan::{
    self, DeviceStateSnapshot, PreparationReader, PrepareInput, PreparedSafetyEffect,
    VerificationMode,
};
use serde_json::json;

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
