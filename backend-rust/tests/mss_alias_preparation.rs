mod common;
use rerouter_controller::reroute::{
    device_plan::{self, DeviceStateSnapshot, PreparationReader, PrepareInput},
    templates,
};
use serde_json::json;

struct InterfaceRead;
impl PreparationReader for InterfaceRead {
    fn read_one<'a>(
        &'a self,
        _: u64,
        command: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            assert!(command.contains("Port-channel1"));
            Ok("interface Port-channel1\n mtu 9214\n no negotiation auto".into())
        })
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
async fn snmp_short_alias_canonicalizes_to_proven_cli_interface_identity() {
    let db = common::test_database().await;
    let pool = db.pool();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.240')")
        .bind(format!("mss-alias-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    sqlx::query("INSERT INTO device_interfaces(device_id,if_index,if_name,if_descr,last_seen_at) VALUES(?,1,'Po1','Port-channel1',UTC_TIMESTAMP())").bind(device).execute(pool).await.unwrap();
    let tid: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='iface_tcp_adjust_mss'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, tid).await.unwrap();
    let canonical = templates::canonicalize_inventory_params(
        pool,
        device,
        &template,
        &json!({"interface":"Po1","mss":1400}),
    )
    .await
    .unwrap();
    assert_eq!(canonical["interface"], "Port-channel1");
    let prepared = device_plan::prepare_actions_read_only_with_reader(
        pool,
        &[PrepareInput {
            device_id: device,
            template_id: tid,
            template_name: template.name.clone(),
            canonical_params: canonical,
        }],
        &InterfaceRead,
    )
    .await
    .unwrap()
    .remove(0);
    assert!(
        matches!(&prepared.before[0],DeviceStateSnapshot::InterfaceMss{interface,mss:None} if interface=="Port-channel1")
    );
    assert!(prepared
        .commands
        .contains(&"interface Port-channel1".into()));
    assert!(prepared
        .inverse
        .as_ref()
        .unwrap()
        .commands
        .contains(&"no ip tcp adjust-mss".into()));
    let invalid = templates::canonicalize_inventory_params(
        pool,
        device,
        &template,
        &json!({"interface":"Port-channel999","mss":1400}),
    )
    .await;
    assert!(invalid.is_err());
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}
