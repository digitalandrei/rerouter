mod common;
use rerouter_controller::reroute::device_plan::{
    self, DeviceStateSnapshot, PreparationReader, PrepareInput,
};
use serde_json::json;

struct Config(&'static str);
impl PreparationReader for Config {
    fn read_one<'a>(
        &'a self,
        _: u64,
        _: &'a str,
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move { Ok(self.0.into()) })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> rerouter_controller::ssh::BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move { Ok(vec![String::new(); commands.len()]) })
    }
}

async fn prepare(
    pool: &sqlx::MySqlPool,
    device: u64,
    name: &str,
    direction: &str,
    route_map: &str,
    config: &'static str,
) -> device_plan::PreparedDeviceAction {
    let template_id: u64 = sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name=?")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap();
    device_plan::prepare_actions_read_only_with_reader(pool,&[PrepareInput{device_id:device,template_id,template_name:name.into(),canonical_params:json!({"local_asn":"34501","neighbor_ip":"192.0.2.1","route_map":route_map,"direction":direction})}],&Config(config)).await.unwrap().remove(0)
}

#[tokio::test]
async fn fresh_route_map_set_unset_preserve_proven_af_and_global_scope() {
    let db = common::test_database().await;
    let pool = db.pool();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'192.0.2.241')")
        .bind(format!("route-map-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let af="router bgp 34501\n neighbor 192.0.2.1 remote-as 64500\n address-family ipv4\n neighbor 192.0.2.1 activate\n neighbor 192.0.2.1 route-map OLD out\n exit-address-family";
    let set = prepare(pool, device, "bgp_route_map_set", "out", "NEW", af).await;
    assert!(set.commands.contains(&"address-family ipv4".into()));
    assert!(set
        .inverse
        .as_ref()
        .unwrap()
        .commands
        .contains(&"neighbor 192.0.2.1 route-map OLD out".into()));
    let DeviceStateSnapshot::RouteMapAssignment {
        address_family,
        route_map,
        ..
    } = &set.before[0]
    else {
        panic!()
    };
    assert_eq!(address_family.as_deref(), Some("ipv4"));
    assert_eq!(route_map.as_deref(), Some("OLD"));
    let unset = prepare(pool, device, "bgp_route_map_unset", "out", "OLD", af).await;
    assert!(
        matches!(&unset.after[0],DeviceStateSnapshot::RouteMapAssignment{route_map:None,address_family:Some(scope),..} if scope=="ipv4")
    );
    assert!(unset
        .inverse
        .as_ref()
        .unwrap()
        .commands
        .contains(&"neighbor 192.0.2.1 route-map OLD out".into()));
    let global = "router bgp 34501\n neighbor 192.0.2.1 remote-as 64500";
    let inbound = prepare(pool, device, "bgp_route_map_set", "in", "NEW", global).await;
    assert!(!inbound
        .commands
        .iter()
        .any(|c| c.starts_with("address-family")));
    assert!(inbound
        .inverse
        .as_ref()
        .unwrap()
        .commands
        .contains(&"no neighbor 192.0.2.1 route-map NEW in".into()));
    assert!(
        matches!(&inbound.before[0],DeviceStateSnapshot::RouteMapAssignment{route_map:None,address_family:Some(scope),..} if scope=="default_ipv4")
    );
    sqlx::query("DELETE FROM devices WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
}
