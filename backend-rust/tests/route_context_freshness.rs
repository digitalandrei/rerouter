//! The `peer_out_prefix_list` inventory gate must measure the age of the value
//! it is gating.
//!
//! `device_bgp_peers.out_prefix_list` is written by SSH route-context discovery,
//! but the validator used to gate it on `last_polled_at` (written only by SNMP
//! polling) AND on `EXISTS(fresh device_route_maps row)`. Neither describes the
//! prefix-list reading, and the EXISTS is false FOREVER on a device that
//! legitimately has no route-maps — exactly the `neighbor <ip> prefix-list
//! <NAME> out` case — so a freshly discovered, valid value was refused forever.
//!
//! The gate is now `route_context_discovered_at` (stamped in the same
//! transaction as the value) against ROUTING_INVENTORY_MAX_AGE_HOURS. It still
//! fails closed: a stale or never-stamped route context is refused.
//!
//! DB integration test — runs only when REROUTER_TEST_DATABASE_URL points at a MariaDB the
//! test may migrate + write to; missing configuration fails the suite. Cleans up its rows.

use rerouter_controller::reroute::templates::{canonicalize_inventory_params, Template};
use serde_json::json;
use sqlx::MySqlPool;
mod common;

/// A template shaped like `bgp_advertise_add`, restricted to the parameters the
/// case under test needs. Only the `source` annotations matter here.
fn template(schema: serde_json::Value) -> Template {
    Template {
        id: 0,
        name: "bgp_advertise_add".into(),
        display_name: None,
        description: None,
        provider_type: "device_cli".into(),
        mode: "ios_ssh".into(),
        automatic_allowed: false,
        parameter_schema: schema,
        plan: json!({}),
        verification: json!({}),
        rollback_template_id: None,
        v6_sibling_template_id: None,
        enabled: true,
    }
}

fn prefix_list_only() -> Template {
    template(json!({
        "prefix_list_name": {
            "type": "string", "label": "Outbound prefix-list",
            "required": true, "source": "peer_out_prefix_list"
        }
    }))
}

fn peer_and_prefix_list() -> Template {
    template(json!({
        "neighbor_ip": {
            "type": "ip", "label": "Upstream neighbor",
            "required": true, "source": "bgp_peer"
        },
        "prefix_list_name": {
            "type": "string", "label": "Outbound prefix-list",
            "required": true, "source": "peer_out_prefix_list"
        }
    }))
}

/// Seed one device + one peer. `polled_hours_ago` / `discovered_hours_ago` are
/// NULL when `None` (never polled / never discovered).
async fn seed(
    pool: &MySqlPool,
    name: &str,
    polled_hours_ago: Option<i64>,
    discovered_hours_ago: Option<i64>,
) -> u64 {
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, ?)")
        .bind(name)
        .bind("203.0.113.7")
        .execute(pool)
        .await
        .expect("insert device")
        .last_insert_id();
    // The ages are computed here and bound as plain timestamps. Binding a NULL
    // into `INTERVAL ? HOUR` makes MariaDB 11.4 reject the prepared execute
    // (error 1210), and "never polled / never discovered" is exactly the case
    // these tests need.
    let ago = |hours: Option<i64>| hours.map(|h| chrono::Utc::now() - chrono::Duration::hours(h));
    sqlx::query(
        "INSERT INTO device_bgp_peers \
             (device_id, peer_remote_addr, out_prefix_list, last_polled_at, route_context_discovered_at) \
         VALUES (?, '198.51.100.7', 'pfx-to-viva', ?, ?)",
    )
    .bind(device_id)
    .bind(ago(polled_hours_ago))
    .bind(ago(discovered_hours_ago))
    .execute(pool)
    .await
    .expect("insert bgp peer");
    // No `device_route_maps` rows are seeded on purpose: this device has none,
    // which is the configuration the old EXISTS subquery refused forever.
    device_id
}

async fn cleanup(pool: &MySqlPool, device_id: u64) {
    let _ = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(pool)
        .await;
}

#[tokio::test]
async fn fresh_route_context_is_accepted_although_snmp_polling_is_stale() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    // Discovered an hour ago; SNMP has not polled this peer in ~69 days.
    let device_id = seed(&pool, "route-ctx-fresh", Some(1650), Some(1)).await;

    let out = canonicalize_inventory_params(
        &pool,
        device_id,
        &prefix_list_only(),
        &json!({ "prefix_list_name": "pfx-to-viva" }),
    )
    .await;

    cleanup(&pool, device_id).await;
    let canonical = out.expect("fresh route context must resolve the prefix-list");
    assert_eq!(canonical["prefix_list_name"], json!("pfx-to-viva"));
}

#[tokio::test]
async fn stale_route_context_is_refused_although_snmp_polling_is_fresh() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    // Peer is alive (polled minutes ago) but the routing read is ~8 days old.
    let device_id = seed(&pool, "route-ctx-stale", Some(0), Some(200)).await;

    let out = canonicalize_inventory_params(
        &pool,
        device_id,
        &prefix_list_only(),
        &json!({ "prefix_list_name": "pfx-to-viva" }),
    )
    .await;
    // And the peer<->prefix-list cross-check must refuse the pair too.
    let pair = canonicalize_inventory_params(
        &pool,
        device_id,
        &peer_and_prefix_list(),
        &json!({ "neighbor_ip": "198.51.100.7", "prefix_list_name": "pfx-to-viva" }),
    )
    .await;

    cleanup(&pool, device_id).await;
    assert!(out.is_err(), "a stale route context must fail closed");
    assert!(pair.is_err(), "the cross-check must fail closed too");
}

#[tokio::test]
async fn never_discovered_route_context_is_refused() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    // The field state before this fix: a value can only exist here by hand, and
    // a NULL marker means "never proven by a discovery run" => refuse.
    let device_id = seed(&pool, "route-ctx-null", Some(0), None).await;

    let out = canonicalize_inventory_params(
        &pool,
        device_id,
        &prefix_list_only(),
        &json!({ "prefix_list_name": "pfx-to-viva" }),
    )
    .await;

    cleanup(&pool, device_id).await;
    assert!(out.is_err(), "NULL route context must fail closed");
}

#[tokio::test]
async fn a_device_without_route_maps_still_resolves_its_peer_prefix_list() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    // The regression this fixes: peer + prefix-list both fresh, device has NO
    // route-maps at all (direct `neighbor <ip> prefix-list <NAME> out`), which
    // the old EXISTS(device_route_maps) subquery rejected permanently.
    let device_id = seed(&pool, "route-ctx-no-rm", Some(0), Some(0)).await;

    let out = canonicalize_inventory_params(
        &pool,
        device_id,
        &peer_and_prefix_list(),
        &json!({ "neighbor_ip": "198.51.100.7", "prefix_list_name": "pfx-to-viva" }),
    )
    .await;

    cleanup(&pool, device_id).await;
    let canonical = out.expect("peer + prefix-list must resolve without any route-map row");
    assert_eq!(canonical["neighbor_ip"], json!("198.51.100.7"));
    assert_eq!(canonical["prefix_list_name"], json!("pfx-to-viva"));
}
