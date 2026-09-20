//! Durable mutation ownership regressions. These tests use only the dedicated
//! REROUTER_TEST_DATABASE_URL schema supplied by CI/the operator and never contact a router.

use rerouter_controller::config::Config;
use rerouter_controller::reroute::executor::{
    ActionRequest, ActorContext, BundleMembership, ExecutionAuthorization, Rerouter,
};
use rerouter_controller::reroute::guard;
use rerouter_controller::reroute::rollback::{self, PersistedRollbackRequest};
use rerouter_controller::reroute::templates::Template;
use rerouter_controller::reroute::{bundle, device_plan};
use rerouter_controller::ssh::{
    BoxFuture, CommandResult, LockedDeviceSetPort, ResolvedApply, SessionResolver, SshExecutor,
    SshOutcome,
};
use serde_json::json;
use std::sync::{Arc, Mutex};

mod common;
use std::collections::HashMap;

#[derive(Clone)]
struct FakeLockedSsh {
    failed_device: u64,
    writes: Arc<Mutex<Vec<u64>>>,
    shutdown: Arc<Mutex<HashMap<u64, bool>>>,
    flap_after_verify: Option<u64>,
}

struct FakeLocks {
    devices: Vec<u64>,
    failed_device: u64,
    writes: Arc<Mutex<Vec<u64>>>,
    shutdown: Arc<Mutex<HashMap<u64, bool>>>,
    flap_after_verify: Option<u64>,
    verified_once: HashMap<u64, bool>,
}

impl LockedDeviceSetPort for FakeLocks {
    fn device_ids(&self) -> Vec<u64> {
        let mut devices = self.devices.clone();
        devices.sort_unstable();
        devices.dedup();
        devices
    }

    fn transport_identity(
        &self,
        device_id: u64,
    ) -> anyhow::Result<device_plan::DeviceTransportIdentity> {
        Ok(device_plan::DeviceTransportIdentity {
            host: format!("fake-{device_id}"),
            port: 22,
            pinned_host_fingerprint: format!("fake-fingerprint-{device_id}"),
        })
    }

    fn read<'a>(
        &'a mut self,
        _device_id: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            let mut states = self.shutdown.lock().unwrap();
            let mut shutdown = states.get(&_device_id).copied().unwrap_or(false);
            if shutdown
                && self.flap_after_verify == Some(_device_id)
                && self.verified_once.insert(_device_id, true).is_some()
            {
                states.insert(_device_id, false);
                shutdown = false;
            }
            Ok(CommandResult {
                command: command.into(),
                output: format!(
                    "interface {}\n{}",
                    command
                        .strip_prefix("show running-config interface ")
                        .unwrap_or("GigabitEthernet0/0"),
                    if shutdown {
                        " shutdown"
                    } else {
                        " no shutdown"
                    }
                ),
            })
        })
    }

    fn execute<'a>(
        &'a mut self,
        device_id: u64,
        commands: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            self.writes.lock().unwrap().push(device_id);
            self.shutdown.lock().unwrap().insert(device_id, true);
            if device_id == self.failed_device {
                anyhow::bail!("simulated disconnect after write intent");
            }
            Ok(SshOutcome {
                results: commands
                    .iter()
                    .map(|command| CommandResult {
                        command: command.clone(),
                        output: String::new(),
                    })
                    .collect(),
                fingerprint: "fake".into(),
                pinned_now: false,
            })
        })
    }

    fn unlock_all(self: Box<Self>) -> BoxFuture<'static, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl SshExecutor for FakeLockedSsh {
    async fn apply(&self, _device_id: u64, _commands: &[String]) -> anyhow::Result<SshOutcome> {
        anyhow::bail!("unprepared fake apply")
    }

    async fn verify_read(&self, _device_id: u64, _command: &str) -> anyhow::Result<String> {
        anyhow::bail!("unprepared fake verify")
    }

    async fn apply_resolved<'a>(
        &'a self,
        _device_id: u64,
        _read_command: &'a str,
        _resolve: SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        anyhow::bail!("unprepared fake resolver")
    }

    fn lock_devices<'a>(
        &'a self,
        device_ids: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        Box::pin(async move {
            Ok(Box::new(FakeLocks {
                devices: device_ids.to_vec(),
                failed_device: self.failed_device,
                writes: self.writes.clone(),
                shutdown: self.shutdown.clone(),
                flap_after_verify: self.flap_after_verify,
                verified_once: HashMap::new(),
            }) as Box<dyn LockedDeviceSetPort>)
        })
    }
}

#[tokio::test]
async fn verified_noop_has_no_inverse_and_creates_no_rollback_attempt() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let suffix = std::process::id();
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(format!("noop-ownership-{suffix}"))
        .execute(&pool)
        .await
        .expect("insert device")
        .last_insert_id();
    let template_id: u64 = sqlx::query_scalar(
        "SELECT id FROM reroute_templates WHERE rollback_template_id IS NOT NULL LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("load reversible template");
    let original_id = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, reroute_template_id, trigger_type, state, mutation_effect, \
             started_at, finished_at, success) \
         VALUES (?, ?, 'manual', 'succeeded', 'noop', UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)",
    )
    .bind(device_id)
    .bind(template_id)
    .execute(&pool)
    .await
    .expect("insert no-op original")
    .last_insert_id();

    let before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ?")
            .bind(original_id)
            .fetch_one(&pool)
            .await
            .expect("count rollback attempts");
    let result = rollback::rollback_persisted(
        &pool,
        &Config::default(),
        PersistedRollbackRequest {
            original_reroute_id: Some(original_id),
            rule_event_id: None,
            user_id: None,
            actor_context: None,
            reason: "test no-op inverse".into(),
            defer_cooldown: true,
            dry_run: false,
            authorization: None,
        },
    )
    .await
    .expect("classify no-op rollback")
    .expect("no-op outcome");
    assert!(!result.executed);
    assert_eq!(result.state.as_deref(), Some("succeeded"));
    assert_eq!(result.mutation_effect.as_deref(), Some("noop"));
    let after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id = ?")
            .bind(original_id)
            .fetch_one(&pool)
            .await
            .expect("count rollback attempts after no-op");
    assert_eq!(
        after, before,
        "a no-op must not create or execute an inverse"
    );

    sqlx::query("DELETE FROM reroutes WHERE id = ?")
        .bind(original_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn dropped_policy_fence_closes_its_session_and_releases_the_advisory_lock() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let cfg = Config::default();
    let runtime = cfg.advisory_runtime(&pool).await.unwrap();
    rerouter_controller::db::advisory::foreground_scope(runtime, async {
        let fence = guard::policy_fence(&pool)
            .await
            .expect("acquire first policy fence");
        let mut observer = pool.acquire().await.expect("acquire lock observer");
        let lock_name = rerouter_controller::db::scoped_advisory_lock_name(
            &mut observer,
            "10:execution:policy",
        )
        .await
        .unwrap();
        let owner: Option<u64> = sqlx::query_scalar("SELECT CAST(IS_USED_LOCK(?) AS UNSIGNED)")
            .bind(lock_name)
            .fetch_one(&mut *observer)
            .await
            .expect("inspect policy lock");
        assert!(owner.is_some(), "policy advisory lock must be held");
        drop(fence);
        let second = guard::policy_fence(&pool)
            .await
            .expect("poisoned idle session must be replaced");
        second.release().await.expect("release second policy fence");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn advisory_lock_names_are_stable_bounded_and_schema_isolated() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let (a, same_a, b): (String, String, String) = sqlx::query_as(
        "SELECT \
          CONCAT('rrt:', LEFT(SHA2(CONCAT(?, ':', ?), 256), 60)), \
          CONCAT('rrt:', LEFT(SHA2(CONCAT(?, ':', ?), 256), 60)), \
          CONCAT('rrt:', LEFT(SHA2(CONCAT(?, ':', ?), 256), 60))",
    )
    .bind("rerouter_test_alpha")
    .bind("reroute:rate-global")
    .bind("rerouter_test_alpha")
    .bind("reroute:rate-global")
    .bind("rerouter_test_beta")
    .bind("reroute:rate-global")
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(a, same_a);
    assert_ne!(
        a, b,
        "two schemas must never share a server-global lock name"
    );
    assert_eq!(a.len(), 64);
    assert_eq!(b.len(), 64);
}

#[tokio::test]
async fn destructive_step_is_blocked_when_replacement_flaps_after_its_own_verification() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let suffix = std::process::id();
    let rule_id = sqlx::query(
        "INSERT INTO rules (name, metric, operator, threshold_value, duration_seconds, \
                            severity, automatic_reroute_enabled) \
         VALUES (?, 'tx_bps', '>', 1, 0, 'high', 1)",
    )
    .bind(format!("freeze-rule-{suffix}"))
    .execute(&pool)
    .await
    .expect("insert rule")
    .last_insert_id();
    sqlx::query("INSERT INTO rule_states (rule_id, current_state) VALUES (?, 'firing')")
        .bind(rule_id)
        .execute(&pool)
        .await
        .unwrap();
    let actions_revision: u64 =
        sqlx::query_scalar("SELECT actions_revision FROM rules WHERE id = ?")
            .bind(rule_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let insert_device = |name: String| {
        let pool = pool.clone();
        async move {
            sqlx::query(
                "INSERT INTO devices \
                    (name, hostname, ssh_status, last_ssh_ok_at, ssh_reachable_since) \
                 VALUES (?, '127.0.0.1', 'reachable', UTC_TIMESTAMP(), \
                         DATE_SUB(UTC_TIMESTAMP(), INTERVAL 5 MINUTE))",
            )
            .bind(name)
            .execute(&pool)
            .await
            .expect("insert device")
            .last_insert_id()
        }
    };
    let device_a = insert_device(format!("freeze-a-{suffix}")).await;
    let device_c = insert_device(format!("freeze-c-{suffix}")).await;
    rerouter_controller::reroute::reachability::stamp_ssh_ok(&pool, device_a)
        .await
        .unwrap();
    rerouter_controller::reroute::reachability::stamp_ssh_ok(&pool, device_c)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO system_settings (`key`, `value`) VALUES \
            ('operating_mode', 'enforce'), ('automatic_actions_enabled', 'true') \
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
    )
    .execute(&pool)
    .await
    .expect("arm isolated test schema");

    let additive_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name = 'bgp_advertise_add'")
            .fetch_one(&pool)
            .await
            .expect("load additive template id");
    let destructive_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name = 'bgp_advertise_remove'")
            .fetch_one(&pool)
            .await
            .expect("load destructive template id");
    let additive_template = rerouter_controller::reroute::templates::load(&pool, additive_id)
        .await
        .unwrap();
    let destructive_template = rerouter_controller::reroute::templates::load(&pool, destructive_id)
        .await
        .unwrap();
    let prepared =
        |device_id: u64, template_id: u64, template_name: &str| device_plan::PreparedDeviceAction {
            schema_version: device_plan::PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
            device_id,
            template_id,
            template_name: template_name.into(),
            canonical_params: json!({}),
            verification_mode: device_plan::VerificationMode::Routing,
            commands: vec![
                "configure terminal".into(),
                "ip route 192.0.2.1 255.255.255.255 Null0".into(),
                "end".into(),
            ],
            before: vec![device_plan::DeviceStateSnapshot::InterfaceAdmin {
                interface: "Loopback0".into(),
                shutdown: false,
            }],
            after: vec![device_plan::DeviceStateSnapshot::InterfaceAdmin {
                interface: "Loopback0".into(),
                shutdown: true,
            }],
            verify: vec![device_plan::DeviceStateSnapshot::InterfaceAdmin {
                interface: "Loopback0".into(),
                shutdown: true,
            }],
            effect: device_plan::PreparedEffect::Change,
            inverse: None,
            prepared_at: chrono::Utc::now(),
        };
    let actions = vec![
        bundle::BundleAction {
            device_id: device_a,
            template: additive_template,
            params: json!({}),
            reason: "install replacement path".into(),
            position: 0,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(device_a, additive_id, "bgp_advertise_add")),
            original_reroute_id: None,
        },
        bundle::BundleAction {
            device_id: device_c,
            template: destructive_template,
            params: json!({}),
            reason: "withdraw old path".into(),
            position: 1,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(device_c, destructive_id, "bgp_advertise_remove")),
            original_reroute_id: None,
        },
    ];
    let bundle_id = bundle::create(
        &pool,
        Some(rule_id),
        Some(
            sqlx::query("INSERT INTO rule_events (rule_id, event) VALUES (?, 'fired')")
                .bind(rule_id)
                .execute(&pool)
                .await
                .unwrap()
                .last_insert_id(),
        ),
        "automatic",
        None,
        "cross-device uncertainty test",
        bundle::FailurePolicy::AbortAndCompensate,
        2,
    )
    .await
    .unwrap();
    let identities = [device_a, device_c]
        .into_iter()
        .map(|device_id| {
            (
                device_id,
                device_plan::DeviceTransportIdentity {
                    host: format!("fake-{device_id}"),
                    port: 22,
                    pinned_host_fingerprint: format!("fake-fingerprint-{device_id}"),
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    sqlx::query("UPDATE reroute_bundles SET source_json = ? WHERE id = ?")
        .bind(sqlx::types::Json(
            json!({"transport_identities": identities, "actions_revision": actions_revision}),
        ))
        .bind(bundle_id)
        .execute(&pool)
        .await
        .unwrap();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let shutdown = Arc::new(Mutex::new(HashMap::new()));
    let fake = FakeLockedSsh {
        failed_device: u64::MAX,
        writes: writes.clone(),
        shutdown,
        flap_after_verify: Some(device_a),
    };
    let mut cfg = Config::default();
    cfg.safety.operating_mode = rerouter_controller::config::OperatingMode::Enforce;
    cfg.safety.automatic_actions_enabled = true;
    cfg.safety.global_action_rate_limit_count = 0;
    let rule_event_id: u64 =
        sqlx::query_scalar("SELECT rule_event_id FROM reroute_bundles WHERE id = ?")
            .bind(bundle_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    let final_proof_action = actions[0].clone();
    let outcome = bundle::run_with_ssh(
        &pool,
        &cfg,
        bundle::BundleRun::automatic(
            bundle_id,
            bundle::FailurePolicy::AbortAndCompensate,
            rule_id,
            rule_event_id,
        ),
        actions,
        &fake,
    )
    .await;
    assert_eq!(
        outcome.state, "compensation_blocked",
        "{:?}",
        outcome.failure_reason
    );
    assert_eq!(
        *writes.lock().unwrap(),
        vec![device_a],
        "withdrawal on C must not run after replacement state on A disappears"
    );
    let phases: Vec<String> = sqlx::query_scalar(
        "SELECT phase FROM device_change_windows WHERE bundle_id = ? ORDER BY device_id",
    )
    .bind(bundle_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(phases, vec!["uncertain", "uncertain"]);

    sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query(
        "DELETE FROM locks WHERE reroute_id IN (SELECT id FROM reroutes WHERE bundle_id = ?)",
    )
    .bind(bundle_id)
    .execute(&pool)
    .await
    .ok();
    sqlx::query("DELETE FROM reroutes WHERE bundle_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query(
        "DELETE FROM cooldowns WHERE (scope = 'device' AND scope_ref IN (?, ?)) \
          OR (scope = 'rule' AND scope_ref = ?)",
    )
    .bind(device_a.to_string())
    .bind(device_c.to_string())
    .bind(rule_id.to_string())
    .execute(&pool)
    .await
    .ok();

    // This fixture intentionally discards the first scenario's quarantine;
    // remove its explicit membership as well before reusing the same devices.
    sqlx::query("DELETE FROM device_change_window_sources WHERE source_bundle_id=?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .unwrap();
    // A one-action additive bundle has no following destructive boundary, so
    // the final all-set proof is the only place a post-verification flap can be
    // caught before success is reported.
    let final_bundle = bundle::create(
        &pool,
        Some(rule_id),
        Some(rule_event_id),
        "automatic",
        None,
        "final projected-state proof test",
        bundle::FailurePolicy::AbortAndCompensate,
        1,
    )
    .await
    .unwrap();
    let final_identity = std::collections::BTreeMap::from([(
        device_a,
        device_plan::DeviceTransportIdentity {
            host: format!("fake-{device_a}"),
            port: 22,
            pinned_host_fingerprint: format!("fake-fingerprint-{device_a}"),
        },
    )]);
    sqlx::query("UPDATE reroute_bundles SET source_json = ? WHERE id = ?")
        .bind(sqlx::types::Json(json!({
            "transport_identities": final_identity,
            "actions_revision": actions_revision
        })))
        .bind(final_bundle)
        .execute(&pool)
        .await
        .unwrap();
    let final_writes = Arc::new(Mutex::new(Vec::new()));
    let final_fake = FakeLockedSsh {
        failed_device: u64::MAX,
        writes: final_writes.clone(),
        shutdown: Arc::new(Mutex::new(HashMap::new())),
        flap_after_verify: Some(device_a),
    };
    let final_outcome = bundle::run_with_ssh(
        &pool,
        &cfg,
        bundle::BundleRun::automatic(
            final_bundle,
            bundle::FailurePolicy::AbortAndCompensate,
            rule_id,
            rule_event_id,
        ),
        vec![final_proof_action],
        &final_fake,
    )
    .await;
    assert_eq!(
        final_outcome.state, "compensation_blocked",
        "{:?}",
        final_outcome.failure_reason
    );
    assert_eq!(*final_writes.lock().unwrap(), vec![device_a]);
    let uncertain: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM reroutes WHERE bundle_id = ? \
         AND state = 'uncertain' AND mutation_effect = 'unknown'",
    )
    .bind(final_bundle)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        uncertain, 1,
        "failed final proof must quarantine owned change"
    );
    sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
        .bind(final_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query(
        "DELETE FROM locks WHERE reroute_id IN (SELECT id FROM reroutes WHERE bundle_id = ?)",
    )
    .bind(final_bundle)
    .execute(&pool)
    .await
    .ok();
    sqlx::query("DELETE FROM reroutes WHERE bundle_id = ?")
        .bind(final_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(final_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM rules WHERE id = ?")
        .bind(rule_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id IN (?, ?)")
        .bind(device_a)
        .bind(device_c)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("UPDATE system_settings SET `value` = 'observe' WHERE `key` = 'operating_mode'")
        .execute(&pool)
        .await
        .ok();
    sqlx::query(
        "UPDATE system_settings SET `value` = 'false' WHERE `key` = 'automatic_actions_enabled'",
    )
    .execute(&pool)
    .await
    .ok();
}

#[tokio::test]
async fn prepared_inverse_uses_persisted_effective_params_not_mutable_catalog_input() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(format!("inverse-params-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name = 'bgp_route_map_set'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let template = rerouter_controller::reroute::templates::load(&pool, template_id)
        .await
        .unwrap();
    let effective = json!({
        "local_asn": "65000",
        "neighbor_ip": "192.0.2.1",
        "direction": "out",
        "route_map": "RM_MIT",
        "prior_route_map": "RM_OLD",
        "sequence": "117"
    });
    let expected_current = device_plan::DeviceStateSnapshot::RouteMapAssignment {
        local_asn: 65_000,
        neighbor: "192.0.2.1".into(),
        direction: "out".into(),
        address_family: None,
        route_map: Some("RM_MIT".into()),
    };
    let restore = device_plan::DeviceStateSnapshot::RouteMapAssignment {
        local_asn: 65_000,
        neighbor: "192.0.2.1".into(),
        direction: "out".into(),
        address_family: None,
        route_map: Some("RM_OLD".into()),
    };
    let inverse = device_plan::PreparedInverse {
        verification_mode: device_plan::VerificationMode::Routing,
        expected_current: vec![expected_current],
        restore: vec![restore.clone()],
        commands: vec![
            "configure terminal".into(),
            "router bgp 65000".into(),
            "neighbor 192.0.2.1 route-map RM_OLD out".into(),
            "end".into(),
        ],
        verify: vec![restore],
    };
    let original_id = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, reroute_template_id, trigger_type, state, mutation_effect, parameters_json, \
             template_snapshot_json, rollback_snapshot_json, started_at, finished_at, success) \
         VALUES (?, ?, 'manual', 'succeeded', 'changed', ?, ?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), 1)",
    )
    .bind(device_id)
    .bind(template_id)
    .bind(sqlx::types::Json(&effective))
    .bind(sqlx::types::Json(serde_json::to_value(&template).unwrap()))
    .bind(sqlx::types::Json(serde_json::to_value(&inverse).unwrap()))
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();

    let actions = rerouter_controller::reroute::preparation::prepare_rollbacks(
        &pool,
        &[original_id],
        "restore persisted route-map",
        false,
    )
    .await
    .unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].params, effective);
    let prepared = actions[0].prepared.as_ref().unwrap();
    assert_eq!(prepared.canonical_params, effective);
    assert!(prepared
        .commands
        .iter()
        .any(|command| command.contains("RM_OLD")));
    assert!(prepared
        .commands
        .iter()
        .all(|command| !command.contains("RM_MIT out")));

    sqlx::query("DELETE FROM reroutes WHERE id = ?")
        .bind(original_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn consumed_manual_plan_is_bound_to_its_actor_before_any_ssh_write() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    sqlx::query(
        "INSERT INTO system_settings (`key`, `value`) VALUES ('operating_mode', 'enforce') \
         ON DUPLICATE KEY UPDATE `value` = VALUES(`value`)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let user = |label: &str| {
        let pool = pool.clone();
        let label = label.to_string();
        async move {
            sqlx::query("INSERT INTO users (name, email, password) VALUES (?, ?, 'x')")
                .bind(&label)
                .bind(format!("{label}-{}@example.test", uuid::Uuid::new_v4()))
                .execute(&pool)
                .await
                .unwrap()
                .last_insert_id()
        }
    };
    let authorized_user = user("authorized").await;
    let other_user = user("other").await;
    let device_id = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(format!("actor-bound-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let template_id: u64 = sqlx::query_scalar("SELECT id FROM reroute_templates LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    let template = Template {
        id: template_id,
        name: "actor_bound_test".into(),
        display_name: None,
        description: None,
        provider_type: "device_cli".into(),
        mode: "ios_ssh".into(),
        automatic_allowed: false,
        parameter_schema: json!({}),
        plan: json!({"transport":"ios_ssh","config_mode":true,"apply":["shutdown"]}),
        verification: json!({"command":"show running-config interface Loopback0","expect":"shutdown"}),
        rollback_template_id: None,
        v6_sibling_template_id: None,
        enabled: true,
    };
    let before = device_plan::DeviceStateSnapshot::InterfaceAdmin {
        interface: "Loopback0".into(),
        shutdown: false,
    };
    let after = device_plan::DeviceStateSnapshot::InterfaceAdmin {
        interface: "Loopback0".into(),
        shutdown: true,
    };
    let prepared = device_plan::PreparedDeviceAction {
        schema_version: device_plan::PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
        device_id,
        template_id,
        template_name: template.name.clone(),
        canonical_params: json!({}),
        verification_mode: device_plan::VerificationMode::Routing,
        commands: vec![
            "configure terminal".into(),
            "interface Loopback0".into(),
            "shutdown".into(),
            "end".into(),
        ],
        before: vec![before],
        after: vec![after.clone()],
        verify: vec![after],
        effect: device_plan::PreparedEffect::Change,
        inverse: None,
        prepared_at: chrono::Utc::now(),
    };
    let action = bundle::BundleAction {
        device_id,
        template,
        params: json!({}),
        reason: "actor authority test".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: Some(prepared.clone()),
        original_reroute_id: None,
    };
    let source = json!({"kind":"manual","transport_identities":{}});
    let bundle_id = bundle::create(
        &pool,
        None,
        None,
        "manual",
        Some(authorized_user),
        "actor authority test",
        bundle::FailurePolicy::AbortAndCompensate,
        1,
    )
    .await
    .unwrap();
    sqlx::query("UPDATE reroute_bundles SET source_json = ? WHERE id = ?")
        .bind(sqlx::types::Json(&source))
        .bind(bundle_id)
        .execute(&pool)
        .await
        .unwrap();
    bundle::persist_actions(&pool, bundle_id, std::slice::from_ref(&action))
        .await
        .unwrap();
    let snapshot = json!({
        "actions": [action.clone()],
        "device_actions": [prepared],
        "source": source,
        "reason": "actor authority test",
        "request": {}
    });
    let plan_id = sqlx::query(
        "INSERT INTO execution_plans \
            (user_id, scope, reason, snapshot_json, plan_hash, token_hash, expires_at, consumed_at, bundle_id) \
         VALUES (?, 'manual_mitigation', 'actor authority test', ?, REPEAT('a',64), \
                 REPEAT('b',64), DATE_ADD(UTC_TIMESTAMP(), INTERVAL 5 MINUTE), UTC_TIMESTAMP(), ?)",
    )
    .bind(authorized_user)
    .bind(sqlx::types::Json(snapshot))
    .bind(bundle_id)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    let owner = format!("plan:{plan_id}");
    rerouter_controller::reroute::locks::acquire_bundle_change_windows(
        &pool,
        bundle_id,
        &owner,
        &[device_id],
    )
    .await
    .unwrap();
    let writes = Arc::new(Mutex::new(Vec::new()));
    let fake = FakeLockedSsh {
        failed_device: u64::MAX,
        writes: writes.clone(),
        shutdown: Arc::new(Mutex::new(HashMap::new())),
        flap_after_verify: None,
    };
    let authorized_action = action.clone();
    let request = ActionRequest {
        device_id,
        template: action.template,
        params: action.params,
        trigger_type: "manual",
        rule_id: None,
        rule_event_id: None,
        rollback_of_reroute_id: None,
        user_id: Some(other_user),
        actor_context: Some(ActorContext {
            ip_address: "127.0.0.1".into(),
            user_agent: "authority test".into(),
        }),
        reason: Some(action.reason),
        defer_cooldown: true,
        bundle: Some(BundleMembership {
            bundle_id,
            position: 0,
        }),
        authorization: Some(ExecutionAuthorization::manual(
            plan_id,
            Some(bundle_id),
            owner.clone(),
            Some(
                sqlx::query_scalar("SELECT id FROM reroute_bundle_actions WHERE bundle_id = ?")
                    .bind(bundle_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap(),
            ),
        )),
    };
    let mut cfg = Config::default();
    cfg.safety.operating_mode = rerouter_controller::config::OperatingMode::Enforce;
    let outcome = Rerouter::with_ssh(&pool, &cfg, fake)
        .execute(request, false)
        .await;
    assert!(!outcome.executed);
    assert!(outcome
        .blocked_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("actor-mismatched")));
    assert!(writes.lock().unwrap().is_empty());

    let prior_enabled: bool =
        sqlx::query_scalar("SELECT enabled FROM reroute_templates WHERE id = ?")
            .bind(template_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE reroute_templates SET enabled = 0 WHERE id = ?")
        .bind(template_id)
        .execute(&pool)
        .await
        .unwrap();
    let no_writes = Arc::new(Mutex::new(Vec::new()));
    let disabled_outcome = Rerouter::with_ssh(
        &pool,
        &cfg,
        FakeLockedSsh {
            failed_device: u64::MAX,
            writes: no_writes.clone(),
            shutdown: Arc::new(Mutex::new(HashMap::new())),
            flap_after_verify: None,
        },
    )
    .execute(
        ActionRequest {
            device_id,
            template: authorized_action.template,
            params: authorized_action.params,
            trigger_type: "manual",
            rule_id: None,
            rule_event_id: None,
            rollback_of_reroute_id: None,
            user_id: Some(authorized_user),
            actor_context: Some(ActorContext {
                ip_address: "127.0.0.1".into(),
                user_agent: "template policy test".into(),
            }),
            reason: Some(authorized_action.reason),
            defer_cooldown: true,
            bundle: Some(BundleMembership {
                bundle_id,
                position: 0,
            }),
            authorization: Some(ExecutionAuthorization::manual(
                plan_id,
                Some(bundle_id),
                owner.clone(),
                Some(
                    sqlx::query_scalar("SELECT id FROM reroute_bundle_actions WHERE bundle_id = ?")
                        .bind(bundle_id)
                        .fetch_one(&pool)
                        .await
                        .unwrap(),
                ),
            )),
        },
        false,
    )
    .await;
    assert!(!disabled_outcome.executed);
    assert!(disabled_outcome
        .blocked_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("disabled after preparation")));
    assert!(no_writes.lock().unwrap().is_empty());
    sqlx::query("UPDATE reroute_templates SET enabled = ? WHERE id = ?")
        .bind(prior_enabled)
        .bind(template_id)
        .execute(&pool)
        .await
        .unwrap();

    sqlx::query("DELETE FROM device_change_windows WHERE bundle_id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM execution_plans WHERE id = ?")
        .bind(plan_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(device_id)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM users WHERE id IN (?, ?)")
        .bind(authorized_user)
        .bind(other_user)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("UPDATE system_settings SET `value` = 'observe' WHERE `key` = 'operating_mode'")
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn successful_recovery_closes_original_ownership_and_releases_all_source_windows() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device_a = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(format!("ownership-a-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let device_c = sqlx::query("INSERT INTO devices (name, hostname) VALUES (?, '127.0.0.1')")
        .bind(format!("ownership-c-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let source_bundle = sqlx::query(
        "INSERT INTO reroute_bundles (trigger_type, state, total_actions) \
         VALUES ('manual', 'compensation_blocked', 2)",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    let original = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, bundle_id, bundle_position, trigger_type, state, mutation_effect, started_at, finished_at) \
         VALUES (?, ?, 0, 'manual', 'succeeded', 'changed', UTC_TIMESTAMP(), UTC_TIMESTAMP())",
    )
    .bind(device_a)
    .bind(source_bundle)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    sqlx::query(
        "INSERT INTO reroute_bundle_actions \
            (bundle_id,position,device_id,template_snapshot_json,canonical_params_json, \
             rendered_plan_json,prepared_action_json,state,mutation_effect,reroute_id) VALUES \
            (?,0,?,'{}','{}','{}','{}','succeeded','changed',?), \
            (?,1,?,'{}','{}','{}','{}','queued','pending',NULL)",
    )
    .bind(source_bundle)
    .bind(device_a)
    .bind(original)
    .bind(source_bundle)
    .bind(device_c)
    .execute(&pool)
    .await
    .unwrap();
    for device in [device_a, device_c] {
        sqlx::query(
            "INSERT INTO device_change_windows (device_id, bundle_id, owner_token, phase) \
             VALUES (?, ?, 'source-owner', 'uncertain')",
        )
        .bind(device)
        .bind(source_bundle)
        .execute(&pool)
        .await
        .unwrap();
    }
    let recovery_bundle = sqlx::query(
        "INSERT INTO reroute_bundles (trigger_type, state, total_actions, source_json) \
         VALUES ('manual', 'running', 1, '{\"kind\":\"recovery\"}')",
    )
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    let mut claim_tx = pool.begin().await.unwrap();
    rerouter_controller::reroute::recovery::claim_sources_for_child_on(
        &mut claim_tx,
        recovery_bundle,
        &[source_bundle],
        &[original],
        "recovery-owner",
        true,
    )
    .await
    .unwrap();
    claim_tx.commit().await.unwrap();
    sqlx::query(
        "INSERT INTO reroute_bundle_actions \
            (bundle_id, position, original_reroute_id, device_id, template_snapshot_json, \
             canonical_params_json, rendered_plan_json, prepared_action_json) \
         VALUES (?, 0, ?, ?, '{}', '{}', '{}', '{}')",
    )
    .bind(recovery_bundle)
    .bind(original)
    .bind(device_a)
    .execute(&pool)
    .await
    .unwrap();
    rerouter_controller::reroute::locks::claim_change_windows_for_recovery(
        &pool,
        recovery_bundle,
        "recovery-owner",
        &[original],
    )
    .await
    .unwrap();
    let inverse = sqlx::query(
        "INSERT INTO reroutes \
            (device_id, bundle_id, rollback_of_reroute_id, trigger_type, state, mutation_effect, \
             started_at, finished_at) \
         VALUES (?, ?, ?, 'rollback', 'succeeded', 'changed', UTC_TIMESTAMP(), UTC_TIMESTAMP())",
    )
    .bind(device_a)
    .bind(recovery_bundle)
    .bind(original)
    .execute(&pool)
    .await
    .unwrap()
    .last_insert_id();
    assert!(bundle::outstanding_owned_originals(&pool, recovery_bundle)
        .await
        .unwrap()
        .is_empty());
    bundle::settle_source_activations(&pool, recovery_bundle)
        .await
        .unwrap();
    rerouter_controller::reroute::locks::release_bundle_change_windows(
        &pool,
        recovery_bundle,
        "recovery-owner",
    )
    .await
    .unwrap();
    let source_state: String = sqlx::query_scalar("SELECT state FROM reroute_bundles WHERE id = ?")
        .bind(source_bundle)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(source_state, "compensated");
    let windows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_change_windows WHERE device_id IN (?, ?)")
            .bind(device_a)
            .bind(device_c)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        windows, 0,
        "untouched device C window must also be released"
    );
    let inverse_of_inverse = rerouter_controller::reroute::preparation::prepare_rollbacks(
        &pool,
        &[inverse],
        "must refuse inverse-of-inverse",
        false,
    )
    .await;
    assert!(inverse_of_inverse.is_err());

    sqlx::query("DELETE FROM recovery_attempt_sources WHERE recovery_bundle_id=?")
        .bind(recovery_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(recovery_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroutes WHERE id IN (?, ?)")
        .bind(inverse)
        .bind(original)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM reroute_bundles WHERE id = ?")
        .bind(source_bundle)
        .execute(&pool)
        .await
        .ok();
    sqlx::query("DELETE FROM devices WHERE id IN (?, ?)")
        .bind(device_a)
        .bind(device_c)
        .execute(&pool)
        .await
        .ok();
}

#[tokio::test]
async fn multi_source_claim_records_shared_device_membership_and_never_repeats_success() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'127.0.0.1')")
        .bind(format!("shared-recovery-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let mut sources = Vec::new();
    let mut originals = Vec::new();
    for position in 0..2_u32 {
        let source=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,remaining_mutations,lifecycle_state) VALUES('automatic','succeeded',1,1,'active')")
            .execute(&pool).await.unwrap().last_insert_id();
        let original=sqlx::query("INSERT INTO reroutes(device_id,bundle_id,bundle_position,trigger_type,state,mutation_effect,started_at,finished_at) VALUES(?,?,?,'automatic','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
            .bind(device).bind(source).bind(position).execute(&pool).await.unwrap().last_insert_id();
        sources.push(source);
        originals.push(original);
    }
    originals.sort_unstable_by(|a, b| b.cmp(a));
    sqlx::query("INSERT INTO device_change_window_sources(device_id,source_bundle_id) VALUES(?,?)")
        .bind(device)
        .bind(sources[0])
        .execute(&pool)
        .await
        .unwrap();
    let child=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions) VALUES('automatic','planned',2)")
        .execute(&pool).await.unwrap().last_insert_id();
    let mut tx = pool.begin().await.unwrap();
    let ownership = rerouter_controller::reroute::recovery::claim_sources_for_child_on(
        &mut tx,
        child,
        &sources,
        &originals,
        "multi-source-claim",
        false,
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(ownership.source_bundle_ids, sources);
    let mappings:i64=sqlx::query_scalar("SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=? AND settlement='active'")
        .bind(child).fetch_one(&pool).await.unwrap();
    let memberships: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_change_window_sources WHERE device_id=?")
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap();
    let attempt_memberships: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_device_memberships \
         WHERE recovery_bundle_id=? AND created_by_attempt=1",
    )
    .bind(child)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(mappings, 2);
    assert_eq!(
        memberships, 2,
        "one device must retain both source quarantines"
    );
    assert_eq!(
        attempt_memberships, 1,
        "the recovery records only the membership absent before its claim"
    );

    let restored = originals[0];
    sqlx::query("INSERT INTO reroutes(device_id,bundle_id,rollback_of_reroute_id,trigger_type,state,mutation_effect,started_at,finished_at) VALUES(?,?,?,'rollback','succeeded','noop',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).bind(child).bind(restored).execute(&pool).await.unwrap();
    let remaining = rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &sources)
        .await
        .unwrap();
    assert!(
        !remaining.original_reroute_ids.contains(&restored),
        "a successful inverse must never be selected again"
    );
    assert_eq!(remaining.original_reroute_ids.len(), 1);

    for (position, original) in originals.iter().enumerate() {
        sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,original_reroute_id,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,prepared_action_json,state,mutation_effect) VALUES(?,?,?,?, '{}','{}','{}','{}',?,?)")
            .bind(child).bind(position as u32).bind(original).bind(device)
            .bind(if *original == restored { "succeeded" } else { "failed" })
            .bind("noop")
            .execute(&pool).await.unwrap();
    }
    sqlx::query("UPDATE reroute_bundles SET state='failed' WHERE id=?")
        .bind(child)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase) VALUES(?,?,?,'applying')")
        .bind(device).bind(child).bind("multi-source-claim").execute(&pool).await.unwrap();
    rerouter_controller::reroute::recovery::finalize_recovery_child(
        &pool,
        child,
        "failed",
        Some("one source restored; one source was not written"),
        "multi-source-claim",
    )
    .await
    .unwrap();
    let settlements: Vec<(u64, String)> = sqlx::query_as(
        "SELECT source_bundle_id,settlement FROM recovery_attempt_sources WHERE recovery_bundle_id=? ORDER BY source_bundle_id",
    )
    .bind(child).fetch_all(&pool).await.unwrap();
    let restored_source: u64 = sqlx::query_scalar("SELECT bundle_id FROM reroutes WHERE id=?")
        .bind(restored)
        .fetch_one(&pool)
        .await
        .unwrap();
    for (source, settlement) in settlements {
        assert_eq!(
            settlement,
            if source == restored_source {
                "restored"
            } else {
                "known_no_write"
            },
            "each source is settled from its own immutable inverse evidence"
        );
    }
    let retained_memberships: Vec<u64> = sqlx::query_scalar(
        "SELECT source_bundle_id FROM device_change_window_sources WHERE device_id=?",
    )
    .bind(device)
    .fetch_all(&pool)
    .await
    .unwrap();
    let known_no_write_source = *sources.iter().find(|id| **id != restored_source).unwrap();
    assert_eq!(
        retained_memberships,
        vec![known_no_write_source],
        "the restored source releases normally while the proven-no-write source retains ownership it held before this attempt"
    );
}

#[tokio::test]
async fn reconciled_inverse_reopens_blocked_mapping_and_settles_source() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'127.0.0.1')")
        .bind(format!("reconciled-recovery-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,remaining_mutations,lifecycle_state,recovery_claim_token) VALUES('manual','compensation_blocked',1,1,'recovery_blocked','reconcile-token')")
        .execute(&pool).await.unwrap().last_insert_id();
    let original = sqlx::query("INSERT INTO reroutes(device_id,bundle_id,trigger_type,state,mutation_effect,started_at,finished_at) VALUES(?,?,'manual','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).bind(source).execute(&pool).await.unwrap().last_insert_id();
    let child = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions) VALUES('manual','compensation_blocked',1)")
        .execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("UPDATE reroute_bundles SET recovery_bundle_id=? WHERE id=?")
        .bind(child)
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token,settlement,settled_at) VALUES(?,?,?,'blocked',UTC_TIMESTAMP())")
        .bind(child).bind(source).bind("reconcile-token").execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO device_change_window_sources(device_id,source_bundle_id) VALUES(?,?)")
        .bind(device)
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase) VALUES(NULLIF(?,0),NULL,CONCAT('quarantine:device:',?),'uncertain')")
        .bind(device).bind(device).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,original_reroute_id,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,prepared_action_json,state,mutation_effect) VALUES(?,0,?,?,'{}','{}','{}','{}','succeeded','changed')")
        .bind(child).bind(original).bind(device).execute(&pool).await.unwrap();
    sqlx::query("INSERT INTO reroutes(device_id,bundle_id,rollback_of_reroute_id,trigger_type,state,mutation_effect,started_at,finished_at) VALUES(?,?,?,'rollback','succeeded','changed',UTC_TIMESTAMP(),UTC_TIMESTAMP())")
        .bind(device).bind(child).bind(original).execute(&pool).await.unwrap();

    rerouter_controller::reroute::recovery::finalize_recovery_child(
        &pool,
        child,
        "succeeded",
        Some("reconciliation proved restore"),
        "reconcile-repair",
    )
    .await
    .unwrap();
    let settlement: String = sqlx::query_scalar("SELECT settlement FROM recovery_attempt_sources WHERE recovery_bundle_id=? AND source_bundle_id=?")
        .bind(child).bind(source).fetch_one(&pool).await.unwrap();
    assert_eq!(settlement, "restored");
    let source_state: (String, u32, Option<String>) = sqlx::query_as("SELECT lifecycle_state,remaining_mutations,recovery_claim_token FROM reroute_bundles WHERE id=?")
        .bind(source).fetch_one(&pool).await.unwrap();
    assert_eq!(source_state, ("inactive".into(), 0, None));
    let windows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_change_windows WHERE device_id=?")
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(windows, 0);
}

#[tokio::test]
async fn stale_child_terminalizes_without_clearing_newer_claim() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'127.0.0.1')")
        .bind(format!("stale-child-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let child = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions) VALUES('manual','running',0)")
        .execute(&pool).await.unwrap().last_insert_id();
    let mut sources = Vec::new();
    for token in ["newer-token", "old-token"] {
        let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state,recovery_claim_token,recovery_bundle_id) VALUES('manual','succeeded',0,'recovery_running',?,?)")
            .bind(token).bind(child).execute(&pool).await.unwrap().last_insert_id();
        sqlx::query("INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token) VALUES(?,?, 'old-token')")
            .bind(child).bind(source).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO device_change_window_sources(device_id,source_bundle_id) VALUES(?,?)",
        )
        .bind(device)
        .bind(source)
        .execute(&pool)
        .await
        .unwrap();
        sources.push(source);
    }
    sqlx::query("INSERT INTO device_change_windows(device_id,bundle_id,owner_token,phase) VALUES(?,?, 'old-token','applying')")
        .bind(device).bind(child).execute(&pool).await.unwrap();
    rerouter_controller::reroute::recovery::finalize_recovery_child(
        &pool,
        child,
        "failed",
        Some("superseded child"),
        "old-token",
    )
    .await
    .unwrap();
    let child_state: String = sqlx::query_scalar("SELECT state FROM reroute_bundles WHERE id=?")
        .bind(child)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(child_state, "compensation_blocked");
    let newer: String =
        sqlx::query_scalar("SELECT recovery_claim_token FROM reroute_bundles WHERE id=?")
            .bind(sources[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(newer, "newer-token");
    let unaffected: String =
        sqlx::query_scalar("SELECT lifecycle_state FROM reroute_bundles WHERE id=?")
            .bind(sources[1])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(unaffected, "recovery_blocked");
    let window: (Option<u64>, String) =
        sqlx::query_as("SELECT bundle_id,phase FROM device_change_windows WHERE device_id=?")
            .bind(device)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(window, (None, "uncertain".into()));
}

#[tokio::test]
async fn scheduled_ledger_failure_never_exposes_child_association() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state,recovery_claim_token) VALUES('manual','succeeded',0,'recovery_claimed','ledger-token')")
        .execute(&pool).await.unwrap().last_insert_id();
    let child = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions) VALUES('automatic','planned',1)")
        .execute(&pool).await.unwrap().last_insert_id();
    let failed = rerouter_controller::reroute::recovery::persist_and_associate_scheduled_child(
        &pool,
        child,
        source,
        &[],
        "ledger-token",
        &[],
        json!({"kind":"recovery"}),
    )
    .await;
    assert!(failed.is_err());
    let mappings: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM recovery_attempt_sources WHERE recovery_bundle_id=?",
    )
    .bind(child)
    .fetch_one(&pool)
    .await
    .unwrap();
    let pointer: Option<u64> =
        sqlx::query_scalar("SELECT recovery_bundle_id FROM reroute_bundles WHERE id=?")
            .bind(source)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(mappings, 0);
    assert_eq!(
        pointer, None,
        "a failed ledger cannot become recovery ownership"
    );
}

#[tokio::test]
async fn missing_source_activation_evidence_stays_blocked_and_startup_repair_is_idempotent() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let source = sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','compensation_blocked',0,'recovery_blocked')")
        .execute(&pool).await.unwrap().last_insert_id();
    let child = sqlx::query("INSERT INTO reroute_bundles(parent_bundle_id,trigger_type,state,total_actions) VALUES(?,'manual','aborted',0)")
        .bind(source).execute(&pool).await.unwrap().last_insert_id();
    let token = format!("legacy:child:{child}");
    sqlx::query("INSERT INTO recovery_attempt_sources(recovery_bundle_id,source_bundle_id,claim_token) VALUES(?,?,?)")
        .bind(child).bind(source).bind(&token).execute(&pool).await.unwrap();

    let ownership =
        rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &[source]).await;
    assert!(ownership
        .unwrap_err()
        .to_string()
        .contains("no durable activation coverage"));
    rerouter_controller::reroute::recovery::finalize_recovery_child(
        &pool,
        child,
        "failed",
        Some("first durable startup diagnosis"),
        "startup-repair",
    )
    .await
    .unwrap();
    sqlx::query("UPDATE recovery_attempt_sources SET settled_at='2001-02-03 04:05:06' WHERE recovery_bundle_id=? AND source_bundle_id=?")
        .bind(child).bind(source).execute(&pool).await.unwrap();
    rerouter_controller::reroute::recovery::finalize_recovery_child(
        &pool,
        child,
        "failed",
        Some("later startup diagnosis must not replace history"),
        "startup-repair",
    )
    .await
    .unwrap();
    let settlement:String=sqlx::query_scalar("SELECT settlement FROM recovery_attempt_sources WHERE recovery_bundle_id=? AND source_bundle_id=?")
        .bind(child).bind(source).fetch_one(&pool).await.unwrap();
    let states:(String,String)=sqlx::query_as("SELECT child.state,source.lifecycle_state FROM reroute_bundles child JOIN reroute_bundles source ON source.id=? WHERE child.id=?")
        .bind(source).bind(child).fetch_one(&pool).await.unwrap();
    assert_eq!(settlement, "blocked");
    assert_eq!(
        states,
        ("compensation_blocked".into(), "recovery_blocked".into())
    );
    let stable_history: (String, Option<String>) = sqlx::query_as(
        "SELECT DATE_FORMAT(ras.settled_at,'%Y-%m-%d %H:%i:%s'),child.failure_reason \
         FROM recovery_attempt_sources ras JOIN reroute_bundles child ON child.id=ras.recovery_bundle_id \
         WHERE ras.recovery_bundle_id=? AND ras.source_bundle_id=?",
    )
    .bind(child)
    .bind(source)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        stable_history,
        (
            "2001-02-03 04:05:06".into(),
            Some("first durable startup diagnosis".into())
        ),
        "idempotent startup repair preserves its first terminal evidence"
    );
    let audits:i64=sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event_type='recovery_blocked' AND entity_type='reroute_bundle' AND entity_id=?")
        .bind(child).fetch_one(&pool).await.unwrap();
    let alerts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE dedup_key=?")
        .bind(format!("recovery_degraded:child:{child}"))
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        (audits, alerts),
        (1, 1),
        "repeated startup repair stays idempotent"
    );
}

#[tokio::test]
async fn complete_terminal_skipped_ledger_is_positive_no_write_coverage() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'127.0.0.1')")
        .bind(format!("skipped-coverage-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let source=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','failed',1,'inactive')")
        .execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,prepared_action_json,state,mutation_effect) VALUES(?,0,?,'{}','{}','{}','{}','queued','pending')")
        .bind(source).bind(device).execute(&pool).await.unwrap();
    let ownership = rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &[source])
        .await
        .unwrap();
    assert!(ownership.original_reroute_ids.is_empty());

    let incomplete=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','succeeded',2,'active')")
        .execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO reroutes(device_id,bundle_id,trigger_type,state,mutation_effect) VALUES(?,?,'manual','succeeded','changed')")
        .bind(device).bind(incomplete).execute(&pool).await.unwrap();
    let missing_slot =
        rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &[incomplete]).await;
    assert!(missing_slot
        .unwrap_err()
        .to_string()
        .contains("no durable activation coverage"));
}

#[tokio::test]
async fn complete_sized_but_unknown_or_unlinked_slots_are_not_coverage() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let device = sqlx::query("INSERT INTO devices(name,hostname) VALUES(?,'127.0.0.1')")
        .bind(format!("invalid-slot-{}", uuid::Uuid::new_v4()))
        .execute(&pool)
        .await
        .unwrap()
        .last_insert_id();
    let unknown=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','failed',1,'recovery_blocked')")
        .execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,prepared_action_json,state,mutation_effect) VALUES(?,0,?,'{}','{}','{}','{}','uncertain','unknown')")
        .bind(unknown).bind(device).execute(&pool).await.unwrap();
    let error = rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &[unknown])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("no durable activation coverage"));

    let pending=sqlx::query("INSERT INTO reroute_bundles(trigger_type,state,total_actions,lifecycle_state) VALUES('manual','failed',1,'recovery_blocked')")
        .execute(&pool).await.unwrap().last_insert_id();
    let root=sqlx::query("INSERT INTO reroutes(device_id,bundle_id,bundle_position,trigger_type,state,mutation_effect) VALUES(?,?,0,'manual','pending','pending')")
        .bind(device).bind(pending).execute(&pool).await.unwrap().last_insert_id();
    sqlx::query("INSERT INTO reroute_bundle_actions(bundle_id,position,device_id,template_snapshot_json,canonical_params_json,rendered_plan_json,prepared_action_json,state,mutation_effect,reroute_id) VALUES(?,0,?,'{}','{}','{}','{}','running','pending',?)")
        .bind(pending).bind(device).bind(root).execute(&pool).await.unwrap();
    let error = rerouter_controller::reroute::recovery::ownership_for_sources(&pool, &[pending])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("in-flight or ambiguous"));
}
