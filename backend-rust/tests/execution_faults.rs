//! Failure-boundary matrix for the prepared executor and bundle orchestrator.
//! No real SSH endpoint is contacted.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use rerouter_controller::config::{Config, OperatingMode};
use rerouter_controller::reroute::{bundle, device_plan, templates};
use rerouter_controller::ssh::{
    BoxFuture, CommandResult, LockedDeviceSetPort, ResolvedApply, SessionResolver, SshExecutor,
    SshOutcome, SshPlanFailure,
};
use serde_json::json;
use sqlx::MySqlPool;

#[derive(Clone, Copy)]
enum Fault {
    BeforeWrite,
    MiddleWrite,
    AfterWrite,
    VerificationRead,
}

#[derive(Clone)]
struct FaultSsh {
    faults: Arc<BTreeMap<usize, Fault>>,
    calls: Arc<Mutex<usize>>,
    writes: Arc<Mutex<Vec<u64>>>,
    state: Arc<Mutex<HashMap<u64, bool>>>,
    fail_read: Arc<Mutex<Option<u64>>>,
}

struct FaultLocks(FaultSsh, Vec<u64>);

impl LockedDeviceSetPort for FaultLocks {
    fn device_ids(&self) -> Vec<u64> {
        self.1.clone()
    }

    fn transport_identity(
        &self,
        device_id: u64,
    ) -> anyhow::Result<device_plan::DeviceTransportIdentity> {
        Ok(identity(device_id))
    }

    fn read<'a>(
        &'a mut self,
        device_id: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            if self.0.fail_read.lock().unwrap().take() == Some(device_id) {
                anyhow::bail!("simulated verification disconnect");
            }
            let shutdown = self
                .0
                .state
                .lock()
                .unwrap()
                .get(&device_id)
                .copied()
                .unwrap_or(false);
            Ok(CommandResult {
                command: command.into(),
                output: if shutdown {
                    " shutdown".into()
                } else {
                    String::new()
                },
            })
        })
    }

    fn execute<'a>(
        &'a mut self,
        device_id: u64,
        commands: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            let call = {
                let mut calls = self.0.calls.lock().unwrap();
                *calls += 1;
                *calls
            };
            let fault = self.0.faults.get(&call).copied();
            if matches!(fault, Some(Fault::BeforeWrite)) {
                return Err(SshPlanFailure {
                    completed: Vec::new(),
                    failed_command: commands.first().cloned().unwrap_or_default(),
                    failed_output: "connection closed before command".into(),
                    certainty: device_plan::EffectCertainty::ProvenNoEffect,
                    reason: "pre-write disconnect".into(),
                }
                .into());
            }
            self.0.writes.lock().unwrap().push(device_id);
            let restoring = commands
                .iter()
                .any(|command| command.contains("no shutdown"));
            self.0.state.lock().unwrap().insert(device_id, !restoring);
            if matches!(fault, Some(Fault::MiddleWrite)) {
                return Err(SshPlanFailure {
                    completed: commands
                        .first()
                        .map(|command| CommandResult {
                            command: command.clone(),
                            output: String::new(),
                        })
                        .into_iter()
                        .collect(),
                    failed_command: commands.get(1).cloned().unwrap_or_default(),
                    failed_output: "partial command output".into(),
                    certainty: device_plan::EffectCertainty::UnknownEffect,
                    reason: "mid-write disconnect".into(),
                }
                .into());
            }
            if matches!(fault, Some(Fault::AfterWrite)) {
                anyhow::bail!("simulated disconnect after all commands");
            }
            if matches!(fault, Some(Fault::VerificationRead)) {
                *self.0.fail_read.lock().unwrap() = Some(device_id);
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

impl SshExecutor for FaultSsh {
    async fn apply(&self, _device_id: u64, _commands: &[String]) -> anyhow::Result<SshOutcome> {
        anyhow::bail!("legacy apply is forbidden in fault tests")
    }
    async fn verify_read(&self, _device_id: u64, _command: &str) -> anyhow::Result<String> {
        anyhow::bail!("legacy verify is forbidden in fault tests")
    }
    async fn apply_resolved<'a>(
        &'a self,
        _device_id: u64,
        _read: &'a str,
        _resolve: SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        anyhow::bail!("legacy resolver is forbidden in fault tests")
    }
    fn lock_devices<'a>(
        &'a self,
        devices: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        Box::pin(async move {
            let mut devices = devices.to_vec();
            devices.sort_unstable();
            devices.dedup();
            Ok(Box::new(FaultLocks(self.clone(), devices)) as Box<dyn LockedDeviceSetPort>)
        })
    }
}

impl FaultSsh {
    fn new(faults: impl IntoIterator<Item = (usize, Fault)>) -> Self {
        Self {
            faults: Arc::new(faults.into_iter().collect()),
            calls: Arc::new(Mutex::new(0)),
            writes: Arc::new(Mutex::new(Vec::new())),
            state: Arc::new(Mutex::new(HashMap::new())),
            fail_read: Arc::new(Mutex::new(None)),
        }
    }
}

fn identity(device_id: u64) -> device_plan::DeviceTransportIdentity {
    device_plan::DeviceTransportIdentity {
        host: format!("fault-{device_id}"),
        port: 22,
        pinned_host_fingerprint: format!("fault-fingerprint-{device_id}"),
    }
}

fn prepared(
    device_id: u64,
    template: &templates::Template,
    with_inverse: bool,
) -> device_plan::PreparedDeviceAction {
    let before = device_plan::DeviceStateSnapshot::InterfaceAdmin {
        interface: "Loopback0".into(),
        shutdown: false,
    };
    let after = device_plan::DeviceStateSnapshot::InterfaceAdmin {
        interface: "Loopback0".into(),
        shutdown: true,
    };
    device_plan::PreparedDeviceAction {
        schema_version: device_plan::PREPARED_DEVICE_ACTION_SCHEMA_VERSION,
        device_id,
        template_id: template.id,
        template_name: template.name.clone(),
        canonical_params: json!({}),
        commands: vec!["configure terminal".into(), "shutdown".into(), "end".into()],
        before: vec![before.clone()],
        after: vec![after.clone()],
        verify: vec![after.clone()],
        effect: device_plan::PreparedEffect::Change,
        inverse: with_inverse.then_some(device_plan::PreparedInverse {
            expected_current: vec![after],
            restore: vec![before.clone()],
            commands: vec![
                "configure terminal".into(),
                "no shutdown".into(),
                "end".into(),
            ],
            verify: vec![before],
        }),
        prepared_at: chrono::Utc::now(),
    }
}

struct Fixture {
    rule_id: u64,
    event_id: u64,
    revision: u64,
    devices: Vec<u64>,
    add: templates::Template,
    remove: templates::Template,
    cfg: Config,
}

async fn fixture(pool: &MySqlPool, devices: usize) -> Fixture {
    sqlx::query(
        "INSERT INTO system_settings (`key`,`value`) VALUES \
            ('operating_mode','enforce'),('automatic_actions_enabled','true') \
         ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)",
    )
    .execute(pool)
    .await
    .unwrap();
    let rule_id = sqlx::query(
        "INSERT INTO rules (name,metric,operator,threshold_value,duration_seconds,severity,automatic_reroute_enabled) \
         VALUES (?, 'tx_bps','>',1,0,'high',1)",
    )
    .bind(format!("fault-rule-{}", uuid::Uuid::new_v4()))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    sqlx::query("INSERT INTO rule_states (rule_id,current_state) VALUES (?, 'firing')")
        .bind(rule_id)
        .execute(pool)
        .await
        .unwrap();
    let revision: u64 = sqlx::query_scalar("SELECT actions_revision FROM rules WHERE id=?")
        .bind(rule_id)
        .fetch_one(pool)
        .await
        .unwrap();
    let event_id = sqlx::query("INSERT INTO rule_events (rule_id,event) VALUES (?, 'fired')")
        .bind(rule_id)
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let mut ids = Vec::new();
    for _ in 0..devices {
        let id = sqlx::query(
            "INSERT INTO devices (name,hostname,ssh_status,last_ssh_ok_at,ssh_reachable_since) \
             VALUES (?, '127.0.0.1','reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 5 MINUTE))",
        )
        .bind(format!("fault-device-{}", uuid::Uuid::new_v4()))
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
        rerouter_controller::reroute::reachability::stamp_ssh_ok(pool, id)
            .await
            .unwrap();
        ids.push(id);
    }
    let mut cfg = Config::default();
    cfg.safety.operating_mode = OperatingMode::Enforce;
    cfg.safety.automatic_actions_enabled = true;
    cfg.safety.global_action_rate_limit_count = 0;
    Fixture {
        rule_id,
        event_id,
        revision,
        devices: ids,
        add: templates::load(
            pool,
            sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='bgp_advertise_add'")
                .fetch_one(pool)
                .await
                .unwrap(),
        )
        .await
        .unwrap(),
        remove: templates::load(
            pool,
            sqlx::query_scalar(
                "SELECT id FROM reroute_templates WHERE name='bgp_advertise_remove'",
            )
            .fetch_one(pool)
            .await
            .unwrap(),
        )
        .await
        .unwrap(),
        cfg,
    }
}

async fn create_bundle(pool: &MySqlPool, f: &Fixture, actions: &[bundle::BundleAction]) -> u64 {
    let id = bundle::create(
        pool,
        Some(f.rule_id),
        Some(f.event_id),
        "automatic",
        None,
        "fault injection",
        bundle::FailurePolicy::AbortAndCompensate,
        actions.len() as u32,
    )
    .await
    .unwrap();
    let identities: BTreeMap<_, _> = actions
        .iter()
        .map(|action| (action.device_id, identity(action.device_id)))
        .collect();
    sqlx::query("UPDATE reroute_bundles SET source_json=? WHERE id=?")
        .bind(sqlx::types::Json(json!({
            "kind":"rule","rule_id":f.rule_id,"actions_revision":f.revision,
            "transport_identities":identities
        })))
        .bind(id)
        .execute(pool)
        .await
        .unwrap();
    id
}

async fn cleanup(pool: &MySqlPool, f: &Fixture, bundles: &[u64]) {
    for id in bundles {
        sqlx::query("DELETE FROM device_change_windows WHERE bundle_id=?")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query(
            "DELETE FROM locks WHERE reroute_id IN (SELECT id FROM reroutes WHERE bundle_id=?)",
        )
        .bind(id)
        .execute(pool)
        .await
        .ok();
        sqlx::query(
            "DELETE FROM locks WHERE reroute_id IN (SELECT inverse.id FROM reroutes inverse \
             JOIN reroutes original ON original.id=inverse.rollback_of_reroute_id \
             WHERE original.bundle_id=?)",
        )
        .bind(id)
        .execute(pool)
        .await
        .ok();
        sqlx::query(
            "DELETE inverse FROM reroutes inverse JOIN reroutes original \
             ON original.id=inverse.rollback_of_reroute_id WHERE original.bundle_id=?",
        )
        .bind(id)
        .execute(pool)
        .await
        .ok();
        sqlx::query("DELETE FROM reroutes WHERE bundle_id=?")
            .bind(id)
            .execute(pool)
            .await
            .ok();
        sqlx::query("DELETE FROM reroute_bundles WHERE id=?")
            .bind(id)
            .execute(pool)
            .await
            .ok();
    }
    sqlx::query("DELETE FROM cooldowns WHERE scope_ref IN (?, ?, ?)")
        .bind(f.devices.first().map(u64::to_string))
        .bind(f.devices.get(1).map(u64::to_string))
        .bind(f.devices.get(2).map(u64::to_string))
        .execute(pool)
        .await
        .ok();
    sqlx::query("DELETE FROM rules WHERE id=?")
        .bind(f.rule_id)
        .execute(pool)
        .await
        .ok();
    for device in &f.devices {
        sqlx::query("DELETE FROM devices WHERE id=?")
            .bind(device)
            .execute(pool)
            .await
            .ok();
    }
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .ok();
    sqlx::query(
        "UPDATE system_settings SET `value`='false' WHERE `key`='automatic_actions_enabled'",
    )
    .execute(pool)
    .await
    .ok();
}

#[tokio::test]
async fn apply_failure_boundaries_preserve_effect_certainty() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let f = fixture(&pool, 1).await;
    let mut bundles = Vec::new();
    for fault in [
        Fault::BeforeWrite,
        Fault::MiddleWrite,
        Fault::AfterWrite,
        Fault::VerificationRead,
    ] {
        let action = bundle::BundleAction {
            device_id: f.devices[0],
            template: f.add.clone(),
            params: json!({}),
            reason: "fault matrix".into(),
            position: 0,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(f.devices[0], &f.add, false)),
            original_reroute_id: None,
        };
        let bundle_id = create_bundle(&pool, &f, std::slice::from_ref(&action)).await;
        bundles.push(bundle_id);
        let ssh = FaultSsh::new([(1, fault)]);
        let outcome = bundle::run_with_ssh(
            &pool,
            &f.cfg,
            bundle::BundleRun::automatic(
                bundle_id,
                bundle::FailurePolicy::AbortAndCompensate,
                f.rule_id,
                f.event_id,
            ),
            vec![action],
            &ssh,
        )
        .await;
        let (state, effect): (String, String) = sqlx::query_as(
            "SELECT state,mutation_effect FROM reroutes WHERE bundle_id=? ORDER BY id LIMIT 1",
        )
        .bind(bundle_id)
        .fetch_one(&pool)
        .await
        .unwrap();
        if matches!(fault, Fault::BeforeWrite) {
            assert_eq!((state.as_str(), effect.as_str()), ("failed", "noop"));
            assert_eq!(outcome.state, "aborted");
            assert!(ssh.writes.lock().unwrap().is_empty());
        } else {
            assert_eq!((state.as_str(), effect.as_str()), ("uncertain", "unknown"));
            assert_eq!(outcome.state, "compensation_blocked");
            assert_eq!(ssh.writes.lock().unwrap().as_slice(), &[f.devices[0]]);
        }
        sqlx::query("DELETE FROM device_change_windows WHERE bundle_id=?")
            .bind(bundle_id)
            .execute(&pool)
            .await
            .ok();
        sqlx::query(
            "DELETE FROM locks WHERE reroute_id IN (SELECT id FROM reroutes WHERE bundle_id=?)",
        )
        .bind(bundle_id)
        .execute(&pool)
        .await
        .ok();
        sqlx::query("DELETE FROM reroutes WHERE bundle_id=?")
            .bind(bundle_id)
            .execute(&pool)
            .await
            .ok();
        sqlx::query("DELETE FROM cooldowns WHERE scope_ref IN (?, ?)")
            .bind(f.devices[0].to_string())
            .bind(f.rule_id.to_string())
            .execute(&pool)
            .await
            .ok();
    }
    cleanup(&pool, &f, &bundles).await;
}

#[tokio::test]
async fn ambiguous_compensation_stops_before_any_earlier_inverse() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let f = fixture(&pool, 3).await;
    let actions = vec![
        bundle::BundleAction {
            device_id: f.devices[0],
            template: f.add.clone(),
            params: json!({}),
            reason: "A".into(),
            position: 0,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(f.devices[0], &f.add, true)),
            original_reroute_id: None,
        },
        bundle::BundleAction {
            device_id: f.devices[1],
            template: f.add.clone(),
            params: json!({}),
            reason: "B".into(),
            position: 1,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(f.devices[1], &f.add, true)),
            original_reroute_id: None,
        },
        bundle::BundleAction {
            device_id: f.devices[2],
            template: f.remove.clone(),
            params: json!({}),
            reason: "C".into(),
            position: 2,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared(f.devices[2], &f.remove, false)),
            original_reroute_id: None,
        },
    ];
    let bundle_id = create_bundle(&pool, &f, &actions).await;
    let ssh = FaultSsh::new([(3, Fault::BeforeWrite), (4, Fault::AfterWrite)]);
    let outcome = bundle::run_with_ssh(
        &pool,
        &f.cfg,
        bundle::BundleRun::automatic(
            bundle_id,
            bundle::FailurePolicy::AbortAndCompensate,
            f.rule_id,
            f.event_id,
        ),
        actions,
        &ssh,
    )
    .await;
    assert_eq!(outcome.state, "compensation_blocked");
    assert_eq!(
        ssh.writes.lock().unwrap().as_slice(),
        &[f.devices[0], f.devices[1], f.devices[1]],
        "A inverse must not run after B compensation becomes ambiguous"
    );
    let original_a: u64 = sqlx::query_scalar(
        "SELECT id FROM reroutes WHERE bundle_id=? AND bundle_position=0 AND rollback_of_reroute_id IS NULL",
    )
    .bind(bundle_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let inverse_a: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE rollback_of_reroute_id=?")
            .bind(original_a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(inverse_a, 0);
    cleanup(&pool, &f, &[bundle_id]).await;
}

#[tokio::test]
async fn terminal_publication_failure_remains_durably_recoverable() {
    let test_db = common::test_database().await;
    let pool = test_db.pool().clone();
    let f = fixture(&pool, 1).await;
    let action = bundle::BundleAction {
        device_id: f.devices[0],
        template: f.add.clone(),
        params: json!({}),
        reason: "terminal-fault-fixture".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: Some(prepared(f.devices[0], &f.add, false)),
        original_reroute_id: None,
    };
    let bundle_id = create_bundle(&pool, &f, std::slice::from_ref(&action)).await;
    // MySQL 8.4 does not accept MariaDB's DROP CONSTRAINT IF EXISTS extension.
    let exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.table_constraints \
         WHERE constraint_schema=DATABASE() AND table_name='reroutes' \
           AND constraint_name='chk_rrt_test_terminal_fault'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    if exists > 0 {
        sqlx::query("ALTER TABLE reroutes DROP CONSTRAINT chk_rrt_test_terminal_fault")
            .execute(&pool)
            .await
            .unwrap();
    }
    sqlx::query(
        "ALTER TABLE reroutes ADD CONSTRAINT chk_rrt_test_terminal_fault CHECK ( \
         NOT (reason='terminal-fault-fixture' AND state IN ('succeeded','failed','uncertain')))",
    )
    .execute(&pool)
    .await
    .unwrap();
    let ssh = FaultSsh::new([]);
    let outcome = bundle::run_with_ssh(
        &pool,
        &f.cfg,
        bundle::BundleRun::automatic(
            bundle_id,
            bundle::FailurePolicy::AbortAndCompensate,
            f.rule_id,
            f.event_id,
        ),
        vec![action],
        &ssh,
    )
    .await;
    assert_eq!(outcome.state, "compensation_blocked");
    let reroute_id: u64 = sqlx::query_scalar("SELECT id FROM reroutes WHERE bundle_id=?")
        .bind(bundle_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let in_flight: String = sqlx::query_scalar("SELECT state FROM reroutes WHERE id=?")
        .bind(reroute_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(matches!(in_flight.as_str(), "running" | "verifying"));
    sqlx::query("ALTER TABLE reroutes DROP CONSTRAINT chk_rrt_test_terminal_fault")
        .execute(&pool)
        .await
        .unwrap();
    rerouter_controller::reroute::state_machine::recover_on_startup(&pool)
        .await
        .unwrap();
    let recovered: (String, String) =
        sqlx::query_as("SELECT state,mutation_effect FROM reroutes WHERE id=?")
            .bind(reroute_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        (recovered.0.as_str(), recovered.1.as_str()),
        ("uncertain", "unknown")
    );
    cleanup(&pool, &f, &[bundle_id]).await;
}
