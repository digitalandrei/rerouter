mod common;

use axum_extra::extract::cookie::Key;
use chrono::{Duration, Utc};
use rerouter_controller::{
    api::{self, manual_mitigations},
    auth::sessions::Session,
    config::{Config, LabDevice},
    reroute::{
        bundle::{self, BundleAction, FailurePolicy},
        device_plan::{self, PreparationReader, VerificationMode},
        executor::ActorContext,
        templates,
    },
    ssh::{
        BoxFuture, CommandResult, LockedDeviceSetPort, ResolvedApply, SessionResolver, SshExecutor,
        SshOutcome,
    },
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

const HOST: &str = "192.0.2.233";
const PIN: &str = "SHA256:configuration-only-fixture";

struct MssReader(Option<u32>, &'static str);
impl PreparationReader for MssReader {
    fn read_one<'a>(&'a self, _: u64, command: &'a str) -> BoxFuture<'a, anyhow::Result<String>> {
        Box::pin(async move {
            assert!(
                !command.contains("show ip bgp") && !command.contains("advertised-routes"),
                "configuration-only preparation must not require operational routing state"
            );
            if command.contains("Port-channel1") {
                Ok(self
                    .0
                    .map(|value| format!("interface Port-channel1\n ip tcp adjust-mss {value}"))
                    .unwrap_or_else(|| "interface Port-channel1\n no negotiation auto".into()))
            } else if command.contains("route-map") {
                Ok("route-map prepend-3 permit 100\n set as-path prepend 34501 34501 34501".into())
            } else if command.contains("prefix-list") {
                Ok("ip prefix-list no-export seq 10 deny 0.0.0.0/0 le 32\nip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 7 permit 194.102.117.0/24\nip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32".into())
            } else {
                Ok(format!("router bgp 34501\n neighbor 23.45.23.197 remote-as 32787\n address-family ipv4\n neighbor 23.45.23.197 activate\n neighbor 23.45.23.197 prefix-list {} out\n exit-address-family", self.1))
            }
        })
    }
    fn read_many<'a>(
        &'a self,
        _: u64,
        commands: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<Vec<String>>> {
        Box::pin(async move {
            assert_eq!(commands.len(), 3);
            Ok(vec![
                format!("router bgp 34501\n neighbor 23.45.23.197 remote-as 32787\n address-family ipv4\n neighbor 23.45.23.197 activate\n neighbor 23.45.23.197 prefix-list {} out\n exit-address-family", self.1),
                "route-map prepend-3 permit 100\n set as-path prepend 34501 34501 34501".into(),
                "ip prefix-list no-export seq 10 deny 0.0.0.0/0 le 32\nip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 7 permit 194.102.117.0/24\nip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32".into(),
            ])
        })
    }
}

#[derive(Clone)]
struct StatefulMssSsh {
    state: Arc<Mutex<(String, Option<u32>)>>,
    device: u64,
    fail_mss: bool,
}
struct StatefulMssLocks {
    state: Arc<Mutex<(String, Option<u32>)>>,
    device: u64,
    fail_mss: bool,
}

impl LockedDeviceSetPort for StatefulMssLocks {
    fn device_ids(&self) -> Vec<u64> {
        vec![self.device]
    }
    fn transport_identity(&self, _: u64) -> anyhow::Result<device_plan::DeviceTransportIdentity> {
        Ok(device_plan::DeviceTransportIdentity {
            host: HOST.into(),
            port: 22,
            pinned_host_fingerprint: PIN.into(),
        })
    }
    fn read<'a>(
        &'a mut self,
        _: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            assert!(
                !command.contains("neighbor")
                    && !command.contains("advertised-routes")
                    && !command.contains("show ip bgp"),
                "routing proof leaked into configuration-only execution: {command}"
            );
            let state = self.state.lock().unwrap().clone();
            let output = if command.contains("section ^router bgp") {
                format!("router bgp 34501\n neighbor 23.45.23.197 remote-as 32787\n address-family ipv4\n neighbor 23.45.23.197 activate\n neighbor 23.45.23.197 prefix-list {} out\n exit-address-family", state.0)
            } else if command.contains("section ^route-map") {
                "route-map prepend-3 permit 100\n set as-path prepend 34501 34501 34501".into()
            } else if command.contains("section ^ip prefix-list") {
                "ip prefix-list no-export seq 10 deny 0.0.0.0/0 le 32\nip prefix-list pfx-to-viva seq 5 permit 194.105.142.0/24\nip prefix-list pfx-to-viva seq 7 permit 194.102.117.0/24\nip prefix-list pfx-to-viva seq 10 deny 0.0.0.0/0 le 32".into()
            } else {
                state
                    .1
                    .map(|v| format!("interface Port-channel1\n ip tcp adjust-mss {v}"))
                    .unwrap_or_else(|| "interface Port-channel1".into())
            };
            Ok(CommandResult {
                command: command.into(),
                output,
            })
        })
    }
    fn execute<'a>(
        &'a mut self,
        _: u64,
        commands: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            for command in commands {
                if command.starts_with("neighbor 23.45.23.197 prefix-list ")
                    && command.ends_with(" out")
                {
                    self.state.lock().unwrap().0 =
                        command.split_whitespace().nth(3).unwrap().into();
                }
                if let Some(value) = command.strip_prefix("ip tcp adjust-mss ") {
                    if self.fail_mss {
                        return Err(device_plan::PreparedExecutionError {
                            certainty: device_plan::EffectCertainty::ProvenNoEffect,
                            reason: "injected MSS refusal before mutation".into(),
                        }
                        .into());
                    }
                    self.state.lock().unwrap().1 = Some(value.parse()?);
                }
                if command == "no ip tcp adjust-mss" {
                    self.state.lock().unwrap().1 = None;
                }
            }
            Ok(SshOutcome {
                results: commands
                    .iter()
                    .map(|command| CommandResult {
                        command: command.clone(),
                        output: String::new(),
                    })
                    .collect(),
                fingerprint: PIN.into(),
                pinned_now: false,
            })
        })
    }
    fn unlock_all(self: Box<Self>) -> BoxFuture<'static, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl SshExecutor for StatefulMssSsh {
    async fn apply(&self, _: u64, _: &[String]) -> anyhow::Result<SshOutcome> {
        anyhow::bail!("unprepared apply")
    }
    async fn verify_read(&self, _: u64, _: &str) -> anyhow::Result<String> {
        anyhow::bail!("unprepared verify")
    }
    async fn apply_resolved<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        anyhow::bail!("unprepared resolver")
    }
    fn lock_devices<'a>(
        &'a self,
        ids: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        Box::pin(async move {
            anyhow::ensure!(ids.iter().all(|id| *id == self.device));
            Ok(Box::new(StatefulMssLocks {
                state: self.state.clone(),
                device: self.device,
                fail_mss: self.fail_mss,
            }) as Box<dyn LockedDeviceSetPort>)
        })
    }
}

#[derive(Clone)]
struct MultiDeviceMssSsh {
    states: Arc<Mutex<BTreeMap<u64, Option<u32>>>>,
}

struct MultiDeviceMssLocks {
    states: Arc<Mutex<BTreeMap<u64, Option<u32>>>>,
}

impl LockedDeviceSetPort for MultiDeviceMssLocks {
    fn device_ids(&self) -> Vec<u64> {
        self.states.lock().unwrap().keys().copied().collect()
    }

    fn transport_identity(
        &self,
        device_id: u64,
    ) -> anyhow::Result<device_plan::DeviceTransportIdentity> {
        anyhow::ensure!(self.states.lock().unwrap().contains_key(&device_id));
        Ok(device_plan::DeviceTransportIdentity {
            host: HOST.into(),
            port: 22,
            pinned_host_fingerprint: PIN.into(),
        })
    }

    fn read<'a>(
        &'a mut self,
        device_id: u64,
        command: &'a str,
    ) -> BoxFuture<'a, anyhow::Result<CommandResult>> {
        Box::pin(async move {
            let value = self
                .states
                .lock()
                .unwrap()
                .get(&device_id)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("unknown fake device"))?;
            let output = value
                .map(|mss| format!("interface Port-channel1\n ip tcp adjust-mss {mss}"))
                .unwrap_or_else(|| "interface Port-channel1".into());
            Ok(CommandResult {
                command: command.into(),
                output,
            })
        })
    }

    fn execute<'a>(
        &'a mut self,
        device_id: u64,
        commands: &'a [String],
    ) -> BoxFuture<'a, anyhow::Result<SshOutcome>> {
        Box::pin(async move {
            for command in commands {
                if let Some(value) = command.strip_prefix("ip tcp adjust-mss ") {
                    self.states
                        .lock()
                        .unwrap()
                        .insert(device_id, Some(value.parse()?));
                } else if command == "no ip tcp adjust-mss" {
                    self.states.lock().unwrap().insert(device_id, None);
                }
            }
            Ok(SshOutcome {
                results: commands
                    .iter()
                    .map(|command| CommandResult {
                        command: command.clone(),
                        output: String::new(),
                    })
                    .collect(),
                fingerprint: PIN.into(),
                pinned_now: false,
            })
        })
    }

    fn unlock_all(self: Box<Self>) -> BoxFuture<'static, anyhow::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

impl SshExecutor for MultiDeviceMssSsh {
    async fn apply(&self, _: u64, _: &[String]) -> anyhow::Result<SshOutcome> {
        anyhow::bail!("unprepared apply")
    }
    async fn verify_read(&self, _: u64, _: &str) -> anyhow::Result<String> {
        anyhow::bail!("unprepared verify")
    }
    async fn apply_resolved<'a>(
        &'a self,
        _: u64,
        _: &'a str,
        _: SessionResolver<'a>,
    ) -> anyhow::Result<ResolvedApply> {
        anyhow::bail!("unprepared resolver")
    }
    fn lock_devices<'a>(
        &'a self,
        ids: &'a [u64],
    ) -> BoxFuture<'a, anyhow::Result<Box<dyn LockedDeviceSetPort>>> {
        Box::pin(async move {
            let expected = self
                .states
                .lock()
                .unwrap()
                .keys()
                .copied()
                .collect::<Vec<_>>();
            anyhow::ensure!(ids == expected.as_slice());
            Ok(Box::new(MultiDeviceMssLocks {
                states: self.states.clone(),
            }) as Box<dyn LockedDeviceSetPort>)
        })
    }
}

fn actor(user_id: u64) -> Session {
    Session {
        id: 1,
        user_id,
        totp_verified: true,
        expires_at: Utc::now() + Duration::hours(1),
        ip_address: "127.0.0.1".into(),
        user_agent: "configuration-only-test".into(),
    }
}

async fn successful_fake_ssh_run_with_timer(
    revert_after_seconds: Option<u32>,
    force_terminal_failure: bool,
) {
    let db = common::test_database().await;
    let pool = db.pool();
    let user =
        sqlx::query("INSERT INTO users(name,email,password) VALUES('timer fixture',?,'unused')")
            .bind(format!("timer-{}@example.test", uuid::Uuid::new_v4()))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
    let device = sqlx::query("INSERT INTO devices(name,hostname,ssh_port,ssh_host_fingerprint,ssh_status,last_ssh_ok_at,ssh_reachable_since) VALUES(?,?,22,?,'reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))")
        .bind(format!("timer-device-{}", uuid::Uuid::new_v4())).bind(HOST).bind(PIN).execute(pool).await.unwrap().last_insert_id();
    rerouter_controller::reroute::reachability::stamp_ssh_ok(pool, device)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_interfaces(device_id,if_index,if_name,if_descr,last_seen_at) VALUES(?,1,'Po1','Port-channel1',UTC_TIMESTAMP())").bind(device).execute(pool).await.unwrap();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='iface_tcp_adjust_mss'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, template_id).await.unwrap();
    let input = device_plan::PrepareInput {
        device_id: device,
        template_id,
        template_name: template.name.clone(),
        canonical_params: json!({"interface":"Port-channel1","mss":1400}),
    };
    let prepared = device_plan::prepare_actions_read_only_with_reader(
        pool,
        std::slice::from_ref(&input),
        &MssReader(None, "no-export"),
    )
    .await
    .unwrap();
    let action = BundleAction {
        device_id: device,
        template,
        params: input.canonical_params,
        reason: "timed proof".into(),
        position: 0,
        auto_target: None,
        auto_target_low_confidence: None,
        prepared: Some(prepared[0].clone()),
        original_reroute_id: None,
    };
    let mut cfg = Config::default();
    cfg.safety.global_action_rate_limit_count = 0;
    cfg.safety.same_device_cooldown_seconds = 0;
    let state = api::AppState {
        pool: pool.clone(),
        config: cfg.clone(),
        cookie_key: Key::from(&[43; 64]),
    };
    let (status, axum::Json(preview)) = manual_mitigations::preview_actions_with_reader(
        &state,
        &actor(user),
        "manual_mitigation",
        None,
        vec![action],
        json!({"kind":"manual","name":"Run once"}),
        "timed proof".into(),
        json!({"actions":[],"revert_after_seconds":revert_after_seconds}),
        revert_after_seconds,
        &MssReader(None, "no-export"),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{preview}");
    let accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        preview["plan_id"].as_u64().unwrap(),
        preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let ssh = StatefulMssSsh {
        state: Arc::new(Mutex::new(("no-export".into(), None))),
        device,
        fail_mss: false,
    };
    let snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(accepted.plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let actions: Vec<BundleAction> = serde_json::from_value(snapshot.0["actions"].clone()).unwrap();
    let mut run = bundle::BundleRun::manual(
        accepted.bundle_id,
        FailurePolicy::AbortAndCompensate,
        None,
        user,
        ActorContext {
            ip_address: "127.0.0.1".into(),
            user_agent: "timer-test".into(),
        },
    )
    .with_authorization(Some(accepted.plan_id), format!("plan:{}", accepted.plan_id));
    if force_terminal_failure {
        run = run.with_forced_terminal_persistence_failure();
    }
    let outcome = bundle::run_with_ssh(pool, &cfg, run, actions, &ssh).await;
    if force_terminal_failure {
        assert_eq!(outcome.state, "compensation_blocked");
        assert_eq!(*ssh.state.lock().unwrap(), ("no-export".into(), Some(1400)));
        let durable: String = sqlx::query_scalar("SELECT state FROM reroute_bundles WHERE id=?")
            .bind(accepted.bundle_id)
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(
            durable, "running",
            "startup repair retains in-flight evidence"
        );
        let phase: String = sqlx::query_scalar(
            "SELECT phase FROM device_change_windows WHERE bundle_id=? AND device_id=?",
        )
        .bind(accepted.bundle_id)
        .bind(device)
        .fetch_one(pool)
        .await
        .unwrap();
        assert_eq!(phase, "uncertain");
        return;
    }
    assert_eq!(outcome.state, "succeeded", "{:?}", outcome.failure_reason);
    let (source_timer, finished_at, deadline, lifecycle): (Option<u32>, chrono::DateTime<Utc>, Option<chrono::DateTime<Utc>>, String) = sqlx::query_as("SELECT CAST(JSON_UNQUOTE(JSON_EXTRACT(source_json,'$.revert_after_seconds')) AS UNSIGNED),finished_at,recovery_deadline,lifecycle_state FROM reroute_bundles WHERE id=?").bind(accepted.bundle_id).fetch_one(pool).await.unwrap();
    assert_eq!(source_timer, revert_after_seconds);
    assert_eq!(
        deadline.map(|value| (value - finished_at).num_seconds()),
        revert_after_seconds.map(i64::from)
    );
    assert_eq!(
        lifecycle,
        if revert_after_seconds.is_some() {
            "recovery_scheduled"
        } else {
            "active"
        }
    );
    rerouter_controller::reroute::recovery::schedule_if_eligible(pool, accepted.bundle_id)
        .await
        .unwrap();
    let anchored: Option<chrono::DateTime<Utc>> =
        sqlx::query_scalar("SELECT recovery_deadline FROM reroute_bundles WHERE id=?")
            .bind(accepted.bundle_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(anchored, deadline);
    if revert_after_seconds.is_some() {
        let mut legacy: sqlx::types::Json<Value> =
            sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
                .bind(accepted.plan_id)
                .fetch_one(pool)
                .await
                .unwrap();
        legacy.0["source"]
            .as_object_mut()
            .unwrap()
            .remove("revert_after_seconds");
        let legacy_hash = manual_mitigations::hash_snapshot(&legacy.0);
        sqlx::query("UPDATE execution_plans SET snapshot_json=?,plan_hash=? WHERE id=?")
            .bind(&legacy)
            .bind(legacy_hash)
            .bind(accepted.plan_id)
            .execute(pool)
            .await
            .unwrap();
        let repeated = manual_mitigations::accept_plan(
            &state,
            &actor(user),
            accepted.plan_id,
            preview["preview_token"].as_str().unwrap(),
            "manual_mitigation",
            None,
        )
        .await
        .unwrap();
        assert!(repeated.already_accepted);
        assert_eq!(repeated.bundle_id, accepted.bundle_id);
        let actions: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM reroute_bundle_actions WHERE bundle_id=?")
                .bind(accepted.bundle_id)
                .fetch_one(pool)
                .await
                .unwrap();
        assert_eq!(
            actions, 1,
            "idempotent legacy replay must not duplicate actions"
        );
    }
}

#[tokio::test]
async fn timed_preview_accept_and_successful_fake_ssh_run_anchor_one_deadline() {
    successful_fake_ssh_run_with_timer(Some(300), false).await;
}

#[tokio::test]
async fn untimed_preview_accept_and_successful_fake_ssh_run_stays_active() {
    successful_fake_ssh_run_with_timer(None, false).await;
}

#[tokio::test]
async fn terminal_persistence_failure_after_fake_write_is_never_reported_succeeded() {
    successful_fake_ssh_run_with_timer(None, true).await;
}

#[tokio::test]
async fn two_router_configuration_only_bundle_executes_and_verifies_both_devices() {
    let db = common::test_database().await;
    let pool = db.pool();
    let user = sqlx::query(
        "INSERT INTO users(name,email,password) VALUES('two router fixture',?,'unused')",
    )
    .bind(format!("two-router-{}@example.test", uuid::Uuid::new_v4()))
    .execute(pool)
    .await
    .unwrap()
    .last_insert_id();
    unsafe {
        std::env::set_var(
            "SECRETS_KEY",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
    };
    let password = rerouter_controller::crypto::seal_str("fixture-password").unwrap();
    let mut devices = Vec::new();
    for ordinal in 1..=2 {
        let device = sqlx::query("INSERT INTO devices(name,hostname,ssh_username,ssh_port,ssh_auth_method,ssh_password_encrypted,ssh_host_fingerprint,ssh_status,last_ssh_ok_at,ssh_reachable_since) VALUES(?,?,'fixture',22,'password',?,?,'reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))")
            .bind(format!("two-router-{ordinal}-{}", uuid::Uuid::new_v4()))
            .bind(HOST)
            .bind(password.clone())
            .bind(PIN)
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
        rerouter_controller::reroute::reachability::stamp_ssh_ok(pool, device)
            .await
            .unwrap();
        sqlx::query("INSERT INTO device_interfaces(device_id,if_index,if_name,if_descr,last_seen_at) VALUES(?,1,'Po1','Port-channel1',UTC_TIMESTAMP())")
            .bind(device)
            .execute(pool)
            .await
            .unwrap();
        devices.push(device);
    }
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='iface_tcp_adjust_mss'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, template_id).await.unwrap();
    let inputs = devices
        .iter()
        .map(|device_id| device_plan::PrepareInput {
            device_id: *device_id,
            template_id,
            template_name: template.name.clone(),
            canonical_params: json!({"interface":"Port-channel1","mss":1436}),
        })
        .collect::<Vec<_>>();
    let prepared = device_plan::prepare_actions_read_only_with_reader_for_mode(
        pool,
        &inputs,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await
    .unwrap();
    let actions = inputs
        .iter()
        .zip(prepared)
        .enumerate()
        .map(|(position, (input, prepared))| BundleAction {
            device_id: input.device_id,
            template: template.clone(),
            params: input.canonical_params.clone(),
            reason: "two-router execution proof".into(),
            position: position as u32,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared),
            original_reroute_id: None,
        })
        .collect::<Vec<_>>();
    let mut cfg = Config::default();
    cfg.safety.same_device_cooldown_seconds = 0;
    let state = api::AppState {
        pool: pool.clone(),
        config: cfg.clone(),
        cookie_key: Key::from(&[44; 64]),
    };
    let (status, axum::Json(preview)) = manual_mitigations::preview_actions_with_reader_mode(
        &state,
        &actor(user),
        "manual_mitigation",
        None,
        actions,
        json!({"kind":"manual","name":"Two routers"}),
        "two-router execution proof".into(),
        json!({"actions":[],"verification_mode":"configuration_only"}),
        None,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{preview:?}");
    let accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        preview["plan_id"].as_u64().unwrap(),
        preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(accepted.plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let actions: Vec<BundleAction> = serde_json::from_value(snapshot.0["actions"].clone()).unwrap();
    let states = Arc::new(Mutex::new(
        devices
            .iter()
            .map(|device| (*device, None))
            .collect::<BTreeMap<_, _>>(),
    ));
    let ssh = MultiDeviceMssSsh {
        states: states.clone(),
    };
    let outcome = bundle::run_with_ssh(
        pool,
        &cfg,
        bundle::BundleRun::manual(
            accepted.bundle_id,
            FailurePolicy::AbortAndCompensate,
            None,
            user,
            ActorContext {
                ip_address: "127.0.0.1".into(),
                user_agent: "two-router-test".into(),
            },
        )
        .with_authorization(Some(accepted.plan_id), format!("plan:{}", accepted.plan_id)),
        actions,
        &ssh,
    )
    .await;
    assert_eq!(outcome.state, "succeeded", "{:?}", outcome.failure_reason);
    assert!(states
        .lock()
        .unwrap()
        .values()
        .all(|mss| *mss == Some(1436)));
    let completed: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM reroutes WHERE bundle_id=? AND state='succeeded'")
            .bind(accepted.bundle_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(completed, 2);
}

#[tokio::test]
async fn real_preview_consume_and_locked_execution_verify_configuration_without_routing() {
    let db = common::test_database().await;
    let pool = db.pool();
    sqlx::query("UPDATE system_settings SET `value`='observe' WHERE `key`='operating_mode'")
        .execute(pool)
        .await
        .unwrap();
    let user =
        sqlx::query("INSERT INTO users(name,email,password) VALUES('lab fixture',?,'unused')")
            .bind(format!("lab-{}@example.test", uuid::Uuid::new_v4()))
            .execute(pool)
            .await
            .unwrap()
            .last_insert_id();
    let device = sqlx::query("INSERT INTO devices(name,hostname,ssh_port,ssh_host_fingerprint,ssh_status,last_ssh_ok_at,ssh_reachable_since) VALUES(?,?,22,?,'reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))")
        .bind(format!("lab-device-{}", uuid::Uuid::new_v4())).bind(HOST).bind(PIN).execute(pool).await.unwrap().last_insert_id();
    rerouter_controller::reroute::reachability::stamp_ssh_ok(pool, device)
        .await
        .unwrap();
    sqlx::query("INSERT INTO device_interfaces(device_id,if_index,if_name,if_descr,last_seen_at) VALUES(?,1,'Po1','Port-channel1',UTC_TIMESTAMP())").bind(device).execute(pool).await.unwrap();
    let template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='iface_tcp_adjust_mss'")
            .fetch_one(pool)
            .await
            .unwrap();
    let template = templates::load(pool, template_id).await.unwrap();
    let policy_template_id: u64 =
        sqlx::query_scalar("SELECT id FROM reroute_templates WHERE name='bgp_export_policy_set'")
            .fetch_one(pool)
            .await
            .unwrap();
    let policy_template = templates::load(pool, policy_template_id).await.unwrap();
    let inputs = vec![
        device_plan::PrepareInput {
            device_id: device,
            template_id: policy_template_id,
            template_name: policy_template.name.clone(),
            canonical_params: json!({"neighbor_ip":"23.45.23.197","policy_kind":"prefix_list","policy_name":"pfx-to-viva"}),
        },
        device_plan::PrepareInput {
            device_id: device,
            template_id,
            template_name: template.name.clone(),
            canonical_params: json!({"interface":"Port-channel1","mss":1400}),
        },
    ];
    let prepared = device_plan::prepare_actions_read_only_with_reader_for_mode(
        pool,
        &inputs,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await
    .unwrap();
    let mut cfg = Config::default();
    cfg.safety.global_action_rate_limit_count = 3;
    cfg.safety.same_device_cooldown_seconds = 0;
    cfg.safety.configuration_test_devices.push(LabDevice {
        device_id: device,
        host: HOST.into(),
        port: 22,
        pinned_host_fingerprint: PIN.into(),
        action_rate_limit_count: 32,
        action_rate_limit_window_seconds: 600,
    });
    let state = api::AppState {
        pool: pool.clone(),
        config: cfg.clone(),
        cookie_key: Key::from(&[42; 64]),
    };
    let actions = vec![
        BundleAction {
            device_id: device,
            template: policy_template,
            params: inputs[0].canonical_params.clone(),
            reason: "lab proof".into(),
            position: 0,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared[0].clone()),
            original_reroute_id: None,
        },
        BundleAction {
            device_id: device,
            template,
            params: inputs[1].canonical_params.clone(),
            reason: "lab proof".into(),
            position: 1,
            auto_target: None,
            auto_target_low_confidence: None,
            prepared: Some(prepared[1].clone()),
            original_reroute_id: None,
        },
    ];
    let failure_actions = actions.clone();
    let mut eight_lab_actions = Vec::new();
    for position in 0..8_u32 {
        let mut action = actions[usize::from(position >= 4)].clone();
        action.position = position;
        eight_lab_actions.push(action);
    }
    let (budget_status, axum::Json(budget_preview)) =
        manual_mitigations::preview_actions_with_reader_mode(
            &state,
            &actor(user),
            "manual_mitigation",
            None,
            eight_lab_actions.clone(),
            json!({"kind":"manual","name":"Run once"}),
            "eight action lab budget".into(),
            json!({"actions":[],"verification_mode":"configuration_only"}),
            None,
            &MssReader(None, "no-export"),
            VerificationMode::ConfigurationOnly,
        )
        .await;
    assert_eq!(
        budget_status,
        axum::http::StatusCode::OK,
        "{budget_preview}"
    );
    let budget_accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        budget_preview["plan_id"].as_u64().unwrap(),
        budget_preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let reserved: u32 =
        sqlx::query_scalar("SELECT rate_reserved_actions FROM reroute_bundles WHERE id=?")
            .bind(budget_accepted.bundle_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        reserved, 8,
        "lab bundle must reserve its complete eight-action budget atomically"
    );
    let mut twenty_five = Vec::new();
    for position in 0..25_u32 {
        let mut action = eight_lab_actions[(position as usize) % eight_lab_actions.len()].clone();
        action.position = position;
        twenty_five.push(action);
    }
    let (exhausted_status, axum::Json(exhausted_preview)) =
        manual_mitigations::preview_actions_with_reader_mode(
            &state,
            &actor(user),
            "manual_mitigation",
            None,
            twenty_five,
            json!({"kind":"manual","name":"Run once"}),
            "lab budget exhaustion".into(),
            json!({"actions":[],"verification_mode":"configuration_only"}),
            None,
            &MssReader(None, "no-export"),
            VerificationMode::ConfigurationOnly,
        )
        .await;
    assert_eq!(
        exhausted_status,
        axum::http::StatusCode::OK,
        "{exhausted_preview}"
    );
    assert!(
        manual_mitigations::accept_plan(
            &state,
            &actor(user),
            exhausted_preview["plan_id"].as_u64().unwrap(),
            exhausted_preview["preview_token"].as_str().unwrap(),
            "manual_mitigation",
            None,
        )
        .await
        .is_err(),
        "8 reserved plus 25 requested must exceed lab limit 32 atomically"
    );
    sqlx::query("UPDATE reroute_bundles SET state='failed' WHERE id=?")
        .bind(budget_accepted.bundle_id)
        .execute(pool)
        .await
        .unwrap();

    let make_twenty = || {
        (0..20_u32)
            .map(|position| {
                let mut action =
                    eight_lab_actions[(position as usize) % eight_lab_actions.len()].clone();
                action.position = position;
                action
            })
            .collect::<Vec<_>>()
    };
    let preview_actor = actor(user);
    let preview_reader = MssReader(None, "no-export");
    let preview_twenty = |reason: &'static str, actions| {
        manual_mitigations::preview_actions_with_reader_mode(
            &state,
            &preview_actor,
            "manual_mitigation",
            None,
            actions,
            json!({"kind":"manual","name":"Run once"}),
            reason.into(),
            json!({"actions":[],"verification_mode":"configuration_only"}),
            None,
            &preview_reader,
            VerificationMode::ConfigurationOnly,
        )
    };
    let (_, axum::Json(first_twenty)) = preview_twenty("concurrent lab one", make_twenty()).await;
    let (_, axum::Json(second_twenty)) = preview_twenty("concurrent lab two", make_twenty()).await;
    let first_actor = actor(user);
    let second_actor = actor(user);
    let (first_admission, second_admission) = tokio::join!(
        manual_mitigations::accept_plan(
            &state,
            &first_actor,
            first_twenty["plan_id"].as_u64().unwrap(),
            first_twenty["preview_token"].as_str().unwrap(),
            "manual_mitigation",
            None
        ),
        manual_mitigations::accept_plan(
            &state,
            &second_actor,
            second_twenty["plan_id"].as_u64().unwrap(),
            second_twenty["preview_token"].as_str().unwrap(),
            "manual_mitigation",
            None
        ),
    );
    assert_eq!(
        usize::from(first_admission.is_ok()) + usize::from(second_admission.is_ok()),
        1,
        "two concurrent 20-action reservations must not both fit limit 32"
    );
    if let Ok(accepted) = first_admission.or(second_admission) {
        sqlx::query("UPDATE reroute_bundles SET state='failed' WHERE id=?")
            .bind(accepted.bundle_id)
            .execute(pool)
            .await
            .unwrap();
    }

    let mut routing_actions = eight_lab_actions;
    for action in &mut routing_actions {
        let prepared = action.prepared.as_mut().unwrap();
        prepared.verification_mode = VerificationMode::Routing;
        if let Some(inverse) = &mut prepared.inverse {
            inverse.verification_mode = VerificationMode::Routing;
        }
    }
    let (routing_status, axum::Json(routing_preview)) =
        manual_mitigations::preview_actions_with_reader_mode(
            &state,
            &actor(user),
            "manual_mitigation",
            None,
            routing_actions,
            json!({"kind":"manual","name":"Run once"}),
            "routing budget refusal".into(),
            json!({"actions":[],"verification_mode":"routing"}),
            None,
            &MssReader(None, "no-export"),
            VerificationMode::Routing,
        )
        .await;
    assert_eq!(
        routing_status,
        axum::http::StatusCode::OK,
        "{routing_preview}"
    );
    let routing_accept = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        routing_preview["plan_id"].as_u64().unwrap(),
        routing_preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await;
    assert!(
        routing_accept.is_err(),
        "ordinary eight-action routing bundle must still respect global limit 3"
    );
    let implicit_device_state = api::AppState {
        pool: pool.clone(),
        config: Config::default(),
        cookie_key: Key::from(&[42; 64]),
    };
    let (implicit_device_status, implicit_device_preview) =
        manual_mitigations::preview_actions_with_reader_mode(
            &implicit_device_state,
            &actor(user),
            "manual_mitigation",
            None,
            actions.clone(),
            json!({"kind":"manual","name":"Run once"}),
            "lab proof".into(),
            json!({"actions":[],"verification_mode":"configuration_only"}),
            None,
            &MssReader(None, "no-export"),
            VerificationMode::ConfigurationOnly,
        )
        .await;
    assert_eq!(
        implicit_device_status,
        axum::http::StatusCode::OK,
        "every enabled device with a pinned SSH identity is implicitly eligible: {implicit_device_preview:?}"
    );
    let second_device = sqlx::query("INSERT INTO devices(name,hostname,ssh_port,ssh_host_fingerprint,ssh_status,last_ssh_ok_at,ssh_reachable_since) VALUES(?,?,22,?,'reachable',UTC_TIMESTAMP(),DATE_SUB(UTC_TIMESTAMP(),INTERVAL 10 MINUTE))")
        .bind(format!("lab-device-two-{}", uuid::Uuid::new_v4()))
        .bind("192.0.2.43")
        .bind("SHA256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        .execute(pool)
        .await
        .unwrap()
        .last_insert_id();
    let mut multi_device = actions.clone();
    multi_device[1].device_id = second_device;
    multi_device[1].prepared.as_mut().unwrap().device_id = second_device;
    let (multi_status, multi_preview) = manual_mitigations::preview_actions_with_reader_mode(
        &state,
        &actor(user),
        "manual_mitigation",
        None,
        multi_device,
        json!({"kind":"manual","name":"Run once"}),
        "two-router configuration-only proof".into(),
        json!({"actions":[],"verification_mode":"configuration_only"}),
        None,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await;
    assert_eq!(
        multi_status,
        axum::http::StatusCode::OK,
        "{multi_preview:?}"
    );
    let multi_accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        multi_preview["plan_id"].as_u64().unwrap(),
        multi_preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let multi_reserved: u32 =
        sqlx::query_scalar("SELECT rate_reserved_actions FROM reroute_bundles WHERE id=?")
            .bind(multi_accepted.bundle_id)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(multi_reserved, 2);
    sqlx::query("UPDATE reroute_bundles SET state='failed',rate_reserved_actions=0 WHERE id=?")
        .bind(multi_accepted.bundle_id)
        .execute(pool)
        .await
        .unwrap();
    let mut unavailable_target = actions.clone();
    unavailable_target[1].device_id = second_device + 1;
    unavailable_target[1].prepared.as_mut().unwrap().device_id = second_device + 1;
    let (unavailable_status, _) = manual_mitigations::preview_actions_with_reader_mode(
        &state,
        &actor(user),
        "manual_mitigation",
        None,
        unavailable_target,
        json!({"kind":"manual","name":"Run once"}),
        "unavailable target".into(),
        json!({"actions":[],"verification_mode":"configuration_only"}),
        None,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await;
    assert_eq!(
        unavailable_status,
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
    let (status, axum::Json(preview)) = manual_mitigations::preview_actions_with_reader_mode(
        &state,
        &actor(user),
        "manual_mitigation",
        None,
        actions,
        json!({"kind":"manual","name":"Run once"}),
        "lab proof".into(),
        json!({"actions":[],"verification_mode":"configuration_only"}),
        None,
        &MssReader(None, "no-export"),
        VerificationMode::ConfigurationOnly,
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{preview}");
    assert_eq!(preview["verification_mode"], "configuration_only");
    assert_eq!(preview["routing_verified"], false);
    let plan_id = preview["plan_id"].as_u64().unwrap();
    let token = preview["preview_token"].as_str().unwrap();
    assert!(manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan_id,
        "tampered-token",
        "manual_mitigation",
        None
    )
    .await
    .is_err());
    let original_snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    sqlx::query("UPDATE execution_plans SET snapshot_json=JSON_SET(snapshot_json,'$.verification_mode','routing') WHERE id=?")
        .bind(plan_id).execute(pool).await.unwrap();
    assert!(manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan_id,
        token,
        "manual_mitigation",
        None
    )
    .await
    .is_err());
    sqlx::query("UPDATE execution_plans SET snapshot_json=? WHERE id=?")
        .bind(&original_snapshot)
        .bind(plan_id)
        .execute(pool)
        .await
        .unwrap();
    sqlx::query("UPDATE devices SET ssh_host_fingerprint='SHA256:changed' WHERE id=?")
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    assert!(manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan_id,
        token,
        "manual_mitigation",
        None
    )
    .await
    .is_err());
    sqlx::query("UPDATE devices SET ssh_host_fingerprint=? WHERE id=?")
        .bind(PIN)
        .bind(device)
        .execute(pool)
        .await
        .unwrap();
    let accepted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        plan_id,
        token,
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(accepted.plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let actions: Vec<BundleAction> = serde_json::from_value(snapshot.0["actions"].clone()).unwrap();
    assert!(actions
        .iter()
        .all(|a| a.prepared.as_ref().unwrap().verification_mode
            == VerificationMode::ConfigurationOnly));
    let ssh = StatefulMssSsh {
        state: Arc::new(Mutex::new(("no-export".into(), None))),
        device,
        fail_mss: false,
    };
    let run = bundle::BundleRun::manual(
        accepted.bundle_id,
        FailurePolicy::AbortAndCompensate,
        None,
        user,
        ActorContext {
            ip_address: "127.0.0.1".into(),
            user_agent: "test".into(),
        },
    )
    .with_authorization(Some(accepted.plan_id), format!("plan:{}", accepted.plan_id));
    let outcome = bundle::run_with_ssh(pool, &cfg, run, actions, &ssh).await;
    assert_eq!(outcome.state, "succeeded", "{:?}", outcome.failure_reason);
    assert_eq!(
        *ssh.state.lock().unwrap(),
        ("pfx-to-viva".into(), Some(1400))
    );
    let stored: Vec<sqlx::types::Json<Value>> = sqlx::query_scalar(
        "SELECT prepared_action_json FROM reroute_bundle_actions WHERE bundle_id=?",
    )
    .bind(accepted.bundle_id)
    .fetch_all(pool)
    .await
    .unwrap();
    assert!(stored
        .iter()
        .all(|value| value.0["verification_mode"] == "configuration_only"));

    let originals: Vec<u64> = sqlx::query_scalar(
        "SELECT id FROM reroutes WHERE bundle_id=? AND rollback_of_reroute_id IS NULL ORDER BY bundle_position DESC",
    )
    .bind(accepted.bundle_id)
    .fetch_all(pool)
    .await
    .unwrap();
    let inverse_actions = rerouter_controller::reroute::preparation::prepare_rollbacks(
        pool,
        &originals,
        "explicit lab revert",
        false,
    )
    .await
    .unwrap();
    assert!(inverse_actions.iter().all(|action| {
        action.prepared.as_ref().unwrap().verification_mode == VerificationMode::ConfigurationOnly
    }));
    let source = accepted.bundle_id;
    let (status, axum::Json(revert_preview)) =
        manual_mitigations::preview_actions_with_reader(
            &state,
            &actor(user),
            "bundle_revert",
            Some(source),
            inverse_actions,
            json!({"kind":"bundle_revert","original_bundle_id":source,"original_reroute_ids":originals}),
            "explicit lab revert".into(),
            json!({"original_bundle_id":source,"reason":"explicit lab revert"}),
            None,
            &MssReader(Some(1400), "pfx-to-viva"),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{revert_preview}");
    assert_eq!(revert_preview["verification_mode"], "configuration_only");
    let reverted = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        revert_preview["plan_id"].as_u64().unwrap(),
        revert_preview["preview_token"].as_str().unwrap(),
        "bundle_revert",
        Some(source),
    )
    .await
    .unwrap();
    let revert_snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(reverted.plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let revert_actions: Vec<BundleAction> =
        serde_json::from_value(revert_snapshot.0["actions"].clone()).unwrap();
    let revert_run = bundle::BundleRun::rollback(
        reverted.bundle_id,
        FailurePolicy::AbortAndCompensate,
        user,
        ActorContext {
            ip_address: "127.0.0.1".into(),
            user_agent: "test".into(),
        },
    )
    .with_authorization(Some(reverted.plan_id), format!("plan:{}", reverted.plan_id));
    let revert_outcome = bundle::run_with_ssh(pool, &cfg, revert_run, revert_actions, &ssh).await;
    assert_eq!(
        revert_outcome.state, "succeeded",
        "{:?}",
        revert_outcome.failure_reason
    );
    assert_eq!(*ssh.state.lock().unwrap(), ("no-export".into(), None));
    let stale_memberships: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM device_change_window_sources WHERE device_id=?")
            .bind(device)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        stale_memberships, 0,
        "successful revert must release every source membership before the next run"
    );

    let (failure_status, axum::Json(failure_preview)) =
        manual_mitigations::preview_actions_with_reader_mode(
            &state,
            &actor(user),
            "manual_mitigation",
            None,
            failure_actions,
            json!({"kind":"manual","name":"Run once"}),
            "compensation proof".into(),
            json!({"actions":[],"verification_mode":"configuration_only"}),
            None,
            &MssReader(None, "no-export"),
            VerificationMode::ConfigurationOnly,
        )
        .await;
    assert_eq!(
        failure_status,
        axum::http::StatusCode::OK,
        "{failure_preview}"
    );
    let failed_accept = manual_mitigations::accept_plan(
        &state,
        &actor(user),
        failure_preview["plan_id"].as_u64().unwrap(),
        failure_preview["preview_token"].as_str().unwrap(),
        "manual_mitigation",
        None,
    )
    .await
    .unwrap();
    let failed_snapshot: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT snapshot_json FROM execution_plans WHERE id=?")
            .bind(failed_accept.plan_id)
            .fetch_one(pool)
            .await
            .unwrap();
    let failed_actions: Vec<BundleAction> =
        serde_json::from_value(failed_snapshot.0["actions"].clone()).unwrap();
    let failing_ssh = StatefulMssSsh {
        state: Arc::new(Mutex::new(("no-export".into(), None))),
        device,
        fail_mss: true,
    };
    let failure_run = bundle::BundleRun::manual(
        failed_accept.bundle_id,
        FailurePolicy::AbortAndCompensate,
        None,
        user,
        ActorContext {
            ip_address: "127.0.0.1".into(),
            user_agent: "test".into(),
        },
    )
    .with_authorization(
        Some(failed_accept.plan_id),
        format!("plan:{}", failed_accept.plan_id),
    );
    let failed_outcome =
        bundle::run_with_ssh(pool, &cfg, failure_run, failed_actions, &failing_ssh).await;
    assert_eq!(
        failed_outcome.state, "compensated",
        "{:?}",
        failed_outcome.failure_reason
    );
    assert_eq!(
        *failing_ssh.state.lock().unwrap(),
        ("no-export".into(), None)
    );
    let original_policy: (u64, String, String) = sqlx::query_as(
        "SELECT id,state,mutation_effect FROM reroutes WHERE bundle_id=? AND bundle_position=0 AND rollback_of_reroute_id IS NULL"
    ).bind(failed_accept.bundle_id).fetch_one(pool).await.unwrap();
    assert_eq!(
        (&original_policy.1[..], &original_policy.2[..]),
        ("succeeded", "changed")
    );
    let inverse: (String, String, sqlx::types::Json<Value>) = sqlx::query_as(
        "SELECT state,mutation_effect,planned_steps_json FROM reroutes WHERE rollback_of_reroute_id=?"
    ).bind(original_policy.0).fetch_one(pool).await.unwrap();
    assert_eq!((&inverse.0[..], &inverse.1[..]), ("succeeded", "changed"));
    assert!(inverse.2 .0["commands"]
        .as_array()
        .is_some_and(|commands| commands.iter().any(|command| command
            .as_str()
            .is_some_and(|line| line.contains("prefix-list no-export out")))));
    let original_inverse: sqlx::types::Json<Value> =
        sqlx::query_scalar("SELECT rollback_snapshot_json FROM reroutes WHERE id=?")
            .bind(original_policy.0)
            .fetch_one(pool)
            .await
            .unwrap();
    assert_eq!(
        original_inverse.0["verification_mode"],
        "configuration_only"
    );

    sqlx::query("DELETE FROM users WHERE id=?")
        .bind(user)
        .execute(pool)
        .await
        .ok();
}

#[test]
fn inverse_scope_mismatch_is_refused() {
    let mut action = device_plan::PreparedDeviceAction {
        schema_version: 1,
        device_id: 1,
        template_id: 1,
        template_name: "iface_tcp_adjust_mss".into(),
        canonical_params: json!({}),
        verification_mode: VerificationMode::ConfigurationOnly,
        commands: vec!["configure terminal".into()],
        before: vec![device_plan::DeviceStateSnapshot::InterfaceMss {
            interface: "Po1".into(),
            mss: None,
        }],
        after: vec![device_plan::DeviceStateSnapshot::InterfaceMss {
            interface: "Po1".into(),
            mss: Some(1400),
        }],
        verify: vec![device_plan::DeviceStateSnapshot::InterfaceMss {
            interface: "Po1".into(),
            mss: Some(1400),
        }],
        effect: device_plan::PreparedEffect::Change,
        inverse: None,
        prepared_at: Utc::now(),
    };
    action.inverse = Some(device_plan::PreparedInverse {
        verification_mode: VerificationMode::Routing,
        expected_current: action.after.clone(),
        restore: action.before.clone(),
        commands: vec!["no ip tcp adjust-mss".into()],
        verify: action.before.clone(),
    });
    assert!(action.validate().is_err());
}
