//! Per-device async SNMP poller + detection driver.
//!
//! One supervised task per enabled device runs an independent loop: SNMP poll
//! (store interface_metrics_current + interface_samples) -> run detection for
//! that device's monitored interfaces. Each loop uses the device's
//! `poll_interval_seconds` plus +/- jitter (telemetry.jitter_percent) so polls
//! de-synchronize across devices. A per-device failure is logged and the loop
//! keeps going (the device is marked unreachable by the poller).
//!
//! A supervisor reloads the enabled-device set every RELOAD_INTERVAL and spawns
//! loops for new devices / drops loops for removed-or-disabled ones, so adding a
//! device from the API starts polling it without a restart.
//!
//! `run` spawns the supervisor and returns immediately so the caller can then
//! start the API server (the loops live for the process lifetime).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use rand::Rng;
use sqlx::MySqlPool;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::detection;
use crate::telemetry::{flow, snmp};

/// How often the supervisor reconciles the running loops against the DB.
const RELOAD_INTERVAL: Duration = Duration::from_secs(30);

/// How often the retention cleanup runs.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// Spawn the scheduler supervisor + the retention cleanup task; return. Never
/// blocks the control plane.
pub async fn run(pool: MySqlPool, cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    tokio::spawn(retention_cleanup(pool.clone(), cfg.clone()));
    tokio::spawn(discover_prefixes_daily(pool.clone()));
    tokio::spawn(evaluate_aggregate_loop(pool.clone(), cfg.clone()));
    // NetFlow/IPFIX flow collector — a SECOND, read-only telemetry source. No-op
    // unless [flow].enabled; binds its own UDP socket (see docs/flow-telemetry.md).
    tokio::spawn(flow::collector::run(pool.clone(), cfg.clone()));
    tokio::spawn(supervise(pool, cfg));
    tracing::info!(
        event_type = "scheduler_started",
        "scheduler supervisor spawned (per-device SNMP poll loops)"
    );
    Ok(())
}

/// How often to revalidate announced prefixes over SSH.
const PREFIX_DISCOVERY_INTERVAL: Duration = Duration::from_secs(24 * 3600);

/// Discover each device's announced BGP prefixes over SSH, shortly after boot and
/// then daily. Best-effort: a device without working SSH is logged and skipped
/// (manual "Discover prefixes" remains available). The SNMP-cached ASN/neighbors
/// refresh every poll, so only the SSH-sourced prefixes need this slow loop.
async fn discover_prefixes_daily(pool: MySqlPool) {
    tokio::time::sleep(Duration::from_secs(120)).await; // let the box settle after boot
    loop {
        match snmp::load_enabled_devices(&pool).await {
            Ok(devices) => {
                for d in devices {
                    match crate::ssh::discover_prefixes_and_store(&pool, d.id).await {
                        Ok(n) => tracing::debug!(
                            event_type = "prefix_discovery",
                            device_id = d.id,
                            prefixes = n,
                            "announced prefixes refreshed"
                        ),
                        Err(e) => {
                            tracing::debug!(event_type = "prefix_discovery_failed", device_id = d.id, error = %e, "announced-prefix discovery failed (non-fatal)")
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!(event_type = "prefix_discovery_load_failed", error = %e, "could not load devices for prefix discovery")
            }
        }
        tokio::time::sleep(PREFIX_DISCOVERY_INTERVAL).await;
    }
}

/// One day-windowed retention rule: delete rows whose `ts_column` is older than
/// `days`. `table`/`ts_column` are compile-time constants (never user input), so
/// they are safe to interpolate into the DELETE.
struct RetentionSpec {
    table: &'static str,
    ts_column: &'static str,
    days: u32,
}

/// Build the day-windowed retention rules from `[retention]` config. Pure (no
/// I/O) so the mapping from config to prune targets is unit-testable.
///
/// Actively-pruned tables only: interface_samples (SNMP), the four flow_*_buckets
/// (NetFlow/sFlow), alerts, and rule_events (detection history) — the short-term
/// telemetry + protection history. The `reroutes` action log and `audit_logs` are
/// deliberately excluded: low-volume safety/security trails, and `reroutes` rows
/// are live state-machine state (an `uncertain` reroute holds a device lock), so
/// they need state-aware pruning, not a blanket time delete.
fn retention_specs(cfg: &Config) -> Vec<RetentionSpec> {
    let r = &cfg.retention;
    let mut specs = vec![RetentionSpec {
        table: "interface_samples",
        ts_column: "sampled_at",
        days: r.traffic_samples_days,
    }];
    for table in [
        "flow_iface_buckets",
        "flow_port_buckets",
        "flow_as_buckets",
        "flow_talker_buckets",
    ] {
        specs.push(RetentionSpec {
            table,
            ts_column: "bucket_ts",
            days: r.flow_buckets_days,
        });
    }
    specs.push(RetentionSpec {
        table: "alerts",
        ts_column: "created_at",
        days: r.alerts_days,
    });
    specs.push(RetentionSpec {
        table: "rule_events",
        ts_column: "created_at",
        days: r.rule_events_days,
    });
    specs
}

/// Periodically enforce the configured retention windows: delete telemetry
/// (interface_samples + flow_*_buckets), alerts, and rule_events older than their
/// window, and drop flow exporters that have gone silent longer than the flow
/// bucket window. A single task owns all retention so the policy has one place to
/// reason about.
async fn retention_cleanup(pool: MySqlPool, cfg: Arc<Config>) {
    let specs = retention_specs(&cfg);
    // Exporters are dropped only once they have been idle LONGER than the flow
    // bucket retention window (+1 day of margin). flow_*_buckets cascade-delete
    // from flow_exporters, so dropping an exporter whose buckets are still inside
    // the window would silently destroy still-retained flow history. Waiting past
    // the window means the bucket prune above has already removed them.
    let exporter_idle_days = cfg.retention.flow_buckets_days.max(1).saturating_add(1);
    loop {
        for spec in &specs {
            // Floor at 1 day so a misconfigured 0 can never mean "delete now".
            let days = spec.days.max(1);
            // SAFETY: table/ts_column are 'static literals from our own code.
            let sql = format!(
                "DELETE FROM {} WHERE {} < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)",
                spec.table, spec.ts_column
            );
            match sqlx::query(&sql).bind(days).execute(&pool).await {
                Ok(r) if r.rows_affected() > 0 => tracing::debug!(
                    event_type = "retention_pruned",
                    table = spec.table,
                    days,
                    rows = r.rows_affected(),
                    "pruned rows past retention window"
                ),
                Ok(_) => {}
                Err(e) => tracing::warn!(event_type = "retention_prune_failed", table = spec.table, error = %e, "retention prune failed"),
            }
        }

        // Drop flow exporters that have been idle past the flow bucket window (see
        // `exporter_idle_days` above) so the exporter-health view doesn't
        // accumulate stale entries. By now the bucket prune has removed their
        // buckets, so the ON DELETE CASCADE has nothing left to take. COALESCE
        // handles an exporter row created but that never sent a datagram.
        match sqlx::query(
            "DELETE FROM flow_exporters \
             WHERE COALESCE(last_packet_at, created_at) < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? DAY)",
        )
        .bind(exporter_idle_days)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(event_type = "flow_exporters_pruned", rows = r.rows_affected(), days = exporter_idle_days, "pruned stale flow exporters (idle past flow window)")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(event_type = "exporter_prune_failed", error = %e, "pruning flow_exporters failed"),
        }

        tokio::time::sleep(PRUNE_INTERVAL).await;
    }
}

/// How often to evaluate cross-interface/cross-device `sum` rules. These have no
/// owning device loop, so a single global loop drives them. The cadence tracks
/// the default poll interval; member freshness is enforced inside the engine.
const AGGREGATE_EVAL_INTERVAL: Duration = Duration::from_secs(15);

/// Evaluate aggregate (`metric_aggregation = 'sum'`) rules forever. Read-only and
/// observe-safe: like every rule path it only renders would-run plans unless the
/// controller is in enforce mode with the global + per-rule auto switches on.
async fn evaluate_aggregate_loop(pool: MySqlPool, cfg: Arc<Config>) {
    // Let device loops populate interface_metrics_current before the first pass.
    tokio::time::sleep(Duration::from_secs(20)).await;
    loop {
        match detection::engine::evaluate_aggregate_rules(&pool, &cfg).await {
            Ok(fired) if fired > 0 => {
                tracing::info!(event_type = "aggregate_detection", fired, "aggregate rules fired")
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(event_type = "aggregate_detection_failed", error = %e, "aggregate rule evaluation failed")
            }
        }
        tokio::time::sleep(AGGREGATE_EVAL_INTERVAL).await;
    }
}

/// Reconcile per-device poll loops with the set of enabled devices, forever.
async fn supervise(pool: MySqlPool, cfg: Arc<Config>) {
    let mut running: HashMap<u64, JoinHandle<()>> = HashMap::new();

    loop {
        match snmp::load_enabled_devices(&pool).await {
            Ok(devices) => {
                let enabled_ids: std::collections::HashSet<u64> =
                    devices.iter().map(|d| d.id).collect();

                // Drop loops for devices that are gone, disabled, or finished.
                running.retain(|id, handle| {
                    if !enabled_ids.contains(id) || handle.is_finished() {
                        handle.abort();
                        false
                    } else {
                        true
                    }
                });

                // Spawn loops for newly enabled devices.
                for dev in devices {
                    running.entry(dev.id).or_insert_with(|| {
                        let pool = pool.clone();
                        let cfg = cfg.clone();
                        let device_id = dev.id;
                        let interval = dev.poll_interval_seconds.max(5);
                        tracing::info!(
                            event_type = "device_loop_started",
                            device_id,
                            interval_seconds = interval,
                            "starting SNMP poll loop"
                        );
                        tokio::spawn(device_loop(pool, cfg, device_id, interval))
                    });
                }
            }
            Err(e) => {
                tracing::warn!(event_type = "scheduler_reload_failed", error = %e, "could not reload device list");
            }
        }
        tokio::time::sleep(RELOAD_INTERVAL).await;
    }
}

/// One device's poll+detect loop. Tolerates per-tick failure; a poll error is
/// already recorded as the device's last_error by the poller.
async fn device_loop(pool: MySqlPool, cfg: Arc<Config>, device_id: u64, base_interval_secs: u32) {
    // Small initial spread so freshly-spawned loops don't all fire at t=0.
    let initial = jittered(base_interval_secs, cfg.telemetry.jitter_percent);
    tokio::time::sleep(Duration::from_millis((initial * 1000.0) as u64 / 4)).await;

    loop {
        let tick = poll_and_detect(&pool, &cfg, device_id).await;
        if let Err(e) = tick {
            tracing::warn!(event_type = "device_tick_failed", device_id, error = %e, "device poll/detect tick failed");
        }
        let secs = jittered(base_interval_secs, cfg.telemetry.jitter_percent);
        tokio::time::sleep(Duration::from_millis((secs * 1000.0) as u64)).await;
    }
}

/// One poll + detection pass for a device. Detection runs even if some
/// interfaces had no fresh sample (the engine filters stale/invalid itself).
async fn poll_and_detect(pool: &MySqlPool, cfg: &Config, device_id: u64) -> Result<()> {
    // Poll: stores interface_metrics_current + interface_samples. A transport
    // failure marks the device unreachable and returns Err — detection then has
    // nothing fresh and harmlessly no-ops.
    match snmp::poll(pool, device_id).await {
        Ok(updated) => {
            tracing::debug!(
                event_type = "device_polled",
                device_id,
                interfaces = updated,
                "poll complete"
            );
        }
        Err(e) => {
            // Already recorded as last_error; surface and skip detection.
            return Err(e);
        }
    }

    // Refresh BGP session state (read-only; keeps the UI's session up/down live).
    // Best-effort: a device that doesn't run BGP (or lacks BGP4-MIB) is a no-op,
    // and a transport error here must not block detection.
    if let Err(e) = snmp::discover_bgp_and_store(pool, device_id).await {
        tracing::debug!(event_type = "bgp_discover_failed", device_id, error = %e, "BGP peer discovery failed (non-fatal)");
    }

    // Detection for this device's monitored interfaces.
    match detection::engine::evaluate_device(pool, cfg, device_id).await {
        Ok(fired) if fired > 0 => {
            tracing::info!(
                event_type = "device_detection",
                device_id,
                fired,
                "rules fired on poll"
            );
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(event_type = "detection_failed", device_id, error = %e, "detection pass failed")
        }
    }
    Ok(())
}

/// Apply +/- jitter_percent to an interval (seconds), clamped to a sane floor.
fn jittered(base_secs: u32, jitter_percent: u8) -> f64 {
    let base = base_secs.max(1) as f64;
    if jitter_percent == 0 {
        return base;
    }
    let frac = jitter_percent.min(90) as f64 / 100.0;
    let delta = rand::rng().random_range(-frac..=frac);
    (base * (1.0 + delta)).max(1.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retention_specs_map_config_windows_to_tables() {
        let mut cfg = Config::default();
        cfg.retention.traffic_samples_days = 3;
        cfg.retention.flow_buckets_days = 5;
        cfg.retention.alerts_days = 9;
        cfg.retention.rule_events_days = 4;

        let specs = retention_specs(&cfg);

        // interface_samples + 4 flow bucket tables + alerts + rule_events.
        assert_eq!(specs.len(), 7);
        let by_table = |t: &str| {
            specs
                .iter()
                .find(|s| s.table == t)
                .unwrap_or_else(|| panic!("no retention spec for {t}"))
        };

        let samples = by_table("interface_samples");
        assert_eq!(samples.ts_column, "sampled_at");
        assert_eq!(samples.days, 3, "SNMP samples use traffic_samples_days");

        for t in [
            "flow_iface_buckets",
            "flow_port_buckets",
            "flow_as_buckets",
            "flow_talker_buckets",
        ] {
            let s = by_table(t);
            assert_eq!(s.ts_column, "bucket_ts", "{t} prunes on bucket_ts");
            assert_eq!(s.days, 5, "{t} uses flow_buckets_days");
        }

        let alerts = by_table("alerts");
        assert_eq!(alerts.ts_column, "created_at");
        assert_eq!(alerts.days, 9, "alerts use alerts_days");

        let rule_events = by_table("rule_events");
        assert_eq!(rule_events.ts_column, "created_at");
        assert_eq!(rule_events.days, 4, "rule_events use rule_events_days");
    }
}
