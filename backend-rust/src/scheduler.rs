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

/// interface_samples retention: keep a little over the last hour, so the 60-min
/// detail-page view is always complete. Telemetry is intentionally short-lived.
const SAMPLE_RETENTION_MINUTES: i64 = 70;
/// How often to prune old samples.
const PRUNE_INTERVAL: Duration = Duration::from_secs(600);

/// Spawn the scheduler supervisor + the sample-retention pruner; return. Never
/// blocks the control plane.
pub async fn run(pool: MySqlPool, cfg: Config) -> Result<()> {
    let cfg = Arc::new(cfg);
    tokio::spawn(prune_samples(pool.clone()));
    tokio::spawn(discover_prefixes_daily(pool.clone()));
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

/// Periodically delete interface_samples older than the retention window (so the
/// table only ever holds ~the last hour of per-interface telemetry) and drop
/// flow exporters that have gone silent for over a day.
async fn prune_samples(pool: MySqlPool) {
    loop {
        match sqlx::query(
            "DELETE FROM interface_samples WHERE sampled_at < DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? MINUTE)",
        )
        .bind(SAMPLE_RETENTION_MINUTES)
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::debug!(event_type = "samples_pruned", rows = r.rows_affected(), "pruned old interface_samples")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(event_type = "sample_prune_failed", error = %e, "pruning interface_samples failed"),
        }

        // Drop flow exporters idle for >1 day so the exporter-health view doesn't
        // accumulate stale entries (their buckets are already gone via retention;
        // the FK cascade covers any remainder). COALESCE handles an exporter row
        // that was created but never sent a datagram.
        match sqlx::query(
            "DELETE FROM flow_exporters \
             WHERE COALESCE(last_packet_at, created_at) < DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)",
        )
        .execute(&pool)
        .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(event_type = "flow_exporters_pruned", rows = r.rows_affected(), "pruned stale flow exporters (>1d idle)")
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(event_type = "exporter_prune_failed", error = %e, "pruning flow_exporters failed"),
        }

        tokio::time::sleep(PRUNE_INTERVAL).await;
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
