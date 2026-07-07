//! Device reachability for mitigations — the "can we mitigate this device right
//! now?" decision that gates a reroute (see [`super::executor`]).
//!
//! A reroute pushes config over SSH, so the AUTHORITATIVE signal is: does SSH
//! answer commands? We probe it with a no-op liveness session ([`ssh::ssh_probe`]:
//! connect → auth → privileged EXEC → `terminal length 0` → exit, pushing no
//! config). A telnet port-open check is kept as an INFORMATIONAL secondary signal
//! (shown in the UI, updated by the periodic poll loop) and never gates — many
//! hardened routers disable telnet entirely.
//!
//! To avoid re-probing a device we just talked to — and to avoid tripping the
//! device's SSH connection throttle during a storm — a successful SSH contact
//! within [`RECENCY_WINDOW`] counts as reachable without opening a new session.
//! `devices.last_ssh_ok_at` is stamped by both this probe and every successful
//! reroute push, so bursts of activity keep the window warm.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::MySqlPool;

use crate::ssh;

/// A successful SSH contact newer than this satisfies the gate without re-probing
/// (honors the operator's "sau în ultimul minut a răspuns" rule).
pub const RECENCY_WINDOW: Duration = Duration::from_secs(60);

/// The reachability decision for a device.
#[derive(Debug, Clone, Serialize)]
pub struct Reachability {
    /// SSH answered commands — THIS is what gates a reroute. True when a live
    /// probe just succeeded, or a real SSH contact happened within `RECENCY_WINDOW`.
    pub ssh_ok: bool,
    /// Telnet port accepted a TCP connection at the last periodic probe.
    /// Informational only — never gates.
    pub telnet_open: bool,
    /// True when `ssh_ok` was satisfied by a recent contact rather than a fresh probe.
    pub via_recency: bool,
    /// When SSH last answered (the recency source), if known.
    pub last_ssh_ok_at: Option<DateTime<Utc>>,
    /// Structured reason when SSH did not answer (probe error), for the UI/logs.
    /// Never contains secrets.
    pub ssh_error: Option<String>,
}

/// PURE recency test: is a last-known-good SSH contact still fresh enough to skip
/// the probe? A timestamp in the future (clock skew) or unknown is treated as not
/// recent, so we fall through to a live probe — the safe direction. Unit-tested.
pub fn recent_enough(last_ssh_ok_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match last_ssh_ok_at {
        Some(t) => {
            let secs = now.signed_duration_since(t).num_seconds();
            secs >= 0 && (secs as u64) < RECENCY_WINDOW.as_secs()
        }
        None => false,
    }
}

/// Decide reachability for a mitigation on `device_id`. SSH is authoritative:
/// pass on a recent contact, otherwise run a live liveness probe (and stamp
/// `last_ssh_ok_at` on success). `telnet_open` is read from the cached
/// periodic-probe column and reported but never gates.
pub async fn reachable_for_mitigation(pool: &MySqlPool, device_id: u64) -> Reachability {
    let (last_ssh_ok_at, telnet_open) =
        sqlx::query_as::<_, (Option<DateTime<Utc>>, bool)>(
            "SELECT last_ssh_ok_at, telnet_reachable FROM devices WHERE id = ?",
        )
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or((None, false));

    let now = Utc::now();
    if recent_enough(last_ssh_ok_at, now) {
        return Reachability {
            ssh_ok: true,
            telnet_open,
            via_recency: true,
            last_ssh_ok_at,
            ssh_error: None,
        };
    }

    // Live SSH liveness probe: connect + confirm privileged EXEC, run no commands.
    match ssh::ssh_probe(pool, device_id).await {
        Ok(()) => {
            stamp_ssh_result(pool, device_id, true).await;
            Reachability {
                ssh_ok: true,
                telnet_open,
                via_recency: false,
                last_ssh_ok_at: Some(now),
                ssh_error: None,
            }
        }
        Err(e) => {
            // Record the failure so the displayed ssh_reachable reflects it (the
            // recency timestamp is left untouched — it means "last SUCCESS").
            stamp_ssh_result(pool, device_id, false).await;
            Reachability {
                ssh_ok: false,
                telnet_open,
                via_recency: false,
                last_ssh_ok_at,
                ssh_error: Some(e.to_string()),
            }
        }
    }
}

/// Record an SSH probe outcome on `device_id`. On success sets `ssh_reachable = 1`
/// and stamps `last_ssh_ok_at` (keeping the reroute-gate recency window warm); on
/// failure sets `ssh_reachable = 0` and leaves `last_ssh_ok_at` (which means "last
/// time SSH answered") unchanged. Best-effort.
pub async fn stamp_ssh_result(pool: &MySqlPool, device_id: u64, ok: bool) {
    let sql = if ok {
        "UPDATE devices SET ssh_reachable = 1, last_ssh_ok_at = UTC_TIMESTAMP() WHERE id = ?"
    } else {
        "UPDATE devices SET ssh_reachable = 0 WHERE id = ?"
    };
    let _ = sqlx::query(sql).bind(device_id).execute(pool).await;
}

/// Record that SSH just answered on `device_id` (e.g. a successful reroute push) —
/// keeps the recency window warm and marks the device SSH-reachable.
pub async fn stamp_ssh_ok(pool: &MySqlPool, device_id: u64) {
    stamp_ssh_result(pool, device_id, true).await;
}

/// Periodic SSH liveness probe (the poll loop calls this every
/// `reachability_interval_seconds`). Opens a no-command SSH session and records the
/// outcome in `ssh_reachable` (+ `last_ssh_ok_at` on success), so the UI shows a
/// definite SSH reachable/unreachable state and the reroute gate's recency window
/// is kept warm without an on-demand probe. Returns the outcome for logging.
pub async fn probe_ssh_and_store(pool: &MySqlPool, device_id: u64) -> bool {
    let ok = ssh::ssh_probe(pool, device_id).await.is_ok();
    stamp_ssh_result(pool, device_id, ok).await;
    ok
}

/// Periodic telnet TCP port-open probe (INFORMATIONAL). Reads the device host +
/// `telnet_port`, checks whether the port accepts a connection, and stores the
/// result on the device row (`telnet_reachable` + `last_telnet_ok_at`). Called
/// from the poll loop; best-effort, never errors, sends nothing to the device CLI.
/// This signal is displayed but NEVER gates a reroute — SSH is authoritative.
pub async fn probe_telnet(pool: &MySqlPool, device_id: u64) {
    let Some((host, port)) =
        sqlx::query_as::<_, (String, u16)>("SELECT hostname, telnet_port FROM devices WHERE id = ?")
            .bind(device_id)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
    else {
        return;
    };
    if crate::telemetry::telnet::telnet_open(&host, port).await {
        let _ = sqlx::query(
            "UPDATE devices SET telnet_reachable = 1, last_telnet_ok_at = UTC_TIMESTAMP() WHERE id = ?",
        )
        .bind(device_id)
        .execute(pool)
        .await;
    } else {
        let _ = sqlx::query("UPDATE devices SET telnet_reachable = 0 WHERE id = ?")
            .bind(device_id)
            .execute(pool)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration as ChronoDuration;

    #[test]
    fn recency_window_gates_probe_skip() {
        let now = Utc::now();
        // A contact 30s ago is recent enough to skip the probe.
        assert!(recent_enough(Some(now - ChronoDuration::seconds(30)), now));
        // Exactly at / past the 60s window is NOT recent (re-probe).
        assert!(!recent_enough(Some(now - ChronoDuration::seconds(60)), now));
        assert!(!recent_enough(Some(now - ChronoDuration::seconds(120)), now));
        // Never-contacted -> not recent.
        assert!(!recent_enough(None, now));
        // Future timestamp (clock skew) -> treated as not recent (safe: re-probe).
        assert!(!recent_enough(Some(now + ChronoDuration::seconds(10)), now));
    }
}
