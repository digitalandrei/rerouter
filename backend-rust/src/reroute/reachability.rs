//! Device reachability for mitigations — the "can we mitigate this device right
//! now?" decision that gates a reroute (see [`super::executor`]).
//!
//! A reroute pushes config over SSH, so the AUTHORITATIVE signal is: does SSH
//! answer commands at privileged EXEC? We probe it with a no-op liveness session
//! ([`ssh::ssh_probe`]: connect → auth → prompt → `terminal length 0` → exit,
//! pushing no config), classified into three states:
//!
//! * `reachable` — answered at `#`; usable for a reroute.
//! * `no_privilege` — SSH connected + authenticated but landed at `>`; the account
//!   lacks privilege 15 (an actionable config fix, not a connectivity problem).
//!   Not usable for a reroute.
//! * `unreachable` — could not connect / authenticate / reach a prompt.
//!
//! To avoid re-probing a device we just talked to — and to avoid tripping the
//! device's SSH connection throttle — a successful SSH contact within
//! [`RECENCY_WINDOW`] counts as reachable without opening a new session.
//! `devices.last_ssh_ok_at` is stamped only on a `reachable` outcome (a real
//! privileged success) — by this probe and by every successful reroute push.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::MySqlPool;

use crate::ssh::{self, SshReach};

/// A successful SSH contact newer than this satisfies the gate without re-probing
/// (honors the operator's "sau în ultimul minut a răspuns" rule).
pub const RECENCY_WINDOW: Duration = Duration::from_secs(60);

/// Persisted SSH reachability states (also the `devices.ssh_status` values).
pub const STATUS_REACHABLE: &str = "reachable";
pub const STATUS_NO_PRIVILEGE: &str = "no_privilege";
pub const STATUS_UNREACHABLE: &str = "unreachable";

/// The reachability decision for a device.
#[derive(Debug, Clone, Serialize)]
pub struct Reachability {
    /// SSH is usable for a reroute (answered at privileged EXEC, or a real contact
    /// within `RECENCY_WINDOW`). THIS is what gates a reroute. `no_privilege` and
    /// `unreachable` are both `false`.
    pub ssh_ok: bool,
    /// The classified SSH state: `reachable` | `no_privilege` | `unreachable`.
    pub ssh_status: &'static str,
    /// True when `ssh_ok` was satisfied by a recent contact rather than a fresh probe.
    pub via_recency: bool,
    /// When SSH last answered at privileged EXEC (the recency source), if known.
    pub last_ssh_ok_at: Option<DateTime<Utc>>,
    /// The probe's message when not reachable, for the UI/logs. Never secrets.
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

/// Decide reachability for a mitigation on `device_id`. SSH is authoritative: pass
/// on a recent privileged contact, otherwise run a live liveness probe and record
/// the classified outcome.
pub async fn reachable_for_mitigation(pool: &MySqlPool, device_id: u64) -> Reachability {
    let last_ssh_ok_at = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT last_ssh_ok_at FROM devices WHERE id = ?",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten();

    let now = Utc::now();
    if recent_enough(last_ssh_ok_at, now) {
        return Reachability {
            ssh_ok: true,
            ssh_status: STATUS_REACHABLE,
            via_recency: true,
            last_ssh_ok_at,
            ssh_error: None,
        };
    }

    // Live SSH liveness probe (no commands), classified.
    match ssh::ssh_probe(pool, device_id).await {
        SshReach::Privileged => {
            stamp_ssh_status(pool, device_id, STATUS_REACHABLE, None).await;
            Reachability {
                ssh_ok: true,
                ssh_status: STATUS_REACHABLE,
                via_recency: false,
                last_ssh_ok_at: Some(now),
                ssh_error: None,
            }
        }
        SshReach::UserExec(msg) => {
            stamp_ssh_status(pool, device_id, STATUS_NO_PRIVILEGE, Some(&msg)).await;
            Reachability {
                ssh_ok: false,
                ssh_status: STATUS_NO_PRIVILEGE,
                via_recency: false,
                last_ssh_ok_at,
                ssh_error: Some(msg),
            }
        }
        SshReach::Unreachable(msg) => {
            stamp_ssh_status(pool, device_id, STATUS_UNREACHABLE, Some(&msg)).await;
            Reachability {
                ssh_ok: false,
                ssh_status: STATUS_UNREACHABLE,
                via_recency: false,
                last_ssh_ok_at,
                ssh_error: Some(msg),
            }
        }
    }
}

/// Persist an SSH probe outcome on `device_id`. On `reachable` also stamps
/// `last_ssh_ok_at` (keeping the reroute-gate recency window warm) and clears the
/// error; otherwise records `last_ssh_error` and leaves `last_ssh_ok_at` (which
/// means "last time SSH answered at privileged EXEC") unchanged. Best-effort.
pub async fn stamp_ssh_status(
    pool: &MySqlPool,
    device_id: u64,
    status: &str,
    err: Option<&str>,
) {
    let _ = if status == STATUS_REACHABLE {
        sqlx::query(
            "UPDATE devices SET ssh_status = ?, last_ssh_error = NULL, last_ssh_ok_at = UTC_TIMESTAMP() WHERE id = ?",
        )
        .bind(status)
        .bind(device_id)
        .execute(pool)
        .await
    } else {
        sqlx::query("UPDATE devices SET ssh_status = ?, last_ssh_error = ? WHERE id = ?")
            .bind(status)
            .bind(err)
            .bind(device_id)
            .execute(pool)
            .await
    };
}

/// Record that SSH just answered at privileged EXEC on `device_id` (e.g. a
/// successful reroute push) — keeps the recency window warm and marks the device
/// reachable.
pub async fn stamp_ssh_ok(pool: &MySqlPool, device_id: u64) {
    stamp_ssh_status(pool, device_id, STATUS_REACHABLE, None).await;
}

/// Periodic SSH liveness probe (the poll loop calls this every
/// `reachability_interval_seconds`). Opens a no-command SSH session, classifies the
/// outcome, and stores `ssh_status` (+ `last_ssh_ok_at` on `reachable`) so the UI
/// shows a definite state and the reroute gate's recency window is kept warm.
/// Returns the resulting status for logging.
pub async fn probe_ssh_and_store(pool: &MySqlPool, device_id: u64) -> &'static str {
    let (status, err): (&'static str, Option<String>) = match ssh::ssh_probe(pool, device_id).await
    {
        SshReach::Privileged => (STATUS_REACHABLE, None),
        SshReach::UserExec(m) => (STATUS_NO_PRIVILEGE, Some(m)),
        SshReach::Unreachable(m) => (STATUS_UNREACHABLE, Some(m)),
    };
    stamp_ssh_status(pool, device_id, status, err.as_deref()).await;
    status
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
