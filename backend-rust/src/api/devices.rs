//! SNMP device CRUD + test/discover/interfaces. Devices are the v1 telemetry
//! source of record (SNMP v2c interface polling). The SNMP community is a secret:
//! it is encrypted at rest via `crypto` on create/update and NEVER returned.
//!
//! Reads require `view_asset`; writes (create/update/delete/test/discover and
//! the per-device community) require `manage_devices` — superadmin-only — manages
//! telemetry sources. Field names are pinned by the frontend contract
//! (../../frontend/src/lib/api.ts: Device / Interface / DeviceTestResult).

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use super::{err, AppState};
use crate::auth::rbac::{markers, RequirePermission};
use crate::crypto;
use crate::telemetry::snmp;

type JsonResp = (StatusCode, Json<Value>);

/// One `devices` row in the exact shape the SPA expects. `sys_uptime` is a
/// stringified BIGINT (TimeTicks) per the contract; the community is absent.
fn device_json(r: &DeviceRow, interface_count: i64) -> Value {
    json!({
        "id": r.id,
        "name": r.name,
        "hostname": r.hostname,
        "snmp_version": r.snmp_version,
        "snmp_port": r.snmp_port,
        "enabled": r.enabled,
        "reachable": r.reachable,
        "vendor": r.vendor,
        "model": r.model,
        "os_version": r.os_version,
        "sys_name": r.sys_name,
        "sys_uptime": r.sys_uptime.map(|v| v.to_string()),
        "last_poll_at": r.last_poll_at.map(fmt_ts),
        "last_error": r.last_error,
        "poll_interval_seconds": r.poll_interval_seconds,
        "interface_count": interface_count,
        // SSH access (captured at onboarding for future CLI reroute actions;
        // unused in observe mode). Secrets are NEVER returned — only whether one
        // is stored, plus the non-secret username/port/method.
        "ssh_username": r.ssh_username,
        "ssh_port": r.ssh_port,
        "ssh_auth_method": r.ssh_auth_method,
        "ssh_configured": r.ssh_has_password != 0 || r.ssh_has_key != 0,
    })
}

/// RFC3339 for a UTC timestamp column.
fn fmt_ts(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339()
}

/// Seal an optional plaintext secret for storage. `Ok(None)` when absent/empty;
/// `Err(msg)` when a non-empty secret is given but encryption is unavailable or
/// fails — callers map the message to a 500.
fn seal_opt(plain: Option<&str>) -> Result<Option<Vec<u8>>, &'static str> {
    match plain {
        Some(s) if !s.is_empty() => {
            if !crypto::is_configured() {
                return Err("encryption key not configured");
            }
            crypto::seal_str(s).map(Some).map_err(|_| "encrypting secret failed")
        }
        _ => Ok(None),
    }
}

/// The columns selected for the device JSON projection.
#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: u64,
    name: String,
    hostname: String,
    snmp_version: String,
    snmp_port: u16,
    enabled: bool,
    reachable: bool,
    vendor: Option<String>,
    model: Option<String>,
    os_version: Option<String>,
    sys_name: Option<String>,
    sys_uptime: Option<u64>,
    last_poll_at: Option<chrono::DateTime<chrono::Utc>>,
    last_error: Option<String>,
    poll_interval_seconds: u32,
    ssh_username: Option<String>,
    ssh_port: u16,
    ssh_auth_method: Option<String>,
    // computed presence flags (1/0) — never the ciphertext itself.
    ssh_has_password: i64,
    ssh_has_key: i64,
}

const DEVICE_COLS: &str = "id, name, hostname, snmp_version, snmp_port, enabled, reachable, \
     vendor, model, os_version, sys_name, sys_uptime, last_poll_at, last_error, poll_interval_seconds, \
     ssh_username, ssh_port, ssh_auth_method, \
     (ssh_password_encrypted IS NOT NULL) AS ssh_has_password, \
     (ssh_private_key_encrypted IS NOT NULL) AS ssh_has_key";

async fn fetch_device(pool: &sqlx::MySqlPool, id: u64) -> anyhow::Result<Option<Value>> {
    let row = sqlx::query_as::<_, DeviceRow>(&format!("SELECT {DEVICE_COLS} FROM devices WHERE id = ?"))
        .bind(id)
        .fetch_optional(pool)
        .await?;
    let Some(row) = row else { return Ok(None) };
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_interfaces WHERE device_id = ?")
        .bind(id)
        .fetch_one(pool)
        .await?;
    Ok(Some(device_json(&row, count)))
}

/// GET /api/devices — every device with its interface count.
pub async fn list(_g: RequirePermission<markers::ViewAsset>, State(state): State<AppState>) -> JsonResp {
    let rows = match sqlx::query_as::<_, DeviceRow>(&format!("SELECT {DEVICE_COLS} FROM devices ORDER BY name"))
        .fetch_all(&state.pool)
        .await
    {
        Ok(r) => r,
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };
    // interface counts in one query, then zip.
    let counts: std::collections::HashMap<u64, i64> =
        sqlx::query_as::<_, (u64, i64)>("SELECT device_id, COUNT(*) FROM device_interfaces GROUP BY device_id")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
    let out: Vec<Value> = rows
        .iter()
        .map(|r| device_json(r, counts.get(&r.id).copied().unwrap_or(0)))
        .collect();
    (StatusCode::OK, Json(json!(out)))
}

#[derive(Debug, Deserialize)]
pub struct CreateDevice {
    name: String,
    hostname: String,
    #[serde(default = "default_version")]
    snmp_version: String,
    #[serde(default = "default_port")]
    snmp_port: u16,
    /// Plaintext SNMP community — encrypted at rest, never stored or returned raw.
    community: Option<String>,
    #[serde(default = "default_interval")]
    poll_interval_seconds: u32,
    // SSH access (password XOR key). Secrets are encrypted at rest, never
    // returned. Captured at onboarding for future CLI reroute actions.
    ssh_username: Option<String>,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    /// "password" | "key" (or absent for SNMP-only enrollment).
    ssh_auth_method: Option<String>,
    ssh_password: Option<String>,
    ssh_private_key: Option<String>,
    ssh_key_passphrase: Option<String>,
}

fn default_version() -> String {
    "v2c".to_string()
}
fn default_port() -> u16 {
    161
}
fn default_interval() -> u32 {
    30
}
fn default_ssh_port() -> u16 {
    22
}

/// Validate SSH onboarding fields: an auth method must be `password` or `key`,
/// and the matching secret + a username must be present. Returns the cleaned
/// username (None when SSH is not being configured).
fn validate_ssh<'a>(
    method: Option<&str>,
    username: Option<&'a str>,
    password: Option<&str>,
    private_key: Option<&str>,
) -> Result<Option<&'a str>, &'static str> {
    let user = username.map(str::trim).filter(|s| !s.is_empty());
    match method {
        None => Ok(user),
        Some("password") => {
            if user.is_none() || password.map(str::is_empty).unwrap_or(true) {
                return Err("ssh_auth_method 'password' requires ssh_username and ssh_password");
            }
            Ok(user)
        }
        Some("key") => {
            if user.is_none() || private_key.map(str::is_empty).unwrap_or(true) {
                return Err("ssh_auth_method 'key' requires ssh_username and ssh_private_key");
            }
            Ok(user)
        }
        Some(_) => Err("ssh_auth_method must be 'password' or 'key'"),
    }
}

/// POST /api/devices — create a device. Encrypts the community before insert.
pub async fn create(
    _g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Json(body): Json<CreateDevice>,
) -> JsonResp {
    if body.name.trim().is_empty() || body.hostname.trim().is_empty() {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "name and hostname are required");
    }
    if body.snmp_version != "v2c" {
        return err(StatusCode::UNPROCESSABLE_ENTITY, "only SNMP v2c is supported in v1");
    }
    // Validate SSH access (password XOR key) before touching the DB.
    let ssh_username = match validate_ssh(
        body.ssh_auth_method.as_deref(),
        body.ssh_username.as_deref(),
        body.ssh_password.as_deref(),
        body.ssh_private_key.as_deref(),
    ) {
        Ok(u) => u,
        Err(m) => return err(StatusCode::UNPROCESSABLE_ENTITY, m),
    };

    // Encrypt every secret (community + SSH password/key/passphrase) at rest.
    let (community_enc, ssh_pw_enc, ssh_key_enc, ssh_pass_enc) = match (
        seal_opt(body.community.as_deref()),
        seal_opt(body.ssh_password.as_deref()),
        seal_opt(body.ssh_private_key.as_deref()),
        seal_opt(body.ssh_key_passphrase.as_deref()),
    ) {
        (Ok(c), Ok(p), Ok(k), Ok(pp)) => (c, p, k, pp),
        _ => return err(StatusCode::INTERNAL_SERVER_ERROR, "encrypting credentials failed"),
    };

    let res = sqlx::query(
        "INSERT INTO devices (name, hostname, snmp_version, snmp_port, community_encrypted, poll_interval_seconds, \
         ssh_username, ssh_port, ssh_auth_method, ssh_password_encrypted, ssh_private_key_encrypted, ssh_key_passphrase_encrypted) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&body.name)
    .bind(&body.hostname)
    .bind(&body.snmp_version)
    .bind(body.snmp_port)
    .bind(community_enc)
    .bind(body.poll_interval_seconds)
    .bind(ssh_username)
    .bind(body.ssh_port)
    .bind(body.ssh_auth_method.as_deref())
    .bind(ssh_pw_enc)
    .bind(ssh_key_enc)
    .bind(ssh_pass_enc)
    .execute(&state.pool)
    .await;

    let id = match res {
        Ok(r) => r.last_insert_id(),
        Err(e) if is_dup(&e) => return err(StatusCode::CONFLICT, "a device with that name already exists"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    };

    match fetch_device(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::CREATED, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// GET /api/devices/{id}.
pub async fn show(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    match fetch_device(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        Ok(None) => err(StatusCode::NOT_FOUND, "device not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateDevice {
    name: Option<String>,
    hostname: Option<String>,
    snmp_version: Option<String>,
    snmp_port: Option<u16>,
    /// Optional new community — re-encrypted; omit to leave unchanged.
    community: Option<String>,
    poll_interval_seconds: Option<u32>,
    enabled: Option<bool>,
    // SSH access — a present, non-empty secret is re-encrypted; omit to keep the
    // stored value. ssh_username/ssh_port/ssh_auth_method update when present.
    ssh_username: Option<String>,
    ssh_port: Option<u16>,
    ssh_auth_method: Option<String>,
    ssh_password: Option<String>,
    ssh_private_key: Option<String>,
    ssh_key_passphrase: Option<String>,
}

/// PUT /api/devices/{id} — partial update. A present, non-empty `community` is
/// re-encrypted; an absent one leaves the stored ciphertext untouched.
pub async fn update(
    _g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
    Json(body): Json<UpdateDevice>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    if let Some(v) = &body.snmp_version {
        if v != "v2c" {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "only SNMP v2c is supported in v1");
        }
    }
    if let Some(m) = body.ssh_auth_method.as_deref() {
        if m != "password" && m != "key" {
            return err(StatusCode::UNPROCESSABLE_ENTITY, "ssh_auth_method must be 'password' or 'key'");
        }
    }

    // Build the SET clause dynamically over the present fields.
    let mut sets: Vec<&str> = Vec::new();
    if body.name.is_some() {
        sets.push("name = ?");
    }
    if body.hostname.is_some() {
        sets.push("hostname = ?");
    }
    if body.snmp_version.is_some() {
        sets.push("snmp_version = ?");
    }
    if body.snmp_port.is_some() {
        sets.push("snmp_port = ?");
    }
    if body.poll_interval_seconds.is_some() {
        sets.push("poll_interval_seconds = ?");
    }
    if body.enabled.is_some() {
        sets.push("enabled = ?");
    }
    let set_community = body.community.as_deref().map(|c| !c.is_empty()).unwrap_or(false);
    if set_community {
        sets.push("community_encrypted = ?");
    }
    if body.ssh_username.is_some() {
        sets.push("ssh_username = ?");
    }
    if body.ssh_port.is_some() {
        sets.push("ssh_port = ?");
    }
    if body.ssh_auth_method.is_some() {
        sets.push("ssh_auth_method = ?");
    }
    let set_ssh_pw = body.ssh_password.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    if set_ssh_pw {
        sets.push("ssh_password_encrypted = ?");
    }
    let set_ssh_key = body.ssh_private_key.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    if set_ssh_key {
        sets.push("ssh_private_key_encrypted = ?");
    }
    let set_ssh_pass = body.ssh_key_passphrase.as_deref().map(|s| !s.is_empty()).unwrap_or(false);
    if set_ssh_pass {
        sets.push("ssh_key_passphrase_encrypted = ?");
    }
    if sets.is_empty() {
        // Nothing to change; just return the current row.
        return match fetch_device(&state.pool, id).await {
            Ok(Some(v)) => (StatusCode::OK, Json(v)),
            _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
        };
    }

    // Seal any present secrets (community + SSH password/key/passphrase).
    let (community_enc, ssh_pw_enc, ssh_key_enc, ssh_pass_enc) = match (
        seal_opt(body.community.as_deref()),
        seal_opt(body.ssh_password.as_deref()),
        seal_opt(body.ssh_private_key.as_deref()),
        seal_opt(body.ssh_key_passphrase.as_deref()),
    ) {
        (Ok(c), Ok(p), Ok(k), Ok(pp)) => (c, p, k, pp),
        _ => return err(StatusCode::INTERNAL_SERVER_ERROR, "encrypting credentials failed"),
    };

    let sql = format!("UPDATE devices SET {} WHERE id = ?", sets.join(", "));
    let mut q = sqlx::query(&sql);
    if let Some(v) = &body.name {
        q = q.bind(v);
    }
    if let Some(v) = &body.hostname {
        q = q.bind(v);
    }
    if let Some(v) = &body.snmp_version {
        q = q.bind(v);
    }
    if let Some(v) = body.snmp_port {
        q = q.bind(v);
    }
    if let Some(v) = body.poll_interval_seconds {
        q = q.bind(v);
    }
    if let Some(v) = body.enabled {
        q = q.bind(v);
    }
    if set_community {
        q = q.bind(community_enc);
    }
    if let Some(v) = &body.ssh_username {
        q = q.bind(v);
    }
    if let Some(v) = body.ssh_port {
        q = q.bind(v);
    }
    if let Some(v) = &body.ssh_auth_method {
        q = q.bind(v);
    }
    if set_ssh_pw {
        q = q.bind(ssh_pw_enc);
    }
    if set_ssh_key {
        q = q.bind(ssh_key_enc);
    }
    if set_ssh_pass {
        q = q.bind(ssh_pass_enc);
    }
    q = q.bind(id);

    match q.execute(&state.pool).await {
        Ok(_) => {}
        Err(e) if is_dup(&e) => return err(StatusCode::CONFLICT, "a device with that name already exists"),
        Err(_) => return err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }

    match fetch_device(&state.pool, id).await {
        Ok(Some(v)) => (StatusCode::OK, Json(v)),
        _ => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// DELETE /api/devices/{id}. Cascades to interfaces/metrics/samples via FKs.
pub async fn remove(
    _g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let res = sqlx::query("DELETE FROM devices WHERE id = ?")
        .bind(id)
        .execute(&state.pool)
        .await;
    match res {
        Ok(r) if r.rows_affected() > 0 => (StatusCode::OK, Json(json!({ "ok": true }))),
        Ok(_) => err(StatusCode::NOT_FOUND, "device not found"),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// POST /api/devices/{id}/test — one-shot SNMP reachability + identity probe.
/// Persists the identity/reachability; returns DeviceTestResult. A failure is a
/// clean structured 200 `{ok:false, error}` (the device row carries last_error).
pub async fn test(
    _g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    match snmp::test_and_store(&state.pool, id).await {
        Ok(ident) => (
            StatusCode::OK,
            Json(json!({
                "ok": true,
                "vendor": ident.vendor,
                "model": ident.model,
                "os_version": ident.os_version,
            })),
        ),
        Err(e) => (StatusCode::OK, Json(json!({ "ok": false, "error": e.to_string() }))),
    }
}

/// POST /api/devices/{id}/discover — walk ifXTable/ifTable and reconcile
/// `device_interfaces`. Returns {discovered:N}. A failure surfaces as a 502 with
/// the structured error (the device is marked unreachable, no panic).
pub async fn discover(
    _g: RequirePermission<markers::ManageDevices>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    match snmp::discover_and_store(&state.pool, id).await {
        Ok(n) => (StatusCode::OK, Json(json!({ "discovered": n }))),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(json!({ "error": e.to_string() }))),
    }
}

/// GET /api/devices/{id}/interfaces — every interface on the device, each with
/// its latest metrics (Interface[] in the contract shape).
pub async fn interfaces(
    _g: RequirePermission<markers::ViewAsset>,
    State(state): State<AppState>,
    Path(id): Path<u64>,
) -> JsonResp {
    let exists: Option<u64> = sqlx::query_scalar("SELECT id FROM devices WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.pool)
        .await
        .unwrap_or(None);
    if exists.is_none() {
        return err(StatusCode::NOT_FOUND, "device not found");
    }
    match super::interfaces::load_interfaces_for_device(&state.pool, id).await {
        Ok(list) => (StatusCode::OK, Json(json!(list))),
        Err(_) => err(StatusCode::INTERNAL_SERVER_ERROR, "db_error"),
    }
}

/// True if a sqlx error is a MySQL duplicate-key (1062) violation.
fn is_dup(e: &sqlx::Error) -> bool {
    matches!(e, sqlx::Error::Database(db) if db.code().as_deref() == Some("23000"))
}
