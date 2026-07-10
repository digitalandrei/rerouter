//! SSH transport for device-CLI reroute actions (Cisco IOS over SSH).
//!
//! Pure-Rust via `russh` (no openssl in the tree). Used by the reroute executor
//! (Stage 4) to push validated template commands and by the read-only
//! `POST /api/devices/{id}/ssh-test` probe. Connections are short-lived and
//! opened per action — there is no long-lived session pool.
//!
//! SAFETY:
//!   * Secrets (password / private key / passphrase) are decrypted via `crypto`
//!     into memory only, never logged.
//!   * Host-key TOFU: the first successful connection pins
//!     `devices.ssh_host_fingerprint`; a later mismatch **fails closed**
//!     (doctrine §8 SSH host verification).
//!   * The algorithm profile includes legacy KEX/cipher/MAC + the `ssh-rsa`
//!     host-key type so it can negotiate with old IOS (15.4) SSH servers.
//!   * Everything returns a structured `anyhow::Error` — this module never
//!     panics, so a flaky router cannot take the controller down.
//!
//! This module sends commands; it does NOT decide whether sending is allowed —
//! the executor's safety gates (operating_mode, locks, cooldowns, …) own that.

use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use russh::client::{self, Handler};
use russh::keys::{decode_secret_key, Algorithm, HashAlg, PrivateKeyWithHashAlg, PublicKey};
use russh::{cipher, compression, kex, mac, ChannelMsg, Preferred};
use sqlx::MySqlPool;
use tokio::sync::Mutex;

/// TCP connect + SSH handshake budget. Old IOS DH-group-exchange can be slow.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Quiet-time before we give up waiting for more output on a single read.
const READ_CHUNK_TIMEOUT: Duration = Duration::from_secs(8);
/// Total wall-clock budget for one command's response.
const COMMAND_BUDGET: Duration = Duration::from_secs(25);
/// Total wall-clock budget for a whole session (all commands).
const SESSION_BUDGET: Duration = Duration::from_secs(120);

// ---- Credentials ---------------------------------------------------------------

/// SSH connection fields for a device, secrets already decrypted in memory.
pub struct DeviceSsh {
    pub device_id: u64,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: SshAuth,
    /// Pinned host-key fingerprint, if any (`None` until first contact).
    pub expected_fingerprint: Option<String>,
}

pub enum SshAuth {
    Password(String),
    Key {
        private_key_pem: String,
        passphrase: Option<String>,
    },
}

/// Load + decrypt a device's SSH credentials. Errors are structured and never
/// echo secret material.
pub async fn load_device_ssh(pool: &MySqlPool, device_id: u64) -> Result<DeviceSsh> {
    type Row = (
        String,          // hostname
        Option<String>,  // ssh_username
        u16,             // ssh_port
        Option<String>,  // ssh_auth_method
        Option<Vec<u8>>, // ssh_password_encrypted
        Option<Vec<u8>>, // ssh_private_key_encrypted
        Option<Vec<u8>>, // ssh_key_passphrase_encrypted
        Option<String>,  // ssh_host_fingerprint
    );
    let row = sqlx::query_as::<_, Row>(
        "SELECT hostname, ssh_username, ssh_port, ssh_auth_method, ssh_password_encrypted, \
                ssh_private_key_encrypted, ssh_key_passphrase_encrypted, ssh_host_fingerprint \
         FROM devices WHERE id = ?",
    )
    .bind(device_id)
    .fetch_optional(pool)
    .await
    .context("loading device SSH credentials")?
    .ok_or_else(|| anyhow!("device {device_id} not found"))?;

    let (host, username, port, method, pw_enc, key_enc, pass_enc, fingerprint) = row;
    let username = username
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("device has no SSH username configured"))?;

    let auth = match method.as_deref() {
        Some("password") => {
            let blob = pw_enc.ok_or_else(|| {
                anyhow!("device SSH method is 'password' but no password is stored")
            })?;
            SshAuth::Password(crate::crypto::open_str(&blob).context("decrypting SSH password")?)
        }
        Some("key") => {
            let blob = key_enc.ok_or_else(|| {
                anyhow!("device SSH method is 'key' but no private key is stored")
            })?;
            let pem = crate::crypto::open_str(&blob).context("decrypting SSH private key")?;
            let passphrase = match pass_enc {
                Some(b) => {
                    Some(crate::crypto::open_str(&b).context("decrypting SSH key passphrase")?)
                }
                None => None,
            };
            SshAuth::Key {
                private_key_pem: pem,
                passphrase,
            }
        }
        _ => {
            return Err(anyhow!(
                "device has no SSH credentials configured (set ssh_auth_method)"
            ))
        }
    };

    Ok(DeviceSsh {
        device_id,
        host,
        port,
        username,
        auth,
        expected_fingerprint: fingerprint,
    })
}

// ---- Client key generation -----------------------------------------------------

/// A freshly generated SSH client keypair (no passphrase).
pub struct GeneratedKey {
    /// OpenSSH-format private-key PEM — stored encrypted; `decode_secret_key`
    /// reads it back for publickey auth.
    pub private_key_openssh: String,
    /// `ssh-rsa AAAA… comment` — NOT a secret; shown in the UI and enrolled on the
    /// router via `ip ssh pubkey-chain`.
    pub public_key_openssh: String,
    /// SHA-256 fingerprint of the public key (for display only).
    pub fingerprint: String,
}

/// rand_core 0.10 CSPRNG backed by the OS, bridging our `rand` 0.9 `OsRng` to the
/// rand_core 0.10 traits that `ssh-key`'s RSA generation requires. An OS-entropy
/// failure is unrecoverable and panics — identical to the existing AES-GCM nonce
/// path in `crypto.rs`; this is a one-shot admin keygen, not a parser path.
struct OsCsprng;

impl russh::keys::ssh_key::rand_core::TryRng for OsCsprng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        use rand::TryRngCore;
        rand::rngs::OsRng
            .try_fill_bytes(dst)
            .expect("OS CSPRNG (getrandom) failed");
        Ok(())
    }
}
impl russh::keys::ssh_key::rand_core::TryCryptoRng for OsCsprng {}

/// Generate a 2048-bit RSA client keypair (no passphrase) for SSH publickey auth.
/// RSA — not ed25519 — because Cisco IOS `ip ssh pubkey-chain` only accepts RSA,
/// and `ios_preferred()` is RSA-oriented for these 15.4 boxes.
pub fn generate_rsa_key(comment: &str) -> Result<GeneratedKey> {
    use russh::keys::ssh_key::{private::RsaKeypair, LineEnding, PrivateKey};
    let keypair = RsaKeypair::random(&mut OsCsprng, 2048)
        .map_err(|e| anyhow!("generating RSA keypair: {e}"))?;
    let mut key = PrivateKey::from(keypair);
    key.set_comment(comment);
    let private_key_openssh = key
        .to_openssh(LineEnding::LF)
        .map_err(|e| anyhow!("encoding private key: {e}"))?
        .to_string();
    let public_key_openssh = key
        .public_key()
        .to_openssh()
        .map_err(|e| anyhow!("encoding public key: {e}"))?;
    let fingerprint = key.public_key().fingerprint(HashAlg::Sha256).to_string();
    Ok(GeneratedKey {
        private_key_openssh,
        public_key_openssh,
        fingerprint,
    })
}

/// Best-effort: derive the OpenSSH public-key line from a private-key PEM (any
/// format `decode_secret_key` understands). Returns `None` when the key needs a
/// passphrase we weren't given or can't be parsed — the caller then stores NULL
/// and the UI simply shows no public key for that device.
pub fn derive_public_openssh(private_key_pem: &str, passphrase: Option<&str>) -> Option<String> {
    let key = decode_secret_key(private_key_pem, passphrase).ok()?;
    key.public_key().to_openssh().ok()
}

// ---- Results -------------------------------------------------------------------

/// One command and the device's cleaned response (echo + trailing prompt stripped).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CommandResult {
    pub command: String,
    pub output: String,
}

/// The outcome of a single SSH session against a device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SshOutcome {
    pub results: Vec<CommandResult>,
    /// The server host-key fingerprint observed during this session.
    pub fingerprint: String,
    /// True if this session pinned the fingerprint for the first time (TOFU).
    pub pinned_now: bool,
}

// ---- Executor port (seam) ------------------------------------------------------

/// The seam the reroute `Rerouter` depends on to talk to a device. Two methods
/// encode the session invariant: `apply` pushes config in ONE session (config
/// mode must persist across the commands); `verify_read` opens a SEPARATE,
/// read-only session for one `show`. `RusshExecutor` is the real adapter; tests
/// inject a fake. Generic (not `dyn`) so we need no `async-trait` dependency;
/// the `+ Send` bound keeps the futures usable from spawned tasks.
pub trait SshExecutor: Send + Sync {
    /// Push `commands` in order over one session and return each command's output.
    fn apply(
        &self,
        device_id: u64,
        commands: &[String],
    ) -> impl std::future::Future<Output = Result<SshOutcome>> + Send;

    /// Run one read-only `show` in a fresh session and return its cleaned output.
    fn verify_read(
        &self,
        device_id: u64,
        command: &str,
    ) -> impl std::future::Future<Output = Result<String>> + Send;
}

/// The production adapter: real russh over the wire (credential decrypt, host-key
/// TOFU, and the fail-closed allowlist all live behind it, in `run_commands` /
/// `run_on`). Holds a pool handle (cheap to clone — sqlx pools are reference
/// counted) because credential load + TOFU persistence need it.
pub struct RusshExecutor {
    pool: MySqlPool,
}

impl RusshExecutor {
    pub fn new(pool: MySqlPool) -> Self {
        Self { pool }
    }
}

impl SshExecutor for RusshExecutor {
    async fn apply(&self, device_id: u64, commands: &[String]) -> Result<SshOutcome> {
        run_commands(&self.pool, device_id, commands).await
    }

    async fn verify_read(&self, device_id: u64, command: &str) -> Result<String> {
        // Defense in depth: the verify path must never mutate. Every template
        // verify step is a `show`, so this only rejects a misconfigured one.
        if !command.trim_start().starts_with("show ") {
            return Err(anyhow!(
                "verify_read refuses a non-read command: {command:?}"
            ));
        }
        let outcome = run_commands(
            &self.pool,
            device_id,
            std::slice::from_ref(&command.to_string()),
        )
        .await?;
        Ok(outcome
            .results
            .first()
            .map(|r| r.output.clone())
            .unwrap_or_default())
    }
}

// ---- Host-key handler (TOFU) ---------------------------------------------------

struct TofuHandler {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}

impl Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        let fp = server_public_key.fingerprint(HashAlg::Sha256).to_string();
        *self.observed.lock().await = Some(fp.clone());
        match &self.expected {
            // Pinned already: accept only an exact match (fail closed otherwise).
            Some(expected) => Ok(expected == &fp),
            // First contact: trust on first use; the caller persists the pin.
            None => Ok(true),
        }
    }
}

/// Algorithm profile that can talk to both modern hosts and legacy IOS 15.4
/// (which typically offers group14-sha1 / group-exchange-sha1, aes*-ctr/cbc,
/// hmac-sha1, and an `ssh-rsa` host key).
fn ios_preferred() -> Preferred {
    Preferred {
        kex: Cow::Owned(vec![
            kex::CURVE25519,
            kex::ECDH_SHA2_NISTP256,
            kex::DH_G14_SHA256,
            kex::DH_G14_SHA1,
            kex::DH_GEX_SHA256,
            kex::DH_GEX_SHA1,
        ]),
        key: Cow::Owned(vec![
            Algorithm::Ed25519,
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256),
            },
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512),
            },
            // ssh-rsa (SHA-1) — the only host-key type many IOS 15.4 images offer.
            Algorithm::Rsa { hash: None },
        ]),
        cipher: Cow::Owned(vec![
            cipher::AES_256_CTR,
            cipher::AES_192_CTR,
            cipher::AES_128_CTR,
            cipher::AES_256_CBC,
            cipher::AES_128_CBC,
        ]),
        // MAC: prefer hmac-sha1 — the one MAC every IOS image here offers, and the
        // only one proven to work end-to-end with russh 0.61 against these boxes.
        // SSH picks the CLIENT's first offered MAC the server supports, so listing a
        // SHA-2 MAC first made russh select hmac-sha2-256 on newer IOS-XE (16.9+,
        // which adds SHA-2 MACs) and then silently stall *after* auth — the channel
        // data never decodes, surfacing as "timed out waiting for device prompt".
        // Older IOS (16.3) offers only hmac-sha1, so it never hit the SHA-2 path and
        // worked. OpenSSH negotiates hmac-sha2-512 with the same boxes fine, so the
        // IOS side is healthy — this is russh's SHA-2 MAC path. Keep the SHA-2 MACs
        // as fallback for any host that does NOT offer hmac-sha1.
        mac: Cow::Owned(vec![mac::HMAC_SHA1, mac::HMAC_SHA256, mac::HMAC_SHA512]),
        compression: Cow::Borrowed(&[compression::NONE]),
    }
}

// ---- Session -------------------------------------------------------------------

/// Classification of an SSH reachability probe (see [`ssh_probe`]).
#[derive(Debug, Clone)]
pub enum SshReach {
    /// Answered at privileged EXEC ('#') AND can run every command a reroute needs
    /// (all command-access checks pass) — usable for a reroute.
    Privileged,
    /// Connected + authenticated but landed at user-EXEC ('>'): SSH itself works,
    /// the account just lacks privilege 15. Carries the actionable message.
    UserExec(String),
    /// Reached privileged EXEC ('#') but the account was DENIED one or more of the
    /// commands a reroute needs (a restrictive privilege level / parser view). SSH
    /// works; the account can't do the work. Carries the denied-command summary.
    Restricted(String),
    /// Could not connect / authenticate / reach a usable prompt. Carries the error.
    Unreachable(String),
}

/// True when a [`run_on`] liveness error is the user-EXEC (privilege) case — SSH
/// connected and authenticated but the account isn't privilege 15. Keyed on
/// `run_on`'s own stable message and kept beside it on purpose; if that message
/// changes, keep the `user-EXEC` marker.
pub fn is_user_exec_error(msg: &str) -> bool {
    msg.contains("user-EXEC")
}

/// SSH reachability probe for mitigations, classified into [`SshReach`]. Runs the
/// SAME command-access checks as the Settings "Check access" panel
/// ([`probe_capabilities`]): connect → auth → privileged-EXEC → the config reads +
/// a no-op `configure terminal`, changing NOTHING on the router. A device counts as
/// [`SshReach::Privileged`] (usable for a reroute) ONLY when it reaches '#' AND every
/// check passes — so an account that logs in but can't actually run what a reroute
/// needs (low privilege / restrictive parser view) is caught here, before a mid-push
/// failure. A user-EXEC login surfaces as [`SshReach::UserExec`] (the capability run
/// never starts); denied commands as [`SshReach::Restricted`]. Reused by the reroute
/// reachability gate, the periodic probe, and the manual reachability-test endpoint.
pub async fn ssh_probe(pool: &MySqlPool, device_id: u64) -> SshReach {
    match probe_capabilities(pool, device_id).await {
        Ok(checks) => match caps_denied_summary(&checks) {
            None => SshReach::Privileged,
            Some(summary) => SshReach::Restricted(summary),
        },
        Err(e) => {
            let m = e.to_string();
            if is_user_exec_error(&m) {
                SshReach::UserExec(m)
            } else {
                SshReach::Unreachable(m)
            }
        }
    }
}

/// Connect to a device over SSH, run `commands` in order against an interactive
/// IOS shell, and return each command's output. Pins the host key on first use;
/// a changed key fails closed. `commands` are sent verbatim — callers MUST pass
/// only rendered template commands (typed-param validated), never user free text.
pub async fn run_commands(
    pool: &MySqlPool,
    device_id: u64,
    commands: &[String],
) -> Result<SshOutcome> {
    let dev = load_device_ssh(pool, device_id).await?;
    let outcome = run_on(&dev, commands).await?;

    // TOFU: persist the fingerprint the first time we see it.
    if dev.expected_fingerprint.is_none() {
        let updated = sqlx::query(
            "UPDATE devices SET ssh_host_fingerprint = ? WHERE id = ? AND ssh_host_fingerprint IS NULL",
        )
        .bind(&outcome.fingerprint)
        .bind(device_id)
        .execute(pool)
        .await
        .context("persisting first-seen SSH host key")?;
        if updated.rows_affected() == 0 {
            // Another concurrent probe may have won the TOFU race. Accept only
            // if it pinned the same key; a different winner is a hard mismatch.
            let pinned: Option<String> =
                sqlx::query_scalar("SELECT ssh_host_fingerprint FROM devices WHERE id = ?")
                    .bind(device_id)
                    .fetch_optional(pool)
                    .await
                    .context("checking concurrently pinned SSH host key")?
                    .flatten();
            anyhow::ensure!(
                pinned.as_deref() == Some(outcome.fingerprint.as_str()),
                "SSH host key changed during first-contact pinning"
            );
        }
    }
    Ok(outcome)
}

/// Discover routing context from the `router bgp` config section over SSH:
/// reconcile announced prefixes (`network` statements) into `device_bgp_networks`
/// AND auto-label discovered BGP peers from their `neighbor <ip> description`
/// lines. Returns the prefix count. Requires working SSH; a failure is a
/// structured error (caller logs it).
pub async fn discover_prefixes_and_store(pool: &MySqlPool, device_id: u64) -> Result<usize> {
    let cmd = "show running-config | section ^router bgp".to_string();
    let outcome = run_commands(pool, device_id, std::slice::from_ref(&cmd)).await?;
    let output = outcome
        .results
        .first()
        .map(|r| r.output.as_str())
        .unwrap_or("");

    if let Some(denied) = cisco_denied(output) {
        anyhow::bail!("announced-prefix discovery was denied by the device: {denied}");
    }
    let prefixes = parse_network_statements(output);
    let descriptions = parse_neighbor_descriptions(output);

    // Resolve each peer's OUTBOUND prefix-list (neighbor `route-map NAME out` ->
    // that route-map's `match ip address prefix-list PL`) so the guided picker
    // can offer the correct list per peer for the bgp_advertise_* templates. A
    // best-effort read; failure here never fails the whole discovery.
    let rm_cmd = "show running-config | section ^route-map".to_string();
    let route_context = match run_commands(pool, device_id, std::slice::from_ref(&rm_cmd)).await {
        Ok(rm_outcome) => {
            let rm_output = rm_outcome
                .results
                .first()
                .map(|r| r.output.as_str())
                .unwrap_or("");
            if let Some(denied) = cisco_denied(rm_output) {
                tracing::warn!(event_type = "route_map_discovery_denied", device_id, detail = %denied, "route-map inventory was not refreshed");
                None
            } else {
                let rm_to_pl = parse_routemap_prefix_lists(rm_output);
                let prefix_links = parse_neighbor_out_routemaps(output)
                    .into_iter()
                    .filter_map(|(addr, rm)| rm_to_pl.get(&rm).cloned().map(|pl| (addr, pl)))
                    .collect::<Vec<_>>();
                Some((
                    prefix_links,
                    parse_route_map_names(rm_output),
                    parse_neighbor_route_maps(output),
                ))
            }
        }
        Err(e) => {
            tracing::warn!(event_type = "route_map_discovery_failed", device_id, error = %e, "route-map inventory was not refreshed");
            None
        }
    };

    // Reconcile the complete successful snapshot atomically. Old prefixes and
    // route maps must not remain eligible forever after they disappear from the
    // router, and a partial DB write must never look like a successful refresh.
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE device_bgp_networks SET last_discovered_at = NULL WHERE device_id = ?")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    for prefix in &prefixes {
        sqlx::query(
            "INSERT INTO device_bgp_networks (device_id, prefix, first_seen_at, last_seen_at, last_discovered_at) \
             VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
             ON DUPLICATE KEY UPDATE last_seen_at = UTC_TIMESTAMP(), last_discovered_at = UTC_TIMESTAMP()",
        )
        .bind(device_id)
        .bind(prefix)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "DELETE FROM device_bgp_networks WHERE device_id = ? AND last_discovered_at IS NULL",
    )
    .bind(device_id)
    .execute(&mut *tx)
    .await?;

    // The router's description fills only unlabeled peers, preserving an
    // operator's explicit label.
    for (addr, description) in descriptions {
        sqlx::query(
            "UPDATE device_bgp_peers SET label = ? \
             WHERE device_id = ? AND peer_remote_addr = ? AND (label IS NULL OR label = '')",
        )
        .bind(description)
        .bind(device_id)
        .bind(addr.to_string())
        .execute(&mut *tx)
        .await?;
    }

    if let Some((prefix_links, route_maps, neighbor_maps)) = route_context {
        // These fields are a snapshot, not append-only hints. Clear assignments
        // that disappeared before writing the current set.
        sqlx::query(
            "UPDATE device_bgp_peers SET out_prefix_list = NULL, in_route_map = NULL, out_route_map = NULL \
             WHERE device_id = ?",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
        for (addr, prefix_list) in prefix_links {
            sqlx::query(
                "UPDATE device_bgp_peers SET out_prefix_list = ? \
                 WHERE device_id = ? AND peer_remote_addr = ?",
            )
            .bind(prefix_list)
            .bind(device_id)
            .bind(addr.to_string())
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("UPDATE device_route_maps SET last_discovered_at = NULL WHERE device_id = ?")
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
        for name in route_maps {
            sqlx::query(
                "INSERT INTO device_route_maps (device_id, name, last_discovered_at) \
                 VALUES (?, ?, UTC_TIMESTAMP()) \
                 ON DUPLICATE KEY UPDATE last_discovered_at = UTC_TIMESTAMP()",
            )
            .bind(device_id)
            .bind(name)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "DELETE FROM device_route_maps WHERE device_id = ? AND last_discovered_at IS NULL",
        )
        .bind(device_id)
        .execute(&mut *tx)
        .await?;

        for (addr, name, dir) in neighbor_maps {
            // `col` is whitelisted (in_route_map / out_route_map), never raw input.
            let col = if dir == "in" {
                "in_route_map"
            } else {
                "out_route_map"
            };
            sqlx::query(&format!(
                "UPDATE device_bgp_peers SET {col} = ? WHERE device_id = ? AND peer_remote_addr = ?"
            ))
            .bind(name)
            .bind(device_id)
            .bind(addr.to_string())
            .execute(&mut *tx)
            .await?;
        }
    }
    tx.commit().await?;

    Ok(prefixes.len())
}

/// Parse `neighbor A.B.C.D route-map NAME out` lines from a `router bgp` config
/// section into (peer addr, outbound route-map name) pairs. IPv4 peers only.
fn parse_neighbor_out_routemaps(config: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("neighbor ") else {
            continue;
        };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        // [addr, "route-map", NAME, "out"]
        if toks.len() >= 4 && toks[1] == "route-map" && toks[3] == "out" {
            if let Ok(addr) = toks[0].parse::<Ipv4Addr>() {
                out.push((addr, toks[2].to_string()));
            }
        }
    }
    out
}

/// Parse `neighbor A.B.C.D route-map NAME in|out` lines into (addr, name, dir).
/// Used to record each peer's current applied route-maps. IPv4 peers only.
fn parse_neighbor_route_maps(config: &str) -> Vec<(Ipv4Addr, String, String)> {
    let mut out = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("neighbor ") else {
            continue;
        };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        // [addr, "route-map", NAME, "in"|"out"]
        if toks.len() >= 4 && toks[1] == "route-map" && (toks[3] == "in" || toks[3] == "out") {
            if let Ok(addr) = toks[0].parse::<Ipv4Addr>() {
                out.push((addr, toks[2].to_string(), toks[3].to_string()));
            }
        }
    }
    out
}

/// Parse the distinct names of all `route-map NAME ...` stanzas in a route-map
/// config section (the catalog the Route-Map Change picker offers).
fn parse_route_map_names(config: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in config.lines() {
        if let Some(rest) = line.trim().strip_prefix("route-map ") {
            if let Some(name) = rest.split_whitespace().next() {
                let n = name.to_string();
                if !names.contains(&n) {
                    names.push(n);
                }
            }
        }
    }
    names
}

/// Parse a `route-map` config section into `route-map name -> matched outbound
/// prefix-list` (`match ip address prefix-list PL`). The first prefix-list seen
/// for a route-map wins (typically the lowest-sequence permit stanza).
fn parse_routemap_prefix_lists(config: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut current: Option<String> = None;
    for line in config.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("route-map ") {
            current = rest.split_whitespace().next().map(str::to_string);
        } else if let Some(rest) = trimmed.strip_prefix("match ip address prefix-list ") {
            if let (Some(rm), Some(pl)) = (current.clone(), rest.split_whitespace().next()) {
                map.entry(rm).or_insert_with(|| pl.to_string());
            }
        }
    }
    map
}

/// Parse `neighbor A.B.C.D description <free text>` lines from a `router bgp`
/// config section into (addr, description) pairs. Peer-group / IPv6 neighbours
/// whose first token isn't an IPv4 literal are skipped (v1 is IPv4).
fn parse_neighbor_descriptions(config: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("neighbor ") else {
            continue;
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let Some(addr_tok) = parts.next() else {
            continue;
        };
        let Ok(addr) = addr_tok.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(tail) = parts.next() else { continue };
        if let Some(desc) = tail.trim().strip_prefix("description ") {
            let desc = desc.trim();
            if !desc.is_empty() {
                out.push((addr, desc.to_string()));
            }
        }
    }
    out
}

/// One command-access check result for the device Settings "command access" panel.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapabilityCheck {
    pub name: String,
    pub command: String,
    pub ok: bool,
    /// The router's message when access is denied (empty when ok).
    pub detail: String,
}

/// Cisco rejection markers present in cleaned output when a command is not
/// permitted (parser view / privilege level) or not recognised.
fn cisco_denied(output: &str) -> Option<String> {
    const MARKERS: [&str; 6] = [
        "% Invalid input",
        "ommand authorization failed", // "Command authorization failed"
        "not authorized",
        "% Incomplete command",
        "% Ambiguous command",
        "% Permission denied",
    ];
    output
        .lines()
        .map(str::trim)
        .find(|l| MARKERS.iter().any(|m| l.contains(m)))
        .map(str::to_string)
}

/// Probe whether the device's SSH account can run the commands Rerouter needs —
/// WITHOUT changing any configuration (reads + a no-op config-mode entry).
/// Each check reports ok + the router's message on denial. Used by the Settings
/// "command access" panel so an under-privileged account is obvious.
pub async fn probe_capabilities(pool: &MySqlPool, device_id: u64) -> Result<Vec<CapabilityCheck>> {
    // Reads first (these cover every template's *verification* command family:
    // running-config, ip/ipv6 route, ip bgp, interfaces), then a no-op config-mode
    // entry. The actual apply verbs (ip route / ipv6 route / ip prefix-list /
    // router / interface + sub-commands) can't be probed without side effects, so
    // they aren't executed here — the controller allowlist + the installed parser
    // view are the enforcing controls for those.
    let probes: [(&str, &str); 6] = [
        (
            "Read running-config",
            "show running-config | section ^router bgp",
        ),
        ("Read IPv4 routing table", "show ip route summary"),
        ("Read IPv6 routing table", "show ipv6 route summary"),
        ("Read BGP table", "show ip bgp summary"),
        ("Read interfaces", "show interfaces summary"),
        ("Enter configuration mode", "configure terminal"),
    ];
    // We deliberately do NOT append a trailing `end` to leave config mode. If
    // `configure terminal` is denied (restricted parser view / low privilege) we
    // are still at the exec prompt, where IOS treats a bare `end` as a hostname to
    // telnet to — on a box with `ip domain-lookup` enabled that BLOCKS on DNS until
    // our read budget expires ("timed out waiting for device prompt"), masking the
    // real per-check results. run_on's best-effort `exit` cleanup leaves config mode
    // when we did enter it, and (unlike a command in this list) does no follow-up
    // read, so it cannot hang.
    let commands: Vec<String> = probes.iter().map(|(_, c)| c.to_string()).collect();

    let outcome = run_commands(pool, device_id, &commands).await?;

    Ok(probes
        .iter()
        .enumerate()
        .map(|(i, (name, command))| {
            let output = outcome
                .results
                .get(i)
                .map(|r| r.output.as_str())
                .unwrap_or("");
            let denied = cisco_denied(output);
            CapabilityCheck {
                name: name.to_string(),
                command: command.to_string(),
                ok: denied.is_none(),
                detail: denied.unwrap_or_default(),
            }
        })
        .collect())
}

/// Summarize the denied checks from a [`probe_capabilities`] run into ONE secret-free
/// line for `ssh_status='no_privilege'` reporting, or `None` when every check passed.
/// Lists each denied command and the router's own rejection message so the operator
/// sees exactly what to fix. Pure + unit-tested. (Command names + Cisco error markers
/// only — never credentials / community strings.)
pub fn caps_denied_summary(checks: &[CapabilityCheck]) -> Option<String> {
    let denied: Vec<&CapabilityCheck> = checks.iter().filter(|c| !c.ok).collect();
    if denied.is_empty() {
        return None;
    }
    let list = denied
        .iter()
        .map(|c| {
            if c.detail.is_empty() {
                format!("`{}`", c.command)
            } else {
                format!("`{}` ({})", c.command, c.detail)
            }
        })
        .collect::<Vec<_>>()
        .join("; ");
    Some(format!(
        "SSH reached enable mode but the account was denied {}/{} required commands: {}. \
         Give the account privilege 15 or a parser view that permits these (see the device's \
         Command access panel).",
        denied.len(),
        checks.len(),
        list
    ))
}

/// Parse `network A.B.C.D mask M.M.M.M` (and `network A.B.C.D/len`) lines from a
/// `router bgp` config section into CIDR strings.
fn parse_network_statements(config: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("network ") else {
            continue;
        };
        let parts: Vec<&str> = rest.split_whitespace().collect();
        if parts.len() >= 3 && parts[1] == "mask" {
            if let (Ok(ip), Some(len)) = (parts[0].parse::<Ipv4Addr>(), mask_to_len(parts[2])) {
                out.push(format!("{ip}/{len}"));
            }
        } else if parts.len() == 1 {
            if let Some((ip, len)) = parts[0].split_once('/') {
                if let (Ok(ip), Ok(len)) = (ip.parse::<Ipv4Addr>(), len.parse::<u8>()) {
                    if len <= 32 {
                        out.push(format!("{ip}/{len}"));
                    }
                }
            } else if let Ok(ip) = parts[0].parse::<Ipv4Addr>() {
                out.push(format!("{ip}/{}", classful_len(ip)));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Dotted netmask -> prefix length (counts set bits).
fn mask_to_len(mask: &str) -> Option<u8> {
    let ip: Ipv4Addr = mask.parse().ok()?;
    Some(u32::from(ip).count_ones() as u8)
}

/// Classful default length for a maskless `network` statement.
fn classful_len(ip: Ipv4Addr) -> u8 {
    match ip.octets()[0] {
        0..=127 => 8,
        128..=191 => 16,
        _ => 24,
    }
}

// ---- Command allowlist (fail-closed) -------------------------------------------

fn is_ipv4(tok: &str) -> bool {
    tok.parse::<Ipv4Addr>().is_ok()
}
fn is_u32(tok: &str) -> bool {
    !tok.is_empty() && tok.parse::<u32>().is_ok()
}
/// `a.b.c.d/len` (IPv4 CIDR, len 0..=32) — used by prefix-list entries.
fn is_cidr(tok: &str) -> bool {
    match tok.split_once('/') {
        Some((ip, len)) => {
            ip.parse::<Ipv4Addr>().is_ok() && len.parse::<u8>().is_ok_and(|l| l <= 32)
        }
        None => false,
    }
}
/// A bare IPv6 address — `{prefix_net}` renders to one for `show ipv6 route`.
fn is_ipv6(tok: &str) -> bool {
    tok.parse::<Ipv6Addr>().is_ok()
}
/// `addr/len` (IPv6 CIDR, len 0..=128) — `{prefix}` renders to one for the
/// IPv6 blackhole/null-route templates (`ipv6 route <cidr> Null0`).
fn is_cidr6(tok: &str) -> bool {
    match tok.split_once('/') {
        Some((ip, len)) => {
            ip.parse::<Ipv6Addr>().is_ok() && len.parse::<u8>().is_ok_and(|l| l <= 128)
        }
        None => false,
    }
}
/// A bare config name token (interface name, prefix-list name): non-empty and
/// restricted to `[A-Za-z0-9/._:-]` so it can never smuggle a second command or
/// whitespace. Template params are already whitespace-free; this is defense in depth.
fn is_name(tok: &str) -> bool {
    !tok.is_empty()
        && tok
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | ':' | '-'))
}

/// True if `cmd` is one of the EXACT command shapes Rerouter is designed to send
/// (every read, the config-mode entry/exit, and the catalogued routing/interface
/// templates). Variable tokens (IP, mask, ASN, tag) are validated; anything else
/// — chaining, free-text, other config verbs — is rejected. IOS output filters
/// (`| include|section|begin|exclude|count`) are permitted on `show` only, since
/// they filter output and cannot execute anything.
fn command_allowed(cmd: &str) -> bool {
    let cmd = cmd.trim();
    if cmd.is_empty() || cmd.bytes().any(|b| b.is_ascii_control()) {
        return false;
    }
    // Peel off an optional output filter at the first pipe.
    let (base, filter) = match cmd.split_once('|') {
        Some((b, f)) => (b.trim(), Some(f.trim())),
        None => (cmd, None),
    };
    if let Some(f) = filter {
        if !base.starts_with("show ") {
            return false;
        }
        let kw = f.split_whitespace().next().unwrap_or("");
        if !matches!(kw, "include" | "exclude" | "section" | "begin" | "count") {
            return false;
        }
        // IOS output-filter expressions used by the controller need only this
        // small regex/name alphabet. Refuse command separators and other syntax
        // even if a future caller bypasses template parameter validation.
        if !f.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || c == ' '
                || matches!(
                    c,
                    '(' | ')' | '^' | '|' | '.' | '_' | ':' | '/' | '-' | '=' | '[' | ']' | '$'
                )
        }) {
            return false;
        }
    }

    let toks: Vec<&str> = base.split_whitespace().collect();
    match toks.as_slice() {
        // session / reads
        ["terminal", "length", "0"] => true,
        ["configure", "terminal"] => true,
        ["end"] | ["exit"] => true,
        ["show", "clock"] => true,
        ["show", "version"] => true,
        ["show", "running-config"] => true,
        ["show", "ip", "route", "summary"] => true,
        ["show", "ip", "route", a] => is_ipv4(a),
        ["show", "ipv6", "route", "summary"] => true,
        ["show", "ipv6", "route", a] => is_ipv6(a) || is_cidr6(a),
        ["show", "ip", "bgp", "summary"] => true,
        ["show", "ip", "bgp", "neighbors", a] => is_ipv4(a),
        ["show", "ip", "bgp", "neighbors", a, "advertised-routes"] => is_ipv4(a),
        ["show", "interfaces", n] => is_name(n),
        ["show", "running-config", "interface", n] => is_name(n),
        // null-route (RTBH to Null0), with the optional name / tag the templates use
        ["ip", "route", net, mask, "Null0"] => is_ipv4(net) && is_ipv4(mask),
        ["ip", "route", net, mask, "Null0", "name", name] => {
            is_ipv4(net) && is_ipv4(mask) && is_name(name)
        }
        ["ip", "route", net, mask, "Null0", "tag", tag] => {
            is_ipv4(net) && is_ipv4(mask) && is_u32(tag)
        }
        ["no", "ip", "route", net, mask, "Null0"] => is_ipv4(net) && is_ipv4(mask),
        ["no", "ip", "route", net, mask, "Null0", "tag", tag] => {
            is_ipv4(net) && is_ipv4(mask) && is_u32(tag)
        }
        // IPv6 blackhole/null-route: `ipv6 route <cidr> Null0` (single CIDR token,
        // no dotted mask), with the optional name / tag the templates render.
        ["ipv6", "route", p, "Null0"] => is_cidr6(p),
        ["ipv6", "route", p, "Null0", "name", name] => is_cidr6(p) && is_name(name),
        ["ipv6", "route", p, "Null0", "tag", tag] => is_cidr6(p) && is_u32(tag),
        ["no", "ipv6", "route", p, "Null0"] => is_cidr6(p),
        ["no", "ipv6", "route", p, "Null0", "tag", tag] => is_cidr6(p) && is_u32(tag),
        // BGP session shut / no-shut
        ["router", "bgp", asn] => is_u32(asn),
        ["neighbor", ip, "shutdown"] => is_ipv4(ip),
        ["no", "neighbor", ip, "shutdown"] => is_ipv4(ip),
        // BGP per-peer advertisement via outbound prefix-list (+ soft clear)
        ["ip", "prefix-list", name, "permit", cidr] => is_name(name) && is_cidr(cidr),
        ["no", "ip", "prefix-list", name, "permit", cidr] => is_name(name) && is_cidr(cidr),
        ["clear", "ip", "bgp", ip, "soft", dir] => is_ipv4(ip) && matches!(*dir, "in" | "out"),
        // BGP per-peer route-map change (Route-Map Change mitigation), in|out
        ["neighbor", ip, "route-map", name, dir] => {
            is_ipv4(ip) && is_name(name) && matches!(*dir, "in" | "out")
        }
        ["no", "neighbor", ip, "route-map", name, dir] => {
            is_ipv4(ip) && is_name(name) && matches!(*dir, "in" | "out")
        }
        // interface-scoped actions: MSS clamp + shutdown / no shutdown
        ["interface", n] => is_name(n),
        ["ip", "tcp", "adjust-mss", mss] => is_u32(mss),
        ["no", "ip", "tcp", "adjust-mss"] => true,
        ["shutdown"] | ["no", "shutdown"] => true,
        _ => false,
    }
}

/// Plan-level safety beyond the per-command allowlist: a bare `shutdown` /
/// `no shutdown` is an INTERFACE command and must only run in interface config.
/// In `router bgp` context a bare `shutdown` would shut the entire BGP process,
/// and in global config it's invalid — so refuse it anywhere but interface mode.
/// Templates always pair `interface <name>` + `shutdown`; this guards a buggy or
/// forged plan now that the device account may be full privilege-15 with the
/// allowlist as the only router-side limit. `neighbor <ip> shutdown` is a
/// different (fully-specified) command and is unaffected.
fn sequence_safe(commands: &[String]) -> Result<()> {
    let mut in_interface = false;
    for c in commands {
        match c.split_whitespace().collect::<Vec<_>>().as_slice() {
            ["interface", _] => in_interface = true,
            ["configure", "terminal"] | ["router", "bgp", _] | ["end"] | ["exit"] => {
                in_interface = false
            }
            ["shutdown"] | ["no", "shutdown"] if !in_interface => {
                return Err(anyhow!(
                    "refusing '{}' outside interface config (would affect more than the target interface)",
                    c.trim()
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Lower-level: run commands against already-loaded credentials. Used by
/// [`run_commands`]; broken out so the executor can reuse one decrypt.
pub async fn run_on(dev: &DeviceSsh, commands: &[String]) -> Result<SshOutcome> {
    // Fail-closed allowlist: refuse to open a session if ANY command is outside the
    // exact set Rerouter is designed to send. Defense-in-depth behind template
    // rendering — even a malformed template or future caller cannot push an
    // unexpected command to a router. We validate before connecting.
    for c in commands {
        if !command_allowed(c) {
            return Err(anyhow!(
                "refusing to send command not on the allowlist: {c:?}"
            ));
        }
    }
    // Plan-level guard: a bare `shutdown` is only safe in interface config.
    sequence_safe(commands)?;

    let observed = Arc::new(Mutex::new(None::<String>));
    let handler = TofuHandler {
        expected: dev.expected_fingerprint.clone(),
        observed: observed.clone(),
    };

    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        preferred: ios_preferred(),
        ..Default::default()
    });

    let connect = client::connect(config, (dev.host.as_str(), dev.port), handler);
    let mut session = match tokio::time::timeout(CONNECT_TIMEOUT, connect).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            // A host-key mismatch surfaces as a rejected key during the handshake.
            if dev.expected_fingerprint.is_some() {
                if let Some(seen) = observed.lock().await.clone() {
                    if Some(&seen) != dev.expected_fingerprint.as_ref() {
                        return Err(anyhow!(
                            "SSH host key changed (pinned {}, server offered {}) — refusing to connect",
                            dev.expected_fingerprint.as_deref().unwrap_or("?"),
                            seen
                        ));
                    }
                }
            }
            return Err(anyhow!(
                "SSH connect to {}:{} failed: {e}",
                dev.host,
                dev.port
            ));
        }
        Err(_) => {
            return Err(anyhow!(
                "SSH connect to {}:{} timed out",
                dev.host,
                dev.port
            ))
        }
    };

    // Authenticate (password XOR key).
    let authed = match &dev.auth {
        SshAuth::Password(pw) => session
            .authenticate_password(dev.username.clone(), pw.clone())
            .await
            .context("SSH password authentication")?,
        SshAuth::Key {
            private_key_pem,
            passphrase,
        } => {
            let key = decode_secret_key(private_key_pem, passphrase.as_deref())
                .context("parsing SSH private key")?;
            let rsa_hash = session
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
            session
                .authenticate_publickey(dev.username.clone(), key)
                .await
                .context("SSH public-key authentication")?
        }
    };
    if !authed.success() {
        return Err(anyhow!(
            "SSH authentication failed for user '{}'",
            dev.username
        ));
    }

    let fingerprint = observed
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow!("internal: no host key observed during handshake"))?;

    // Open an interactive shell (IOS commonly disables the bare `exec` channel).
    let mut channel = session
        .channel_open_session()
        .await
        .context("opening SSH channel")?;
    channel
        .request_pty(false, "vt100", 200, 512, 0, 0, &[])
        .await
        .context("requesting PTY")?;
    channel
        .request_shell(false)
        .await
        .context("requesting interactive shell")?;

    let session_start = Instant::now();

    // Read the login banner up to the first prompt; derive the device hostname so
    // subsequent prompt detection is anchored to THIS device (not stray output).
    let banner = read_until(
        &mut channel,
        &mut |buf| tail_prompt(buf).is_some(),
        session_start,
    )
    .await?;
    let base_prompt = tail_prompt(&banner).unwrap_or_default();
    let hostname = prompt_hostname(&base_prompt);

    // The account must log straight into privileged EXEC ("name#"). A user-EXEC
    // session ("name>") can't run the controller's privileged commands (show
    // running-config, configure terminal, the reroute templates) and we can't
    // answer an `enable` password prompt on a non-interactive session — fail fast
    // with an actionable message instead of stalling on the first denied command.
    if base_prompt.ends_with('>') {
        return Err(anyhow!(
            "SSH account logged in at user-EXEC ('{base_prompt}'), not enable mode ('#'). \
             Rerouter needs privileged EXEC and cannot supply an enable password on a \
             non-interactive session — give the account privilege 15 so it logs straight \
             into '#' (e.g. `username <user> privilege 15 …`)."
        ));
    }

    // Disable paging so long `show` output isn't broken by "--More--".
    send_line(&mut channel, "terminal length 0").await?;
    let _ = read_until(&mut channel, &mut prompt_matcher(&hostname), session_start).await?;

    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        if session_start.elapsed() > SESSION_BUDGET {
            return Err(anyhow!(
                "SSH session exceeded its time budget before '{command}'"
            ));
        }
        send_line(&mut channel, command).await?;
        let raw = read_until(&mut channel, &mut prompt_matcher(&hostname), session_start).await?;
        results.push(CommandResult {
            command: command.clone(),
            output: clean_output(&raw, command),
        });
    }

    // Best-effort clean exit; ignore errors (we already have the results).
    let _ = send_line(&mut channel, "exit").await;
    let _ = channel.close().await;

    Ok(SshOutcome {
        results,
        fingerprint,
        pinned_now: dev.expected_fingerprint.is_none(),
    })
}

// ---- Shell I/O helpers ---------------------------------------------------------

async fn send_line(channel: &mut russh::Channel<client::Msg>, line: &str) -> Result<()> {
    let payload = format!("{line}\n");
    channel
        .data(payload.as_bytes())
        .await
        .map_err(|e| anyhow!("sending command over SSH: {e}"))
}

/// Read channel output until `done(buf)` is true, a per-read quiet timeout with no
/// prompt, EOF/close, or the session budget is exhausted.
async fn read_until(
    channel: &mut russh::Channel<client::Msg>,
    done: &mut (dyn FnMut(&str) -> bool + Send),
    session_start: Instant,
) -> Result<String> {
    let mut buf = String::new();
    let cmd_start = Instant::now();
    loop {
        match tokio::time::timeout(READ_CHUNK_TIMEOUT, channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => {
                buf.push_str(&String::from_utf8_lossy(&data));
                if done(&buf) {
                    break;
                }
            }
            Ok(Some(ChannelMsg::ExtendedData { data, .. })) => {
                buf.push_str(&String::from_utf8_lossy(&data));
            }
            Ok(Some(ChannelMsg::Eof)) | Ok(Some(ChannelMsg::Close)) | Ok(None) => break,
            Ok(Some(_)) => {}
            Err(_) => {
                // Quiet for READ_CHUNK_TIMEOUT: accept whatever we have if it already
                // ends at a prompt, otherwise treat as a stall.
                if done(&buf) {
                    break;
                }
                let tail: String = buf.chars().rev().take(400).collect();
                let tail: String = tail.chars().rev().collect();
                tracing::warn!(
                    event_type = "ssh_prompt_timeout",
                    bytes = buf.len(),
                    tail = %tail.escape_debug(),
                    "timed out waiting for device prompt"
                );
                return Err(anyhow!("timed out waiting for device prompt"));
            }
        }
        if cmd_start.elapsed() > COMMAND_BUDGET || session_start.elapsed() > SESSION_BUDGET {
            return Err(anyhow!(
                "device did not return to a prompt within the time budget"
            ));
        }
    }
    Ok(buf)
}

/// Returns the last line if it looks like a Cisco prompt (`name#`, `name>`,
/// `name(config)#`, …): no spaces, ends in `#`/`>`.
fn tail_prompt(buf: &str) -> Option<String> {
    let last = buf
        .trim_end_matches([' ', '\r', '\n'])
        .lines()
        .last()?
        .trim();
    if last.len() >= 2 && !last.contains(' ') && (last.ends_with('#') || last.ends_with('>')) {
        Some(last.to_string())
    } else {
        None
    }
}

/// Extract the device hostname from a prompt: strip a trailing `(config…)#` and
/// the final `#`/`>` (`ASR1004(config-router)#` -> `ASR1004`).
fn prompt_hostname(prompt: &str) -> String {
    prompt
        .trim_end_matches(['#', '>'])
        .split('(')
        .next()
        .unwrap_or("")
        .to_string()
}

/// A prompt matcher anchored to a specific device hostname.
fn prompt_matcher(hostname: &str) -> impl FnMut(&str) -> bool + '_ {
    move |buf: &str| {
        tail_prompt(buf)
            .map(|p| prompt_hostname(&p) == hostname && !hostname.is_empty())
            .unwrap_or(false)
    }
}

/// Strip the echoed command (first line) and the trailing prompt line(s) from a
/// raw response so only the device's actual output remains.
fn clean_output(raw: &str, command: &str) -> String {
    let mut lines: Vec<&str> = raw.split('\n').map(|l| l.trim_end_matches('\r')).collect();
    if lines
        .first()
        .map(|l| l.trim() == command.trim())
        .unwrap_or(false)
    {
        lines.remove(0);
    }
    while let Some(last) = lines.last() {
        let lt = last.trim();
        let is_prompt =
            lt.len() >= 2 && !lt.contains(' ') && (lt.ends_with('#') || lt.ends_with('>'));
        if lt.is_empty() || is_prompt {
            lines.pop();
        } else {
            break;
        }
    }
    lines.join("\n").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_summary_flags_denied_commands_and_stays_secret_free() {
        let check = |command: &str, ok: bool, detail: &str| CapabilityCheck {
            name: command.to_string(),
            command: command.to_string(),
            ok,
            detail: detail.to_string(),
        };
        // A mix like the operator's box: reads OK, running-config + config-mode denied.
        let checks = vec![
            check("show ip route summary", true, ""),
            check("show ip bgp summary", true, ""),
            check(
                "show running-config | section ^router bgp",
                false,
                "% Invalid input detected at '^' marker.",
            ),
            check(
                "configure terminal",
                false,
                "% Invalid input detected at '^' marker.",
            ),
        ];
        let s = caps_denied_summary(&checks).expect("some checks denied");
        assert!(s.contains("2/4"), "counts denied of total: {s}");
        assert!(s.contains("configure terminal"), "names the denied command");
        assert!(
            s.contains("show running-config | section ^router bgp"),
            "names each denied command"
        );
        // The summary is safe to log/email — command names + Cisco markers only.
        let low = s.to_lowercase();
        assert!(!low.contains("password") && !low.contains("community") && !low.contains("secret"));

        // Every check passing -> nothing to report (device is Privileged).
        let all_ok = vec![check("show ip route summary", true, "")];
        assert!(caps_denied_summary(&all_ok).is_none());
        // No checks at all -> None (not a denial).
        assert!(caps_denied_summary(&[]).is_none());
    }

    #[test]
    fn classifies_user_exec_privilege_error() {
        // The exact message run_on emits when the account lands at user-EXEC.
        let m = "SSH account logged in at user-EXEC ('eMA3>'), not enable mode ('#'). \
                 Rerouter needs privileged EXEC …";
        assert!(is_user_exec_error(m), "user-EXEC message -> privilege case");
        // A plain connect/auth failure is NOT the privilege case.
        assert!(!is_user_exec_error("SSH connect to 10.0.0.1:22 timed out"));
        assert!(!is_user_exec_error(
            "SSH authentication failed for user 'rerouter'"
        ));
    }

    #[test]
    fn allows_exactly_the_controller_command_set() {
        for ok in [
            "terminal length 0",
            "configure terminal",
            "end",
            "exit",
            "show clock",
            "show version | include (Version|uptime is)",
            "show running-config | section ^router bgp",
            "show ip route summary",
            "show ip route 203.0.113.0",
            "show ip bgp summary",
            "show ip bgp neighbors 198.51.100.7",
            "ip route 203.0.113.0 255.255.255.0 Null0",
            "ip route 203.0.113.0 255.255.255.0 Null0 name RRT-BLACKHOLE",
            "ip route 203.0.113.0 255.255.255.0 Null0 tag 666",
            "no ip route 203.0.113.0 255.255.255.0 Null0",
            "no ip route 203.0.113.0 255.255.255.0 Null0 tag 666",
            // IPv6 blackhole / null-route (single CIDR token) + verify reads
            "ipv6 route 2001:db8::1/128 Null0",
            "ipv6 route 2001:db8::1/128 Null0 name RRT-BLACKHOLE",
            "ipv6 route 2001:db8::/48 Null0 tag 666",
            "no ipv6 route 2001:db8::1/128 Null0",
            "no ipv6 route 2001:db8::/48 Null0 tag 666",
            "show ipv6 route summary",
            "show ipv6 route 2001:db8::1",
            "show ipv6 route 2001:db8::/48",
            "router bgp 65010",
            "neighbor 198.51.100.7 shutdown",
            "no neighbor 198.51.100.7 shutdown",
            // BGP per-peer advertisement (prefix-list + soft clear + verify read)
            "ip prefix-list PL-UPSTREAM-A permit 192.0.2.0/24",
            "no ip prefix-list PL-UPSTREAM-A permit 192.0.2.0/24",
            "clear ip bgp 198.51.100.7 soft out",
            "show ip bgp neighbors 198.51.100.7 advertised-routes",
            // BGP per-peer route-map change (Route-Map Change), in + out + soft in
            "neighbor 198.51.100.7 route-map RM-UPSTREAM-A out",
            "no neighbor 198.51.100.7 route-map RM-UPSTREAM-A out",
            "neighbor 198.51.100.7 route-map RM-IN in",
            "clear ip bgp 198.51.100.7 soft in",
            // interface MSS clamp + shutdown / no shutdown (+ verify reads)
            "interface GigabitEthernet0/0",
            "interface Port-channel1.100",
            "ip tcp adjust-mss 1436",
            "no ip tcp adjust-mss",
            "shutdown",
            "no shutdown",
            "show interfaces GigabitEthernet0/0",
            "show running-config interface GigabitEthernet0/0",
            "show running-config interface GigabitEthernet0/0 | include ip tcp adjust-mss",
        ] {
            assert!(command_allowed(ok), "should allow: {ok}");
        }
    }

    #[test]
    fn rejects_anything_outside_the_set() {
        for bad in [
            "reload",
            "ip route 203.0.113.0 255.255.255.0 10.0.0.1", // next-hop, not Null0
            "ip route 203.0.113.0 255.255.255.0 Null0 ; reload",
            "neighbor 198.51.100.7 remote-as 65000", // not shutdown
            "neighbor notanip shutdown",
            "no neighbor 198.51.100.7 password secret",
            "router bgp not-a-number",
            "show running-config | append flash:cfg", // filter verb not allowed
            "show running-config | include route-map; reload", // unsafe filter syntax
            "show running-config | include route-map\nreload", // control character
            "configure terminal\nreload",
            "do reload",
            "write erase",
            "ip prefix-list PL permit 192.0.2.0/24 ; reload", // chaining / extra tokens
            "ip prefix-list PL deny 192.0.2.0/24",            // only `permit` allowed
            "ip prefix-list PL permit notacidr",
            "clear ip bgp 198.51.100.7 soft both", // dir must be in|out
            "neighbor 198.51.100.7 route-map RM-X both", // dir must be in|out
            "neighbor 198.51.100.7 route-map bad name out", // route-map name has whitespace
            "interface Gig 0/0",                   // whitespace in name
            "ip tcp adjust-mss notanumber",
            "ipv6 route 2001:db8::1 Null0", // needs a /len (CIDR), not a bare addr
            "ipv6 route 2001:db8::1/128 10::1", // next-hop, not Null0
            "ipv6 route gggg::/128 Null0",  // not a valid v6 address
            "ipv6 route 203.0.113.0/24 Null0", // v4 in a v6 command
            "show ipv6 route ; reload",     // chaining / extra tokens
            "ip route 203.0.113.0 255.255.255.0 Null0 name RRT;reload",
            "ipv6 route 2001:db8::1/128 Null0 name RRT;reload",
            // device-destructive verbs are NOT on the allowlist (fail-closed)
            "no router bgp 65010", // would delete the BGP process
            "erase startup-config",
            "copy running-config startup-config", // controller never persists config
            "reload in 5",
            "ip route 203.0.113.0 255.255.255.0 GigabitEthernet0/0", // egress iface, not Null0
        ] {
            assert!(!command_allowed(bad), "should reject: {bad}");
        }
    }

    #[test]
    fn shutdown_only_in_interface_context() {
        let ok =
            |cmds: &[&str]| sequence_safe(&cmds.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        // The interface shutdown / no-shutdown templates (interface X first).
        assert!(ok(&["interface GigabitEthernet0/0", "shutdown"]).is_ok());
        assert!(ok(&["interface GigabitEthernet0/0", "no shutdown"]).is_ok());
        assert!(ok(&["interface GigabitEthernet0/0", "ip tcp adjust-mss 1436"]).is_ok());
        // `neighbor <ip> shutdown` is a different command — fine in router context.
        assert!(ok(&["router bgp 65010", "neighbor 198.51.100.7 shutdown"]).is_ok());
        // A BARE shutdown outside interface config is refused (would shut BGP / be
        // invalid), even though command_allowed() accepts the token in isolation.
        assert!(ok(&["router bgp 65010", "shutdown"]).is_err());
        assert!(ok(&["configure terminal", "shutdown"]).is_err());
        assert!(ok(&["shutdown"]).is_err());
        assert!(ok(&["no shutdown"]).is_err());
        // Leaving interface mode re-arms the guard.
        assert!(ok(&["interface GigabitEthernet0/0", "end", "shutdown"]).is_err());
    }

    #[test]
    fn parses_neighbor_route_maps_and_names() {
        let cfg = "router bgp 65010\n\
neighbor 198.51.100.7 route-map RM-OUT-A out\n\
neighbor 198.51.100.7 route-map RM-IN-A in\n\
neighbor 203.0.113.9 route-map RM-OUT-B out\n";
        let mut nm = parse_neighbor_route_maps(cfg);
        nm.sort();
        assert_eq!(
            nm,
            vec![
                (
                    "198.51.100.7".parse().unwrap(),
                    "RM-IN-A".to_string(),
                    "in".to_string()
                ),
                (
                    "198.51.100.7".parse().unwrap(),
                    "RM-OUT-A".to_string(),
                    "out".to_string()
                ),
                (
                    "203.0.113.9".parse().unwrap(),
                    "RM-OUT-B".to_string(),
                    "out".to_string()
                ),
            ]
        );

        // Distinct route-map names in first-seen order.
        let rm = "route-map RM-OUT-A permit 10\n\
match ip address prefix-list PL\n\
route-map RM-IN-A deny 5\n\
route-map RM-OUT-A permit 20\n";
        assert_eq!(
            parse_route_map_names(rm),
            vec!["RM-OUT-A".to_string(), "RM-IN-A".to_string()]
        );
    }
}
