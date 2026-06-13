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
use std::net::Ipv4Addr;
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
    Key { private_key_pem: String, passphrase: Option<String> },
}

/// Load + decrypt a device's SSH credentials. Errors are structured and never
/// echo secret material.
pub async fn load_device_ssh(pool: &MySqlPool, device_id: u64) -> Result<DeviceSsh> {
    type Row = (
        String,         // hostname
        Option<String>, // ssh_username
        u16,            // ssh_port
        Option<String>, // ssh_auth_method
        Option<Vec<u8>>, // ssh_password_encrypted
        Option<Vec<u8>>, // ssh_private_key_encrypted
        Option<Vec<u8>>, // ssh_key_passphrase_encrypted
        Option<String>, // ssh_host_fingerprint
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
            let blob = pw_enc.ok_or_else(|| anyhow!("device SSH method is 'password' but no password is stored"))?;
            SshAuth::Password(crate::crypto::open_str(&blob).context("decrypting SSH password")?)
        }
        Some("key") => {
            let blob = key_enc.ok_or_else(|| anyhow!("device SSH method is 'key' but no private key is stored"))?;
            let pem = crate::crypto::open_str(&blob).context("decrypting SSH private key")?;
            let passphrase = match pass_enc {
                Some(b) => Some(crate::crypto::open_str(&b).context("decrypting SSH key passphrase")?),
                None => None,
            };
            SshAuth::Key { private_key_pem: pem, passphrase }
        }
        _ => return Err(anyhow!("device has no SSH credentials configured (set ssh_auth_method)")),
    };

    Ok(DeviceSsh { device_id, host, port, username, auth, expected_fingerprint: fingerprint })
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
    let keypair =
        RsaKeypair::random(&mut OsCsprng, 2048).map_err(|e| anyhow!("generating RSA keypair: {e}"))?;
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
    Ok(GeneratedKey { private_key_openssh, public_key_openssh, fingerprint })
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

// ---- Host-key handler (TOFU) ---------------------------------------------------

struct TofuHandler {
    expected: Option<String>,
    observed: Arc<Mutex<Option<String>>>,
}

impl Handler for TofuHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
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
            Algorithm::Rsa { hash: Some(HashAlg::Sha256) },
            Algorithm::Rsa { hash: Some(HashAlg::Sha512) },
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
        mac: Cow::Owned(vec![mac::HMAC_SHA256, mac::HMAC_SHA512, mac::HMAC_SHA1]),
        compression: Cow::Borrowed(&[compression::NONE]),
    }
}

// ---- Session -------------------------------------------------------------------

/// Connect to a device over SSH, run `commands` in order against an interactive
/// IOS shell, and return each command's output. Pins the host key on first use;
/// a changed key fails closed. `commands` are sent verbatim — callers MUST pass
/// only rendered template commands (typed-param validated), never user free text.
pub async fn run_commands(pool: &MySqlPool, device_id: u64, commands: &[String]) -> Result<SshOutcome> {
    let dev = load_device_ssh(pool, device_id).await?;
    let outcome = run_on(&dev, commands).await?;

    // TOFU: persist the fingerprint the first time we see it.
    if dev.expected_fingerprint.is_none() {
        let _ = sqlx::query(
            "UPDATE devices SET ssh_host_fingerprint = ? WHERE id = ? AND ssh_host_fingerprint IS NULL",
        )
        .bind(&outcome.fingerprint)
        .bind(device_id)
        .execute(pool)
        .await;
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
    let output = outcome.results.first().map(|r| r.output.as_str()).unwrap_or("");

    let prefixes = parse_network_statements(output);
    for prefix in &prefixes {
        let _ = sqlx::query(
            "INSERT INTO device_bgp_networks (device_id, prefix, first_seen_at, last_seen_at, last_discovered_at) \
             VALUES (?, ?, UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP()) \
             ON DUPLICATE KEY UPDATE last_seen_at = UTC_TIMESTAMP(), last_discovered_at = UTC_TIMESTAMP()",
        )
        .bind(device_id)
        .bind(prefix)
        .execute(pool)
        .await;
    }

    // Auto-label sessions from `neighbor <ip> description <text>`. The router's own
    // description is authoritative for the friendly name; only fill peers that have
    // no label yet so a manually-set label is never clobbered.
    for (addr, description) in parse_neighbor_descriptions(output) {
        let _ = sqlx::query(
            "UPDATE device_bgp_peers SET label = ? \
             WHERE device_id = ? AND peer_remote_addr = ? AND (label IS NULL OR label = '')",
        )
        .bind(&description)
        .bind(device_id)
        .bind(addr.to_string())
        .execute(pool)
        .await;
    }

    Ok(prefixes.len())
}

/// Parse `neighbor A.B.C.D description <free text>` lines from a `router bgp`
/// config section into (addr, description) pairs. Peer-group / IPv6 neighbours
/// whose first token isn't an IPv4 literal are skipped (v1 is IPv4).
fn parse_neighbor_descriptions(config: &str) -> Vec<(Ipv4Addr, String)> {
    let mut out = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("neighbor ") else { continue };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let Some(addr_tok) = parts.next() else { continue };
        let Ok(addr) = addr_tok.parse::<Ipv4Addr>() else { continue };
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
/// WITHOUT changing any configuration (reads + a no-op config-mode entry/exit).
/// Each check reports ok + the router's message on denial. Used by the Settings
/// "command access" panel so an under-privileged account is obvious.
pub async fn probe_capabilities(pool: &MySqlPool, device_id: u64) -> Result<Vec<CapabilityCheck>> {
    // Reads first, then enter+leave config mode (nothing is applied).
    let probes: [(&str, &str); 4] = [
        ("Read running-config", "show running-config | section ^router bgp"),
        ("Read routing table", "show ip route summary"),
        ("Read BGP table", "show ip bgp summary"),
        ("Enter configuration mode", "configure terminal"),
    ];
    let commands: Vec<String> = probes
        .iter()
        .map(|(_, c)| c.to_string())
        .chain(std::iter::once("end".to_string())) // leave config mode if we entered it
        .collect();

    let outcome = run_commands(pool, device_id, &commands).await?;

    Ok(probes
        .iter()
        .enumerate()
        .map(|(i, (name, command))| {
            let output = outcome.results.get(i).map(|r| r.output.as_str()).unwrap_or("");
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

/// Parse `network A.B.C.D mask M.M.M.M` (and `network A.B.C.D/len`) lines from a
/// `router bgp` config section into CIDR strings.
fn parse_network_statements(config: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in config.lines() {
        let Some(rest) = line.trim().strip_prefix("network ") else { continue };
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

/// Lower-level: run commands against already-loaded credentials. Used by
/// [`run_commands`]; broken out so the executor can reuse one decrypt.
pub async fn run_on(dev: &DeviceSsh, commands: &[String]) -> Result<SshOutcome> {
    let observed = Arc::new(Mutex::new(None::<String>));
    let handler = TofuHandler { expected: dev.expected_fingerprint.clone(), observed: observed.clone() };

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
            return Err(anyhow!("SSH connect to {}:{} failed: {e}", dev.host, dev.port));
        }
        Err(_) => return Err(anyhow!("SSH connect to {}:{} timed out", dev.host, dev.port)),
    };

    // Authenticate (password XOR key).
    let authed = match &dev.auth {
        SshAuth::Password(pw) => session
            .authenticate_password(dev.username.clone(), pw.clone())
            .await
            .context("SSH password authentication")?,
        SshAuth::Key { private_key_pem, passphrase } => {
            let key = decode_secret_key(private_key_pem, passphrase.as_deref())
                .context("parsing SSH private key")?;
            let rsa_hash = session.best_supported_rsa_hash().await.ok().flatten().flatten();
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), rsa_hash);
            session
                .authenticate_publickey(dev.username.clone(), key)
                .await
                .context("SSH public-key authentication")?
        }
    };
    if !authed.success() {
        return Err(anyhow!("SSH authentication failed for user '{}'", dev.username));
    }

    let fingerprint = observed
        .lock()
        .await
        .clone()
        .ok_or_else(|| anyhow!("internal: no host key observed during handshake"))?;

    // Open an interactive shell (IOS commonly disables the bare `exec` channel).
    let mut channel = session.channel_open_session().await.context("opening SSH channel")?;
    channel
        .request_pty(false, "vt100", 200, 512, 0, 0, &[])
        .await
        .context("requesting PTY")?;
    channel.request_shell(false).await.context("requesting interactive shell")?;

    let session_start = Instant::now();

    // Read the login banner up to the first prompt; derive the device hostname so
    // subsequent prompt detection is anchored to THIS device (not stray output).
    let banner = read_until(&mut channel, &mut |buf| tail_prompt(buf).is_some(), session_start).await?;
    let base_prompt = tail_prompt(&banner).unwrap_or_default();
    let hostname = prompt_hostname(&base_prompt);

    // Disable paging so long `show` output isn't broken by "--More--".
    send_line(&mut channel, "terminal length 0").await?;
    let _ = read_until(&mut channel, &mut prompt_matcher(&hostname), session_start).await?;

    let mut results = Vec::with_capacity(commands.len());
    for command in commands {
        if session_start.elapsed() > SESSION_BUDGET {
            return Err(anyhow!("SSH session exceeded its time budget before '{command}'"));
        }
        send_line(&mut channel, command).await?;
        let raw = read_until(&mut channel, &mut prompt_matcher(&hostname), session_start).await?;
        results.push(CommandResult { command: command.clone(), output: clean_output(&raw, command) });
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
                return Err(anyhow!("timed out waiting for device prompt"));
            }
        }
        if cmd_start.elapsed() > COMMAND_BUDGET || session_start.elapsed() > SESSION_BUDGET {
            return Err(anyhow!("device did not return to a prompt within the time budget"));
        }
    }
    Ok(buf)
}

/// Returns the last line if it looks like a Cisco prompt (`name#`, `name>`,
/// `name(config)#`, …): no spaces, ends in `#`/`>`.
fn tail_prompt(buf: &str) -> Option<String> {
    let last = buf.trim_end_matches([' ', '\r', '\n']).lines().last()?.trim();
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
    if lines.first().map(|l| l.trim() == command.trim()).unwrap_or(false) {
        lines.remove(0);
    }
    while let Some(last) = lines.last() {
        let lt = last.trim();
        let is_prompt = lt.len() >= 2 && !lt.contains(' ') && (lt.ends_with('#') || lt.ends_with('>'));
        if lt.is_empty() || is_prompt {
            lines.pop();
        } else {
            break;
        }
    }
    lines.join("\n").trim().to_string()
}
