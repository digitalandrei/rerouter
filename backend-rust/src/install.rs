//! Installer + first-admin bootstrap. The released binary carries everything it
//! needs: `rerouter-controller --install` lays down /srv/rerouter (binary,
//! .env, config.toml) and the systemd unit, then the operator fills in
//! /srv/rerouter/.env and `systemctl start rerouter-controller`.
//!
//! Idempotent: re-running upgrades the binary and the unit only — an existing
//! .env or config.toml is NEVER overwritten (they belong to the operator).
//! `--prefix <dir>` relocates the whole tree for testing (e.g. --prefix /tmp/x).

use std::fs;
use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use sqlx::MySqlPool;

use crate::auth::password;

/// Canonical systemd unit — `include_str!` of the deploy copy so the embedded
/// template and deploy/systemd/rerouter-controller.service can never drift.
const SYSTEMD_UNIT: &str = include_str!("../../deploy/systemd/rerouter-controller.service");

/// Embedded copy of config.example.toml (same no-drift guarantee).
const CONFIG_TEMPLATE: &str = include_str!("../config.example.toml");

/// .env template written on first install only. `{session_secret}` /
/// `{secrets_key}` are replaced with values generated at install time.
/// KEEP THE KEY SET IN SYNC with deploy/env/rerouter.example.env (the repo
/// reference copy) — wording may differ, keys must not.
const ENV_TEMPLATE: &str = "\
# Rerouter controller environment — loaded by systemd (EnvironmentFile) and by
# the binary itself (--env-file). Written once by `rerouter-controller --install`;
# never overwritten on upgrade. Keep mode 0600: this file contains secrets.
#
# FILL IN BEFORE FIRST START (everything marked CHANGE-ME):
#   1. DATABASE_URL — real MariaDB credentials (see the SQL printed by --install)
#   2. SMTP_*       — outbound mail for the alert dispatcher
# SESSION_SECRET and SECRETS_KEY were generated for you at install time.

# --- Database (MariaDB, via sqlx) — REQUIRED -------------------------------------
DATABASE_URL=mysql://rerouter:CHANGE-ME@127.0.0.1:3306/rerouter

# --- Email alerts (SMTP) — REQUIRED for alert delivery ---------------------------
SMTP_HOST=CHANGE-ME.example.com
SMTP_PORT=587
SMTP_USERNAME=CHANGE-ME
SMTP_PASSWORD=CHANGE-ME
SMTP_FROM=rerouter@CHANGE-ME.example.com

# --- Auth / 2FA -------------------------------------------------------------------
# TOTP issuer label shown in authenticator apps.
TWO_FACTOR_ISSUER=Rerouter

# --- Generated at install time (32 random bytes hex each) — do not share ---------
# SESSION_SECRET signs/authenticates session cookies (DB-backed sessions table).
# SECRETS_KEY encrypts device, TOTP, and webhook secrets at rest with AES-256-GCM.
SESSION_SECRET={session_secret}
SECRETS_KEY={secrets_key}
";

/// `--install`: lay down the controller under `<prefix>/srv/rerouter` plus the
/// systemd unit. Safe to re-run (upgrade path: binary + unit only).
pub fn run_install(prefix: &str) -> Result<()> {
    let prefix_is_root = prefix == "/";
    let prefix_path = Path::new(prefix);
    let srv_dir = prefix_path.join("srv");
    let install_dir = srv_dir.join("rerouter");
    let etc_dir = prefix_path.join("etc");
    let systemd_dir = etc_dir.join("systemd");
    let unit_dir = prefix_path.join("etc/systemd/system");
    let unit_path = unit_dir.join("rerouter-controller.service");

    tracing::info!(
        event_type = "install_started",
        prefix,
        install_dir = %install_dir.display(),
        "installing rerouter-controller"
    );

    // b. system user (required for a real install; never inspect or modify host
    // accounts for test prefixes).
    let service_account = ensure_system_user(prefix_is_root)?;

    fs::create_dir_all(prefix_path)
        .with_context(|| format!("creating prefix {}", prefix_path.display()))?;
    create_dir_with_mode_if_new(&srv_dir, 0o755)?;
    create_dir_with_mode_if_new(&install_dir, 0o750)?;
    // Do not let the invoking shell's umask make the service directory
    // untraversable by the rerouter account. This changes only the installer-owned
    // directory; existing operator-owned files inside retain their modes.
    fs::set_permissions(&install_dir, fs::Permissions::from_mode(0o750))
        .context("chmod 0750 on install directory")?;
    if let Some(account) = service_account {
        set_owner(&install_dir, 0, account.gid, "root:rerouter")?;
    }
    create_dir_with_mode_if_new(&etc_dir, 0o755)?;
    create_dir_with_mode_if_new(&systemd_dir, 0o755)?;
    create_dir_with_mode_if_new(&unit_dir, 0o755)?;

    // c. binary: copy ourselves in via tmp+rename so an upgrade replaces a
    // running binary atomically (plain copy would hit ETXTBSY).
    let exe = std::env::current_exe().context("resolving current executable")?;
    let bin_dest = install_dir.join("rerouter-controller");
    let bin_tmp = install_dir.join(".rerouter-controller.tmp");
    fs::copy(&exe, &bin_tmp)
        .with_context(|| format!("copying {} -> {}", exe.display(), bin_tmp.display()))?;
    fs::set_permissions(&bin_tmp, fs::Permissions::from_mode(0o755))
        .context("chmod 0755 on binary")?;
    if service_account.is_some() {
        set_owner(&bin_tmp, 0, 0, "root:root")?;
    }
    fs::rename(&bin_tmp, &bin_dest).context("installing binary into place")?;
    tracing::info!(event_type = "install_binary", path = %bin_dest.display(), "binary installed");

    // d. .env — ONLY IF NOT EXISTS; 0600; secrets generated now.
    let env_path = install_dir.join(".env");
    if env_path.exists() {
        tracing::info!(
            event_type = "install_env_kept",
            path = %env_path.display(),
            "existing .env left untouched (operator-owned)"
        );
    } else {
        let content = ENV_TEMPLATE
            .replace("{session_secret}", &random_hex_32())
            .replace("{secrets_key}", &random_hex_32());
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&env_path)
            .with_context(|| format!("creating {}", env_path.display()))?;
        f.write_all(content.as_bytes()).context("writing .env")?;
        fs::set_permissions(&env_path, fs::Permissions::from_mode(0o600))
            .context("chmod 0600 on .env")?;
        if let Some(account) = service_account {
            set_owner(&env_path, account.uid, account.gid, "rerouter:rerouter")?;
        }
        tracing::info!(
            event_type = "install_env_written",
            path = %env_path.display(),
            "wrote .env template (mode 0600, SESSION_SECRET/SECRETS_KEY generated)"
        );
    }

    // e. config.toml — ONLY IF NOT EXISTS; embedded config.example.toml.
    let config_path = install_dir.join("config.toml");
    if config_path.exists() {
        tracing::info!(
            event_type = "install_config_kept",
            path = %config_path.display(),
            "existing config.toml left untouched (operator-owned)"
        );
    } else {
        let mut config = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .open(&config_path)
            .with_context(|| format!("creating {}", config_path.display()))?;
        config
            .write_all(CONFIG_TEMPLATE.as_bytes())
            .context("writing config.toml")?;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o640))
            .context("chmod 0640 on config.toml")?;
        if let Some(account) = service_account {
            set_owner(&config_path, 0, account.gid, "root:rerouter")?;
        }
        tracing::info!(
            event_type = "install_config_written",
            path = %config_path.display(),
            "wrote config.toml (copy of config.example.toml)"
        );
    }

    // f. systemd unit — ours, overwrite allowed; then daemon-reload + enable
    // (enable only: .env must be filled before the first start).
    fs::write(&unit_path, SYSTEMD_UNIT)
        .with_context(|| format!("writing {}", unit_path.display()))?;
    fs::set_permissions(&unit_path, fs::Permissions::from_mode(0o644))
        .context("chmod 0644 on systemd unit")?;
    if service_account.is_some() {
        set_owner(&unit_path, 0, 0, "root:root")?;
    }
    tracing::info!(event_type = "install_unit_written", path = %unit_path.display(), "systemd unit written");

    let mut systemd_ready = false;
    if prefix_is_root {
        match systemctl(&["daemon-reload"])
            .and_then(|()| systemctl(&["enable", "rerouter-controller"]))
        {
            Ok(()) => {
                systemd_ready = true;
                tracing::info!(
                    event_type = "install_unit_enabled",
                    "unit enabled (NOT started — fill in .env first)"
                );
            }
            Err(e) => tracing::warn!(
                event_type = "install_systemctl_failed",
                error = %e,
                "systemctl unavailable or failed (container?) — enable manually: \
                 systemctl daemon-reload && systemctl enable rerouter-controller"
            ),
        }
    } else {
        tracing::warn!(
            event_type = "install_systemctl_skipped",
            prefix,
            "prefixed (test) install — skipping systemctl; on a real host run: \
             systemctl daemon-reload && systemctl enable rerouter-controller"
        );
    }

    print_next_steps(&install_dir, systemd_ready);
    Ok(())
}

/// g. operator-facing summary (plain stdout on purpose, not structured logs).
fn print_next_steps(install_dir: &Path, systemd_ready: bool) {
    let dir = install_dir.display();
    println!();
    println!("==============================================================================");
    println!(" rerouter-controller installed under {dir}");
    println!("==============================================================================");
    println!(" 1. Create the MariaDB database and user (mariadb as root):");
    println!("        CREATE DATABASE rerouter CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;");
    println!("        CREATE USER 'rerouter'@'127.0.0.1' IDENTIFIED BY '<strong password>';");
    println!("        GRANT ALL PRIVILEGES ON rerouter.* TO 'rerouter'@'127.0.0.1';");
    println!("        FLUSH PRIVILEGES;");
    println!(" 2. Edit {dir}/.env:");
    println!("      - DATABASE_URL  -> the password from step 1");
    println!("      - SMTP_*        -> your mail relay (alert delivery)");
    println!("      (SESSION_SECRET and SECRETS_KEY were generated for you.)");
    println!(" 3. Verify credentials:");
    println!("        {dir}/rerouter-controller --check-db --env-file {dir}/.env");
    if systemd_ready {
        println!(" 4. Start it (schema + seeds are created automatically on first start):");
    } else {
        println!(" 4. Enable + start it (schema + seeds are created on first start):");
        println!("        systemctl daemon-reload && systemctl enable rerouter-controller");
    }
    println!("        systemctl start rerouter-controller");
    println!("        journalctl -fu rerouter-controller");
    println!(" 5. Create the first admin (TOTP enrollment happens at first login):");
    println!("        {dir}/rerouter-controller --create-admin --env-file {dir}/.env");
    println!("==============================================================================");
}

/// `--create-admin`: minimal first-admin bootstrap. Email/name/password come
/// from flags, ADMIN_* env vars, or an interactive prompt. Idempotent on email;
/// two_factor_confirmed_at stays NULL so TOTP enrollment happens at first login.
pub async fn create_admin(
    pool: &MySqlPool,
    email: Option<String>,
    name: Option<String>,
    password_plain: Option<String>,
) -> Result<()> {
    let email = match email {
        Some(v) => v,
        None => prompt("Admin email")?,
    }
    .trim()
    .to_lowercase();
    let name = match name {
        Some(v) => v,
        None => prompt("Admin name")?,
    }
    .trim()
    .to_string();
    anyhow::ensure!(!email.is_empty(), "admin email must not be empty");
    anyhow::ensure!(!name.is_empty(), "admin name must not be empty");

    let existing: Option<(u64, bool)> =
        sqlx::query_as("SELECT id, two_factor_confirmed_at IS NOT NULL FROM users WHERE email = ?")
            .bind(&email)
            .fetch_optional(pool)
            .await
            .context("looking up existing user")?;

    let mut enrollment_code: Option<String> = None;

    let (user_id, created) = match existing {
        Some((id, confirmed)) => {
            if !confirmed {
                let code = crate::auth::sessions::generate_token();
                sqlx::query(
                    "UPDATE users SET two_factor_enrollment_token_hash = ?, last_totp_step = NULL WHERE id = ?",
                )
                    .bind(crate::auth::sessions::hash_token(&code))
                    .bind(id)
                    .execute(pool)
                    .await
                    .context("rotating admin enrollment code")?;
                enrollment_code = Some(code);
            }
            (id, false)
        }
        None => {
            let plain = match password_plain {
                Some(v) => v,
                None => prompt_password("Admin password")?,
            };
            anyhow::ensure!(
                plain.len() >= 12,
                "admin password must be at least 12 characters"
            );
            let phc = password::hash(&plain)?;
            let code = crate::auth::sessions::generate_token();
            let res = sqlx::query(
                "INSERT INTO users \
                 (name, email, password, two_factor_confirmed_at, two_factor_enrollment_token_hash) \
                 VALUES (?, ?, ?, NULL, ?)",
            )
            .bind(&name)
            .bind(&email)
            .bind(&phc)
            .bind(crate::auth::sessions::hash_token(&code))
            .execute(pool)
            .await
            .context("inserting admin user")?;
            enrollment_code = Some(code);
            (res.last_insert_id(), true)
        }
    };

    // Attach the admin role (idempotent; the role itself is seeded by migrations).
    let role_rows = sqlx::query(
        "INSERT IGNORE INTO role_user (role_id, user_id) SELECT id, ? FROM roles WHERE name = 'superadmin'",
    )
    .bind(user_id)
    .execute(pool)
    .await
    .context("attaching admin role")?
    .rows_affected();

    tracing::info!(
        event_type = "create_admin_done",
        user_id,
        created,
        role_attached = role_rows > 0,
        "admin bootstrap complete"
    );
    if created {
        println!(
            "created admin user '{email}' (id {user_id}); 2FA enrollment happens at first login"
        );
    } else {
        println!("user '{email}' already exists (id {user_id}); password left unchanged");
    }
    if let Some(code) = enrollment_code {
        println!("one-time 2FA enrollment code: {code}");
        println!("deliver it separately from the temporary password; it is shown only here");
    }
    if role_rows > 0 {
        println!("attached role 'superadmin' to user id {user_id}");
    } else {
        println!("role 'superadmin' was already attached to user id {user_id}");
    }
    Ok(())
}

/// Create the `rerouter` system user and same-named group when installing for
/// real (prefix "/"). Prefixed installs never inspect or modify host accounts.
#[derive(Clone, Copy)]
struct AccountIds {
    uid: u32,
    gid: u32,
}

fn ensure_system_user(prefix_is_root: bool) -> Result<Option<AccountIds>> {
    if !prefix_is_root {
        tracing::warn!(
            event_type = "install_user_skipped",
            "prefixed (test) install — skipping host user lookup and ownership changes"
        );
        return Ok(None);
    }
    if let Some(account) = lookup_account("rerouter")? {
        return Ok(Some(account));
    }
    let status = Command::new("useradd")
        .args(["-r", "-U", "-s", "/usr/sbin/nologin", "rerouter"])
        .status()
        .context("running useradd for rerouter")?;
    anyhow::ensure!(
        status.success(),
        "could not create required system user 'rerouter'; create it with: \
         useradd -r -U -s /usr/sbin/nologin rerouter"
    );
    tracing::info!(
        event_type = "install_user_created",
        "created system user 'rerouter'"
    );
    lookup_account("rerouter")?
        .map(Some)
        .context("rerouter account is still unavailable after successful useradd")
}

fn lookup_account(name: &str) -> Result<Option<AccountIds>> {
    let uid = numeric_id(&["-u", name])?;
    let Some(uid) = uid else {
        return Ok(None);
    };
    anyhow::ensure!(uid != 0, "service account {name} must not have uid 0");
    let group = Command::new("getent")
        .args(["group", name])
        .output()
        .with_context(|| format!("looking up required group {name}"))?;
    anyhow::ensure!(
        group.status.success(),
        "service account {name} exists but required group {name} does not"
    );
    let group_text =
        std::str::from_utf8(&group.stdout).context("getent returned non-UTF-8 output")?;
    let gid = group_text
        .trim()
        .split(':')
        .nth(2)
        .context("getent group output did not contain a gid")?
        .parse::<u32>()
        .context("getent group returned an invalid numeric gid")?;
    let memberships = Command::new("id")
        .args(["-G", name])
        .output()
        .with_context(|| format!("checking group memberships for {name}"))?;
    anyhow::ensure!(
        memberships.status.success(),
        "could not determine group memberships for {name}"
    );
    let membership_text =
        std::str::from_utf8(&memberships.stdout).context("id returned non-UTF-8 output")?;
    let is_member = membership_text
        .split_whitespace()
        .filter_map(|value| value.parse::<u32>().ok())
        .any(|value| value == gid);
    anyhow::ensure!(
        is_member,
        "service account {name} is not a member of required group {name}"
    );
    Ok(Some(AccountIds { uid, gid }))
}

fn numeric_id(args: &[&str]) -> Result<Option<u32>> {
    let output = Command::new("id")
        .args(args)
        .output()
        .with_context(|| format!("running id {}", args.join(" ")))?;
    if !output.status.success() {
        return Ok(None);
    }
    let text = std::str::from_utf8(&output.stdout).context("id returned non-UTF-8 output")?;
    let id = text
        .trim()
        .parse::<u32>()
        .with_context(|| format!("id {} returned an invalid numeric id", args.join(" ")))?;
    Ok(Some(id))
}

/// Establish and verify ownership for an installer-managed artifact. A real
/// install must stop here rather than leave files unreadable or service-owned.
fn set_owner(path: &Path, uid: u32, gid: u32, label: &str) -> Result<()> {
    let owner = format!("{uid}:{gid}");
    let status = Command::new("chown")
        .arg(&owner)
        .arg(path)
        .status()
        .with_context(|| format!("setting {label} ownership on {}", path.display()))?;
    anyhow::ensure!(
        status.success(),
        "could not establish required {label} ownership on {}",
        path.display()
    );
    let metadata =
        fs::metadata(path).with_context(|| format!("verifying ownership of {}", path.display()))?;
    anyhow::ensure!(
        metadata.uid() == uid && metadata.gid() == gid,
        "ownership verification failed for {}: expected {label} ({uid}:{gid}), found {}:{}",
        path.display(),
        metadata.uid(),
        metadata.gid()
    );
    Ok(())
}

/// Create one installer path component and normalize its mode only when this
/// invocation created it. Existing ancestors may be operator-managed.
fn create_dir_with_mode_if_new(path: &Path, mode: u32) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} on new directory {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(error) => Err(error).with_context(|| format!("creating {}", path.display())),
    }
}

fn systemctl(args: &[&str]) -> Result<()> {
    let status = Command::new("systemctl")
        .args(args)
        .status()
        .with_context(|| format!("running systemctl {}", args.join(" ")))?;
    anyhow::ensure!(
        status.success(),
        "systemctl {} exited with {status}",
        args.join(" ")
    );
    Ok(())
}

/// 32 random bytes, hex-encoded (rand::rng() is a CSPRNG).
fn random_hex_32() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn prompt(label: &str) -> Result<String> {
    print!("{label}: ");
    std::io::stdout().flush().context("flushing stdout")?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading stdin")?;
    let value = line.trim().to_string();
    anyhow::ensure!(!value.is_empty(), "{label} must not be empty");
    Ok(value)
}

fn prompt_password(label: &str) -> Result<String> {
    struct EchoGuard;
    impl Drop for EchoGuard {
        fn drop(&mut self) {
            let _ = Command::new("stty").arg("echo").status();
            println!();
        }
    }

    print!("{label}: ");
    std::io::stdout().flush().context("flushing stdout")?;
    anyhow::ensure!(
        Command::new("stty")
            .arg("-echo")
            .status()
            .context("disabling terminal echo")?
            .success(),
        "could not disable terminal echo; pass --admin-password or ADMIN_PASSWORD instead"
    );
    let _guard = EchoGuard;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading password")?;
    let value = line.trim().to_string();
    anyhow::ensure!(!value.is_empty(), "{label} must not be empty");
    Ok(value)
}
