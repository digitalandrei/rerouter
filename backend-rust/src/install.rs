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
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
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
# SECRETS_KEY is the AES-256-GCM key for provider credentials encrypted at rest.
SESSION_SECRET={session_secret}
SECRETS_KEY={secrets_key}
";

/// `--install`: lay down the controller under `<prefix>/srv/rerouter` plus the
/// systemd unit. Safe to re-run (upgrade path: binary + unit only).
pub fn run_install(prefix: &str) -> Result<()> {
    let prefix_is_root = prefix == "/";
    let prefix_path = Path::new(prefix);
    let install_dir = prefix_path.join("srv/rerouter");
    let unit_dir = prefix_path.join("etc/systemd/system");
    let unit_path = unit_dir.join("rerouter-controller.service");

    tracing::info!(
        event_type = "install_started",
        prefix,
        install_dir = %install_dir.display(),
        "installing rerouter-controller"
    );

    // b. system user (tolerate failure/absence; never attempt for test prefixes).
    let have_user = ensure_system_user(prefix_is_root);

    fs::create_dir_all(&install_dir)
        .with_context(|| format!("creating {}", install_dir.display()))?;
    fs::create_dir_all(&unit_dir).with_context(|| format!("creating {}", unit_dir.display()))?;

    // c. binary: copy ourselves in via tmp+rename so an upgrade replaces a
    // running binary atomically (plain copy would hit ETXTBSY).
    let exe = std::env::current_exe().context("resolving current executable")?;
    let bin_dest = install_dir.join("rerouter-controller");
    let bin_tmp = install_dir.join(".rerouter-controller.tmp");
    fs::copy(&exe, &bin_tmp)
        .with_context(|| format!("copying {} -> {}", exe.display(), bin_tmp.display()))?;
    fs::set_permissions(&bin_tmp, fs::Permissions::from_mode(0o755))
        .context("chmod 0755 on binary")?;
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
        if have_user {
            chown_rerouter(&env_path);
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
        fs::write(&config_path, CONFIG_TEMPLATE)
            .with_context(|| format!("writing {}", config_path.display()))?;
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
    };
    let name = match name {
        Some(v) => v,
        None => prompt("Admin name")?,
    };

    let existing: Option<u64> = sqlx::query_scalar("SELECT id FROM users WHERE email = ?")
        .bind(&email)
        .fetch_optional(pool)
        .await
        .context("looking up existing user")?;

    let (user_id, created) = match existing {
        Some(id) => (id, false),
        None => {
            let plain = match password_plain {
                Some(v) => v,
                // No extra crates allowed for no-echo input — warn instead.
                None => prompt(
                    "Admin password (input will echo; prefer --admin-password/ADMIN_PASSWORD)",
                )?,
            };
            anyhow::ensure!(
                plain.len() >= 12,
                "admin password must be at least 12 characters"
            );
            let phc = password::hash(&plain)?;
            let res = sqlx::query(
                "INSERT INTO users (name, email, password, two_factor_confirmed_at) VALUES (?, ?, ?, NULL)",
            )
            .bind(&name)
            .bind(&email)
            .bind(&phc)
            .execute(pool)
            .await
            .context("inserting admin user")?;
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
    if role_rows > 0 {
        println!("attached role 'superadmin' to user id {user_id}");
    } else {
        println!("role 'superadmin' was already attached to user id {user_id}");
    }
    Ok(())
}

/// Create the 'rerouter' system user when installing for real (prefix "/").
/// Failure or absence is tolerated with a warning — and for prefixed (test)
/// installs we never touch the host's user database at all. Returns whether
/// the user exists afterwards (drives chown attempts).
fn ensure_system_user(prefix_is_root: bool) -> bool {
    let exists = Command::new("id")
        .args(["-u", "rerouter"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if exists {
        return true;
    }
    if !prefix_is_root {
        tracing::warn!(
            event_type = "install_user_skipped",
            "system user 'rerouter' missing — tolerated for prefixed (test) install; \
             on a real host: useradd -r -s /usr/sbin/nologin rerouter"
        );
        return false;
    }
    match Command::new("useradd")
        .args(["-r", "-s", "/usr/sbin/nologin", "rerouter"])
        .status()
    {
        Ok(s) if s.success() => {
            tracing::info!(
                event_type = "install_user_created",
                "created system user 'rerouter'"
            );
            true
        }
        _ => {
            tracing::warn!(
                event_type = "install_user_failed",
                "could not create system user 'rerouter' — create it manually: \
                 useradd -r -s /usr/sbin/nologin rerouter"
            );
            false
        }
    }
}

/// Best-effort chown to rerouter:rerouter (warn, never fail the install).
fn chown_rerouter(path: &Path) {
    let ok = Command::new("chown")
        .arg("rerouter:rerouter")
        .arg(path)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        tracing::warn!(
            event_type = "install_chown_failed",
            path = %path.display(),
            "could not chown to rerouter:rerouter — fix ownership manually"
        );
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
