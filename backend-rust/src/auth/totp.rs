//! TOTP 2FA (RFC 6238: SHA-1, 30s step, 6 digits, issuer "Rerouter") plus
//! single-use recovery codes. Secrets are stored encrypted (SECRETS_KEY,
//! AES-256-GCM); recovery codes are stored hashed (see password.rs).
//! Compatible with Google Authenticator / Authy / 1Password.

use anyhow::{anyhow, Result};
use rand::distr::{Alphanumeric, SampleString};
use std::time::{SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, Secret, TOTP};

/// Default TOTP issuer label when TWO_FACTOR_ISSUER is unset.
pub const DEFAULT_ISSUER: &str = "Rerouter";
pub const RECOVERY_CODE_COUNT: usize = 8;

/// The issuer label shown in authenticator apps: TWO_FACTOR_ISSUER from the
/// environment (documented in deployment.md / config.example.toml), falling back
/// to [`DEFAULT_ISSUER`]. Read per call so ops can change it without a rebuild.
fn issuer() -> String {
    std::env::var("TWO_FACTOR_ISSUER")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_ISSUER.to_string())
}

fn instance(secret: Secret, account_email: &str) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1, // skew: accept ±1 step
        30,
        secret
            .to_bytes()
            .map_err(|e| anyhow!("decoding totp secret: {e:?}"))?,
        Some(issuer()),
        account_email.to_string(),
    )
    .map_err(|e| anyhow!("building totp: {e}"))
}

/// Begin enrollment: generate a random base32 secret and the otpauth:// URL the
/// SPA renders as a QR code. The secret stays UNCONFIRMED (encrypted at rest)
/// until the user proves possession via [`matched_step`]; only then is
/// two_factor_confirmed_at set and the recovery codes issued (shown once).
pub fn enroll(account_email: &str) -> Result<(String, String)> {
    let secret = Secret::generate_secret();
    let otpauth_url = instance(secret.clone(), account_email)?.get_url();
    Ok((secret.to_encoded().to_string(), otpauth_url))
}

/// Rebuild enrollment material for an already-persisted unconfirmed secret. A
/// repeated password login must not replace the secret and let a password-only
/// attacker race the legitimate enrollment.
pub fn enrollment_for_secret(secret_base32: &str, account_email: &str) -> Result<String> {
    instance(Secret::Encoded(secret_base32.to_string()), account_email).map(|totp| totp.get_url())
}

/// Return the RFC 6238 time-step counter matched by a valid code. The caller
/// persists this value atomically to reject replay across concurrent sessions.
pub fn matched_step(secret_base32: &str, code: &str, account_email: &str) -> Result<Option<u64>> {
    let totp = instance(Secret::Encoded(secret_base32.to_string()), account_email)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow!("system time: {e}"))?
        .as_secs();
    let code = code.trim();
    if !totp.check(code, now) {
        return Ok(None);
    }
    let current = now / 30;
    for step in current.saturating_sub(1)..=current.saturating_add(1) {
        if totp.generate(step * 30) == code {
            return Ok(Some(step));
        }
    }
    Ok(None)
}

#[cfg(test)]
pub(crate) fn current_code(secret_base32: &str, account_email: &str) -> Result<String> {
    instance(Secret::Encoded(secret_base32.to_string()), account_email)?
        .generate_current()
        .map_err(|e| anyhow!("system time: {e}"))
}

/// Generate 8 single-use recovery codes (display once; persist Argon2id hashes
/// only). Consuming a code MUST remove its hash and emit a 2fa_recovery_used
/// security alert — those are always sent immediately.
pub fn generate_recovery_codes() -> Vec<String> {
    let mut rng = rand::rng();
    (0..RECOVERY_CODE_COUNT)
        .map(|_| {
            let raw = Alphanumeric.sample_string(&mut rng, 10).to_lowercase();
            format!("{}-{}", &raw[..5], &raw[5..])
        })
        .collect()
}

// Recovery-code consumption lives in `auth::consume_recovery_code` (auth/mod.rs):
// constant-time match against the stored Argon2id hashes, single-use (deleted on
// match) under `SELECT ... FOR UPDATE`, emitting the `2fa_recovery_used` security
// alert. It lives there because it needs the DB pool + session context.
