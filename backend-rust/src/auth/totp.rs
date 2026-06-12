//! TOTP 2FA (RFC 6238: SHA-1, 30s step, 6 digits, issuer "Rerouter") plus
//! single-use recovery codes. Secrets are stored encrypted (SECRETS_KEY,
//! AES-256-GCM); recovery codes are stored hashed (see password.rs).
//! Compatible with Google Authenticator / Authy / 1Password.

use anyhow::{anyhow, Result};
use rand::distr::{Alphanumeric, SampleString};
use totp_rs::{Algorithm, Secret, TOTP};

pub const ISSUER: &str = "Rerouter";
pub const RECOVERY_CODE_COUNT: usize = 8;

fn instance(secret: Secret, account_email: &str) -> Result<TOTP> {
    TOTP::new(
        Algorithm::SHA1,
        6,
        1, // skew: accept ±1 step
        30,
        secret.to_bytes().map_err(|e| anyhow!("decoding totp secret: {e:?}"))?,
        Some(ISSUER.to_string()),
        account_email.to_string(),
    )
    .map_err(|e| anyhow!("building totp: {e}"))
}

/// Begin enrollment: generate a random base32 secret and the otpauth:// URL the
/// SPA renders as a QR code. The secret stays UNCONFIRMED (encrypted at rest)
/// until the user proves possession via `verify`; only then is
/// two_factor_confirmed_at set and the recovery codes issued (shown once).
pub fn enroll(account_email: &str) -> Result<(String, String)> {
    let secret = Secret::generate_secret();
    let otpauth_url = instance(secret.clone(), account_email)?.get_url();
    Ok((secret.to_encoded().to_string(), otpauth_url))
}

/// Verify a 6-digit code against the (decrypted) base32 secret, ±1 step.
pub fn verify(secret_base32: &str, code: &str, account_email: &str) -> Result<bool> {
    let totp = instance(Secret::Encoded(secret_base32.to_string()), account_email)?;
    totp.check_current(code).map_err(|e| anyhow!("system time: {e}"))
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

// TODO(milestone 1): consume_recovery_code(user, code) — constant-time match
// against the stored hashes, single-use (delete on match), audited.
