//! Encryption at rest for secret material: SNMP community strings and provider
//! credentials. AES-256-GCM with the key from `SECRETS_KEY` (32 bytes, hex). The
//! on-disk blob is `nonce(12) || ciphertext||tag`; the 96-bit nonce is random
//! per seal. Plaintext is NEVER logged or echoed.
//!
//! `SECRETS_KEY` is generated at `--install` time (see install.rs) and lives only
//! in the environment / EnvironmentFile, never in config.toml or the database.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Key, Nonce};
use anyhow::{anyhow, Context, Result};

/// Env var holding the AES-256-GCM master key (64 hex chars = 32 bytes).
pub const SECRETS_KEY_ENV: &str = "SECRETS_KEY";

const NONCE_LEN: usize = 12; // 96-bit GCM nonce

/// Load + validate the 32-byte key from `SECRETS_KEY`. Errors name the variable,
/// never the value.
fn load_key() -> Result<[u8; 32]> {
    let hex_key = std::env::var(SECRETS_KEY_ENV).with_context(|| {
        format!("env {SECRETS_KEY_ENV} not set (needed to encrypt secrets at rest)")
    })?;
    let bytes =
        hex::decode(hex_key.trim()).map_err(|_| anyhow!("{SECRETS_KEY_ENV} is not valid hex"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{SECRETS_KEY_ENV} must decode to exactly 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

/// True if `SECRETS_KEY` is present and well-formed. Used by handlers to fail a
/// write cleanly ("encryption key not configured") instead of panicking.
pub fn is_configured() -> bool {
    load_key().is_ok()
}

/// Encrypt `plaintext` -> `nonce || ciphertext`. Output is opaque; store it in a
/// VARBINARY/BLOB column. The plaintext is dropped immediately after use.
pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    let key = load_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| anyhow!("AES-256-GCM seal failed"))?;
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(nonce.as_slice());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Convenience: seal a string.
pub fn seal_str(plaintext: &str) -> Result<Vec<u8>> {
    seal(plaintext.as_bytes())
}

/// Decrypt a `nonce || ciphertext` blob produced by `seal`. A tampered or
/// wrong-key blob fails authentication and returns an error (never plaintext).
pub fn open(blob: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext too short (missing nonce)"));
    }
    let key = load_key()?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let (nonce_bytes, ciphertext) = blob.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("AES-256-GCM open failed (wrong key or corrupted ciphertext)"))
}

/// Convenience: open to a UTF-8 string (community strings, tokens).
pub fn open_str(blob: &[u8]) -> Result<String> {
    let bytes = open(blob)?;
    String::from_utf8(bytes).map_err(|_| anyhow!("decrypted secret is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed test key so the round-trip test is deterministic and never touches
    // the real environment of a running controller.
    const TEST_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    // SECRETS_KEY is process-global, so the env-var tests must not run
    // concurrently (one removing the var would break another mid-seal). Serialize
    // them on a shared mutex; the lock spans the whole set + run + remove window.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_key<T>(f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: the mutex guarantees no other test touches SECRETS_KEY while
        // we set + run + restore it.
        unsafe { std::env::set_var(SECRETS_KEY_ENV, TEST_KEY_HEX) };
        let out = f();
        unsafe { std::env::remove_var(SECRETS_KEY_ENV) };
        out
    }

    #[test]
    fn round_trip() {
        with_key(|| {
            let blob = seal_str("public-community-123").unwrap();
            // ciphertext must not contain the plaintext.
            assert!(!blob.windows(7).any(|w| w == b"public-"));
            assert_eq!(open_str(&blob).unwrap(), "public-community-123");
        });
    }

    #[test]
    fn nonce_is_random_per_seal() {
        with_key(|| {
            let a = seal_str("same").unwrap();
            let b = seal_str("same").unwrap();
            assert_ne!(
                a, b,
                "two seals of the same plaintext must differ (random nonce)"
            );
            assert_eq!(open_str(&a).unwrap(), "same");
            assert_eq!(open_str(&b).unwrap(), "same");
        });
    }

    #[test]
    fn tamper_is_rejected() {
        with_key(|| {
            let mut blob = seal_str("secret").unwrap();
            let last = blob.len() - 1;
            blob[last] ^= 0xff; // flip a tag byte
            assert!(open(&blob).is_err());
        });
    }
}
