//! Argon2id password hashing/verification (PHC strings in users.password).
//! Also used to hash single-use recovery codes. Constant-time verification via
//! the argon2 crate; never log or echo plaintext material.

use anyhow::{anyhow, Result};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;

/// Hash a password (or recovery code) with Argon2id and a random salt.
pub fn hash(plain: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default() // Argon2id v19, default params
        .hash_password(plain.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("argon2 hash: {e}"))
}

/// Verify a password against a stored PHC string. Returns Ok(false) on
/// mismatch; Err only for malformed stored hashes.
pub fn verify(plain: &str, phc: &str) -> Result<bool> {
    let parsed = PasswordHash::new(phc).map_err(|e| anyhow!("parsing stored hash: {e}"))?;
    Ok(Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok())
}
