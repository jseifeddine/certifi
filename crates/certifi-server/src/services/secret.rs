//! At-rest encryption for application secrets (e.g. PFX passwords).
//!
//! Uses AES-256-GCM with a key derived from `COOKIE_KEY` via SHA-256.
//! Storage format: base64(12-byte nonce || ciphertext || 16-byte auth tag).
//!
//! Rotating COOKIE_KEY invalidates existing ciphertexts — the caller (the
//! `pfx-password` endpoint) treats decryption failures as "no stored password"
//! so the user can simply generate a fresh one.

use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};

fn derive_key(cookie_key: &[u8]) -> LessSafeKey {
    let key_material = digest(&SHA256, cookie_key);
    let unbound = UnboundKey::new(&AES_256_GCM, key_material.as_ref())
        .expect("AES-256 key derivation cannot fail with 32-byte input");
    LessSafeKey::new(unbound)
}

pub fn encrypt(plaintext: &str, cookie_key: &[u8]) -> Result<String> {
    let key = derive_key(cookie_key);
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("RNG failure"))?;

    let mut buf = plaintext.as_bytes().to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("AES-GCM seal failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(STANDARD.encode(out))
}

/// Produce an Argon2 hash that cannot match any user-supplied password.
/// Used when provisioning an OIDC-only account: we still need *some* hash to
/// satisfy `users.password_hash NOT NULL`, but the user shouldn't be able to
/// authenticate via the local login form until they explicitly set one.
pub fn random_password_hash() -> Result<String> {
    use argon2::password_hash::{rand_core::OsRng, SaltString};
    use argon2::{Argon2, PasswordHasher};
    use rand::Rng;
    let salt = SaltString::generate(&mut OsRng);
    // 64 random bytes is plenty; the user can never recover this anyway.
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(64)
        .collect();
    Argon2::default()
        .hash_password(&random_bytes, &salt)
        .map_err(|e| anyhow!("argon2: {}", e))
        .map(|h| h.to_string())
}

pub fn decrypt(token: &str, cookie_key: &[u8]) -> Result<String> {
    let raw = STANDARD
        .decode(token)
        .map_err(|_| anyhow!("malformed ciphertext"))?;
    if raw.len() < NONCE_LEN {
        return Err(anyhow!("ciphertext too short"));
    }
    let (nonce_bytes, body) = raw.split_at(NONCE_LEN);
    let nonce_arr: [u8; NONCE_LEN] = nonce_bytes.try_into().map_err(|_| anyhow!("nonce slice"))?;

    let key = derive_key(cookie_key);
    let mut buf = body.to_vec();
    let nonce = Nonce::assume_unique_for_key(nonce_arr);
    let plain = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| anyhow!("AES-GCM decrypt failed (key changed?)"))?;
    String::from_utf8(plain.to_vec()).map_err(|_| anyhow!("invalid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = b"some-random-cookie-key-of-any-length";
        let ct = encrypt("hunter2", key).unwrap();
        assert_eq!(decrypt(&ct, key).unwrap(), "hunter2");
    }

    #[test]
    fn wrong_key_fails() {
        let ct = encrypt("hunter2", b"key-a").unwrap();
        assert!(decrypt(&ct, b"key-b").is_err());
    }

    #[test]
    fn fresh_ciphertext_each_call() {
        let key = b"k";
        let a = encrypt("x", key).unwrap();
        let b = encrypt("x", key).unwrap();
        assert_ne!(a, b, "nonce must randomize ciphertext");
    }
}
