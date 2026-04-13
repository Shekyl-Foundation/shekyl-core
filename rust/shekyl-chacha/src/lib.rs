//! XChaCha20 stream cipher and XChaCha20-Poly1305 AEAD for Shekyl wallet
//! and cache encryption.
//!
//! Wraps the NCC-audited RustCrypto `chacha20` and `chacha20poly1305` crates.
//! All functions use XChaCha20 (192-bit nonce) to eliminate collision risk
//! for randomly-generated nonces.

#![deny(unsafe_code)]

use chacha20::XChaCha20;
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use cipher::{KeyIvInit, StreamCipher};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;
pub const TAG_SIZE: usize = 16;

/// Apply XChaCha20 keystream to `data` in-place (encrypt or decrypt).
///
/// XChaCha20 is its own inverse: applying the same key + nonce to
/// ciphertext recovers the plaintext.
pub fn xchacha20_apply(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE], data: &mut [u8]) {
    let mut cipher = XChaCha20::new(key.into(), nonce.into());
    cipher.apply_keystream(data);
}

/// Apply XChaCha20 keystream, reading from `src` and writing to `dst`.
///
/// `src` and `dst` must be the same length; panics otherwise.
pub fn xchacha20_apply_copy(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    src: &[u8],
    dst: &mut [u8],
) {
    assert_eq!(src.len(), dst.len(), "src and dst length mismatch");
    dst.copy_from_slice(src);
    xchacha20_apply(key, nonce, dst);
}

/// AEAD error type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AeadError {
    AuthenticationFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AeadError::AuthenticationFailed => write!(f, "AEAD authentication failed"),
        }
    }
}

impl std::error::Error for AeadError {}

/// Encrypt `plaintext` with XChaCha20-Poly1305 AEAD, binding `aad` into the
/// Poly1305 tag. Returns `nonce || ciphertext || tag`.
///
/// The nonce is randomly generated from `OsRng`.
pub fn encrypt_with_aad(
    key: &[u8; KEY_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    use rand_core::OsRng;
    use rand_core::RngCore;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);

    let cipher = XChaCha20Poly1305::new(key.into());
    let ct = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .expect("encryption should never fail with valid key/nonce");

    let mut out = Vec::with_capacity(NONCE_SIZE + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Decrypt `nonce || ciphertext || tag` with XChaCha20-Poly1305 AEAD.
///
/// Returns the plaintext on success, or `AeadError::AuthenticationFailed` if
/// the tag or AAD doesn't match.
pub fn decrypt_with_aad(
    key: &[u8; KEY_SIZE],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if data.len() < NONCE_SIZE + TAG_SIZE {
        return Err(AeadError::AuthenticationFailed);
    }
    let nonce_bytes: [u8; NONCE_SIZE] = data[..NONCE_SIZE]
        .try_into()
        .map_err(|_| AeadError::AuthenticationFailed)?;
    let nonce = chacha20poly1305::XNonce::from(nonce_bytes);
    let ciphertext_and_tag = &data[NONCE_SIZE..];

    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(&nonce, Payload { msg: ciphertext_and_tag, aad })
        .map_err(|_| AeadError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let key = [0x42u8; KEY_SIZE];
        let nonce = [0x24u8; NONCE_SIZE];
        let plaintext = b"Shekyl wallet encryption test payload";
        let mut buf = plaintext.to_vec();

        xchacha20_apply(&key, &nonce, &mut buf);
        assert_ne!(&buf[..], &plaintext[..], "ciphertext must differ from plaintext");

        xchacha20_apply(&key, &nonce, &mut buf);
        assert_eq!(&buf[..], &plaintext[..], "decryption must recover plaintext");
    }

    #[test]
    fn copy_variant() {
        let key = [0xABu8; KEY_SIZE];
        let nonce = [0xCDu8; NONCE_SIZE];
        let plaintext = b"copy variant test";
        let mut ciphertext = vec![0u8; plaintext.len()];

        xchacha20_apply_copy(&key, &nonce, plaintext, &mut ciphertext);
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mut recovered = vec![0u8; ciphertext.len()];
        xchacha20_apply_copy(&key, &nonce, &ciphertext, &mut recovered);
        assert_eq!(&recovered[..], &plaintext[..]);
    }

    #[test]
    fn empty_data() {
        let key = [0u8; KEY_SIZE];
        let nonce = [0u8; NONCE_SIZE];
        let mut buf = vec![];
        xchacha20_apply(&key, &nonce, &mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn different_nonces_produce_different_ciphertext() {
        let key = [0x01u8; KEY_SIZE];
        let nonce_a = [0x0Au8; NONCE_SIZE];
        let nonce_b = [0x0Bu8; NONCE_SIZE];
        let plaintext = b"nonce sensitivity";

        let mut ct_a = plaintext.to_vec();
        let mut ct_b = plaintext.to_vec();
        xchacha20_apply(&key, &nonce_a, &mut ct_a);
        xchacha20_apply(&key, &nonce_b, &mut ct_b);
        assert_ne!(ct_a, ct_b);
    }

    #[test]
    fn aead_round_trip() {
        let key = [0x77u8; KEY_SIZE];
        let aad = b"cache_format_version_1";
        let plaintext = b"wallet cache payload with secrets";

        let encrypted = encrypt_with_aad(&key, aad, plaintext);
        assert!(encrypted.len() > NONCE_SIZE + TAG_SIZE);
        assert_ne!(&encrypted[NONCE_SIZE..encrypted.len() - TAG_SIZE], &plaintext[..]);

        let decrypted = decrypt_with_aad(&key, aad, &encrypted).unwrap();
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn aead_wrong_key_rejected() {
        let key = [0x77u8; KEY_SIZE];
        let wrong_key = [0x88u8; KEY_SIZE];
        let aad = b"version";
        let plaintext = b"secret data";

        let encrypted = encrypt_with_aad(&key, aad, plaintext);
        let result = decrypt_with_aad(&wrong_key, aad, &encrypted);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn aead_wrong_aad_rejected() {
        let key = [0x77u8; KEY_SIZE];
        let plaintext = b"secret data";

        let encrypted = encrypt_with_aad(&key, b"version_1", plaintext);
        let result = decrypt_with_aad(&key, b"version_2", &encrypted);
        assert_eq!(result, Err(AeadError::AuthenticationFailed),
            "AAD mismatch must fail authentication");
    }

    #[test]
    fn aead_tampered_ciphertext_rejected() {
        let key = [0x77u8; KEY_SIZE];
        let aad = b"version";
        let plaintext = b"secret data";

        let mut encrypted = encrypt_with_aad(&key, aad, plaintext);
        let mid = NONCE_SIZE + (encrypted.len() - NONCE_SIZE) / 2;
        encrypted[mid] ^= 0xFF;

        let result = decrypt_with_aad(&key, aad, &encrypted);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn aead_too_short_rejected() {
        let key = [0x77u8; KEY_SIZE];
        let short = vec![0u8; NONCE_SIZE + TAG_SIZE - 1];
        let result = decrypt_with_aad(&key, b"", &short);
        assert_eq!(result, Err(AeadError::AuthenticationFailed));
    }

    #[test]
    fn aead_empty_plaintext() {
        let key = [0x77u8; KEY_SIZE];
        let aad = b"empty test";
        let encrypted = encrypt_with_aad(&key, aad, b"");
        assert_eq!(encrypted.len(), NONCE_SIZE + TAG_SIZE);
        let decrypted = decrypt_with_aad(&key, aad, &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }
}
