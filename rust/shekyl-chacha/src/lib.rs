//! XChaCha20 stream cipher for Shekyl wallet and cache encryption.
//!
//! Wraps the NCC-audited RustCrypto `chacha20` crate, exposing only
//! XChaCha20 (192-bit nonce).  The 24-byte nonce eliminates collision
//! risk for randomly-generated nonces, which is how Shekyl uses them.

#![deny(unsafe_code)]

use chacha20::XChaCha20;
use cipher::{KeyIvInit, StreamCipher};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24;

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
}
