// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise symmetric primitives shared by the handshakes and the record layer.
//!
//! These are raw: a key and a nonce come from the caller. They are public
//! because two crates build handshakes on them, not because they are a
//! general-purpose API. Nothing outside a Noise handshake or this crate's
//! record layer should call them.
//!
//! HMAC-BLAKE2s is RFC 2104 over BLAKE2s-256. `hkdf` is Noise's two-output
//! HKDF: `HMAC(ck, ikm)` then `HMAC(temp, 0x01)` and `HMAC(temp, out1 || 0x02)`.

use blake2::digest::Digest;
use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

pub const HASH_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// One hash-length output of the key derivation, wiped when dropped.
pub type HashOutput = Zeroizing<[u8; HASH_LEN]>;

pub fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Blake2s256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// RFC 2104 HMAC over BLAKE2s-256.
///
/// `Hmac<Blake2s256>` does not implement `Mac` (BLAKE2 finalizes lazily).
/// `SimpleHmac` does, and it does not wipe its keyed state. The pads here
/// are `Zeroizing` because this runs on the Noise chaining key.
fn hmac_blake2s(key: &[u8], data: &[u8]) -> Zeroizing<[u8; HASH_LEN]> {
    const BLOCK: usize = 64;
    let mut key_block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        let hashed = hash(key);
        key_block[..HASH_LEN].copy_from_slice(&hashed);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }
    let mut inner = Blake2s256::new();
    inner.update(&ipad[..]);
    inner.update(data);
    let inner = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(&opad[..]);
    outer.update(inner);
    let digest = outer.finalize();
    let mut out = Zeroizing::new([0u8; HASH_LEN]);
    out.copy_from_slice(&digest);
    out
}

/// Noise `HKDF(ck, ikm) -> (output1, output2)`.
pub fn hkdf(
    ck: &[u8; HASH_LEN],
    ikm: &[u8],
) -> (Zeroizing<[u8; HASH_LEN]>, Zeroizing<[u8; HASH_LEN]>) {
    let temp = hmac_blake2s(ck, ikm);
    let out1 = hmac_blake2s(&temp[..], &[0x01]);
    let mut second = Zeroizing::new([0u8; HASH_LEN + 1]);
    second[..HASH_LEN].copy_from_slice(&out1[..]);
    second[HASH_LEN] = 0x02;
    let out2 = hmac_blake2s(&temp[..], &second[..]);
    (out1, out2)
}

/// Noise `HKDF(ck, ikm) -> (output1, output2, output3)`, the three-output
/// form `MixKeyAndHash` uses. Its first two outputs are [`hkdf`]'s.
pub fn hkdf3(ck: &[u8; HASH_LEN], ikm: &[u8]) -> (HashOutput, HashOutput, HashOutput) {
    let temp = hmac_blake2s(ck, ikm);
    let out1 = hmac_blake2s(&temp[..], &[0x01]);
    let mut second = Zeroizing::new([0u8; HASH_LEN + 1]);
    second[..HASH_LEN].copy_from_slice(&out1[..]);
    second[HASH_LEN] = 0x02;
    let out2 = hmac_blake2s(&temp[..], &second[..]);
    let mut third = Zeroizing::new([0u8; HASH_LEN + 1]);
    third[..HASH_LEN].copy_from_slice(&out2[..]);
    third[HASH_LEN] = 0x03;
    let out3 = hmac_blake2s(&temp[..], &third[..]);
    (out1, out2, out3)
}

pub(crate) fn nonce(n: u64) -> Nonce {
    let mut raw = [0u8; 12];
    raw[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(raw)
}

pub fn seal(key: &[u8; HASH_LEN], n: u64, ad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .encrypt(
            &nonce(n),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .ok()
}

pub fn open(key: &[u8; HASH_LEN], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher
        .decrypt(
            &nonce(n),
            Payload {
                msg: ciphertext,
                aad: ad,
            },
        )
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `hkdf3` is `hkdf` with one more block: the same chain, so the same
    /// first two outputs, and a third that is neither.
    #[test]
    fn the_three_output_form_extends_the_two_output_form() {
        let ck = [0x5au8; HASH_LEN];
        let ikm = b"input key material";
        let (a1, a2) = hkdf(&ck, ikm);
        let (b1, b2, b3) = hkdf3(&ck, ikm);
        assert_eq!(*a1, *b1);
        assert_eq!(*a2, *b2);
        assert_ne!(*b3, *b1);
        assert_ne!(*b3, *b2);
    }
}
