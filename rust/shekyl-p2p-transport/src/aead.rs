// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise symmetric primitives shared by the handshake and the record layer.
//!
//! HMAC-BLAKE2s is RFC 2104 over BLAKE2s-256. `hkdf` is Noise's two-output
//! HKDF: `HMAC(ck, ikm)` then `HMAC(temp, 0x01)` and `HMAC(temp, out1 || 0x02)`.

use blake2::digest::Digest;
use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

pub(crate) const HASH_LEN: usize = 32;
pub(crate) const TAG_LEN: usize = 16;

pub(crate) fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Blake2s256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// RFC 2104 HMAC over BLAKE2s-256.
///
/// The `hmac` crate cannot wrap this hash: BLAKE2s finalizes lazily (the last
/// block is flagged), and `hmac`'s `BlockSizeUser` bound requires an eager
/// buffer. This is the Noise `HMAC(key, data)` those two facts leave us.
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
pub(crate) fn hkdf(
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

pub(crate) fn nonce(n: u64) -> Nonce {
    let mut raw = [0u8; 12];
    raw[4..].copy_from_slice(&n.to_le_bytes());
    Nonce::from(raw)
}

pub(crate) fn seal(key: &[u8; HASH_LEN], n: u64, ad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
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

pub(crate) fn open(key: &[u8; HASH_LEN], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
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
