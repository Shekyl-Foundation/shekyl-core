// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Noise symmetric primitives for the symmetric state and the record layer.
//!
//! A key and a nonce come from the caller. These functions stay in this
//! crate. A handshake drives [`crate::SymmetricState`] and finishes in
//! [`crate::SymmetricState::into_directions`].
//!
//! HMAC-BLAKE2s is RFC 2104 over BLAKE2s-256. `hkdf` is Noise's HKDF:
//! `HMAC(ck, ikm)`, then one block per output. Two outputs for `MixKey`,
//! `Split` and rekey; three for `MixKeyAndHash`. The two-output bytes are
//! the first two of the three-output form.

use blake2::digest::{Digest, Output};
use blake2::Blake2s256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

pub const HASH_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub(crate) fn hash(data: &[u8]) -> [u8; HASH_LEN] {
    let digest = Blake2s256::digest(data);
    let mut out = [0u8; HASH_LEN];
    out.copy_from_slice(&digest);
    out
}

/// RFC 2104 HMAC over BLAKE2s-256.
///
/// `Hmac<Blake2s256>` does not implement `Mac` (BLAKE2 finalizes lazily).
/// `SimpleHmac` does, and it does not wipe its keyed state. The pads and
/// both digests here are `Zeroizing` because this runs on the Noise
/// chaining key.
///
/// **A limit, stated (close-out F4):** BLAKE2s's own hasher state is not
/// wiped. `blake2` 0.10 has no `zeroize` for it, so the compression state
/// that absorbed `ipad` or `opad` (the key, XORed with a constant) is left
/// on the stack when the hasher is dropped. With empty `data`, as in
/// `Split`, the block buffer holds `key ⊕ ipad` itself. Wiping it needs a
/// hasher that zeroizes, which `blake2` 0.11 provides.
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
    // Both digests go straight into wiped buffers: the inner one is keyed
    // material, and the outer one is the derived key.
    let mut inner_digest = Zeroizing::new([0u8; HASH_LEN]);
    let mut inner = Blake2s256::new();
    inner.update(&ipad[..]);
    inner.update(data);
    let inner_out: &mut Output<Blake2s256> = (&mut *inner_digest).into();
    inner.finalize_into(inner_out);
    let mut out = Zeroizing::new([0u8; HASH_LEN]);
    let mut outer = Blake2s256::new();
    outer.update(&opad[..]);
    outer.update(&inner_digest[..]);
    let out_ref: &mut Output<Blake2s256> = (&mut *out).into();
    outer.finalize_into(out_ref);
    out
}

/// Noise `HKDF(ck, ikm)`.
///
/// `N` is 2 or 3. Two outputs are `MixKey`, `Split` and rekey. Three are
/// `MixKeyAndHash`: the chaining key, the handshake-hash mix, and the cipher
/// key, from one HMAC chain. Asking for two does not compute the third block.
pub(crate) fn hkdf<const N: usize>(
    ck: &[u8; HASH_LEN],
    ikm: &[u8],
) -> [Zeroizing<[u8; HASH_LEN]>; N] {
    const {
        assert!(
            N == 2 || N == 3,
            "Noise HKDF yields two outputs, or three for MixKeyAndHash"
        );
    }
    let temp = hmac_blake2s(ck, ikm);
    let mut previous = hmac_blake2s(&temp[..], &[0x01]);
    let mut outputs = std::array::from_fn(|_| Zeroizing::new([0u8; HASH_LEN]));
    let mut index = 0;
    loop {
        if index + 1 == N {
            outputs[index] = previous;
            break;
        }
        // The next block's counter is 0x02, then 0x03. `index` here is 0, or
        // 1 when three outputs were asked for.
        let counter = u8::try_from(index + 2).expect("the HKDF counter is 2 or 3");
        let mut block = Zeroizing::new([0u8; HASH_LEN + 1]);
        block[..HASH_LEN].copy_from_slice(&previous[..]);
        block[HASH_LEN] = counter;
        let next = hmac_blake2s(&temp[..], &block[..]);
        outputs[index] = previous;
        previous = next;
        index += 1;
    }
    outputs
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

/// Run one rekey derivation, `HKDF(chaining_key, record_key)`, and discard it.
///
/// A transport direction runs that same derivation when its nonce reaches
/// the rekey boundary. This function exists so the C5 bench can time those three
/// HMAC-BLAKE2s apart from a session. The derived keys do not leave this crate.
#[cfg(feature = "rekey-timing")]
pub fn rekey_hkdf(chaining_key: &[u8; HASH_LEN], record_key: &[u8; HASH_LEN]) {
    let chaining_key = std::hint::black_box(*chaining_key);
    let record_key = std::hint::black_box(*record_key);
    let [ck, k] = hkdf(&chaining_key, &record_key);
    std::hint::black_box(*ck);
    std::hint::black_box(*k);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three outputs are two outputs and one more block: the same chain, so
    /// the same first two, and a third that is neither.
    #[test]
    fn the_three_output_form_extends_the_two_output_form() {
        let ck = [0x5au8; HASH_LEN];
        let ikm = b"input key material";
        let [two_first, two_second] = hkdf(&ck, ikm);
        let [three_first, three_second, three_third] = hkdf(&ck, ikm);
        assert_eq!(*two_first, *three_first);
        assert_eq!(*two_second, *three_second);
        assert_ne!(*three_third, *three_first);
        assert_ne!(*three_third, *three_second);
    }
}
