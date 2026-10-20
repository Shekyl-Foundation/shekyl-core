// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! mac1: the check a daemon makes on message 1 before it uses a long-term
//! key (`RPC_CHANNEL.md` §4.3).
//!
//! Message 1 travels as the Noise message followed by 16 bytes of mac1:
//! keyed BLAKE2s over the Noise message, under a key that is BLAKE2s-256 of
//! [`MAC1_DST`] followed by the daemon's public bundle (its X25519 key, then
//! its ML-KEM-768 encapsulation key, the order §5 fixes). The bundle goes
//! only to clients that will be enrolled, so a sender without it cannot
//! write a mac1 the daemon accepts, and the daemon drops that message
//! without a reply and without touching its static keys.
//!
//! The mac1 is outside the Noise message: it is not hashed into the
//! transcript, and the Noise bytes are what they were before it existed.
//! The key is derived from public material only. Holding it is holding the
//! bundle, which §4.3 already treats as a probing capability.

use blake2::digest::consts::U16;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac};

use crate::{MAC1_DST, MAC1_LEN, MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

/// The length of the mac1 key.
pub(crate) const MAC1_KEY_LEN: usize = 32;

/// BLAKE2s-256 of [`MAC1_DST`] then the bundle.
pub(crate) fn mac1_key(
    x25519: &[u8; X25519_PUBLIC_LEN],
    mlkem_ek: &[u8; MLKEM768_EK_LEN],
) -> [u8; MAC1_KEY_LEN] {
    let mut hasher = Blake2s256::new();
    hasher.update(MAC1_DST);
    hasher.update(x25519);
    hasher.update(mlkem_ek);
    hasher.finalize().into()
}

fn keyed(key: &[u8; MAC1_KEY_LEN]) -> Blake2sMac<U16> {
    // A 32-byte key is within BLAKE2s's limit, so this cannot fail.
    <Blake2sMac<U16> as Mac>::new_from_slice(key).expect("a 32-byte BLAKE2s key")
}

/// The mac1 of a Noise message 1 under `key`.
pub(crate) fn mac1(key: &[u8; MAC1_KEY_LEN], noise_message1: &[u8]) -> [u8; MAC1_LEN] {
    let mut mac = keyed(key);
    mac.update(noise_message1);
    mac.finalize().into_bytes().into()
}

/// Whether `tag` is the mac1 of `noise_message1` under `key`, compared in
/// constant time.
pub(crate) fn verify(key: &[u8; MAC1_KEY_LEN], noise_message1: &[u8], tag: &[u8]) -> bool {
    let mut mac = keyed(key);
    mac.update(noise_message1);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The key depends on every byte of the bundle and on the label; the
    /// mac depends on every byte of the message.
    #[test]
    fn the_key_and_the_mac_move_with_their_inputs() {
        let x = [0x11; X25519_PUBLIC_LEN];
        let ek = [0x22; MLKEM768_EK_LEN];
        let key = mac1_key(&x, &ek);
        let mut other_x = x;
        other_x[31] ^= 1;
        let mut other_ek = ek;
        other_ek[0] ^= 1;
        assert_ne!(key, mac1_key(&other_x, &ek));
        assert_ne!(key, mac1_key(&x, &other_ek));

        let message = [0x5a; 64];
        let tag = mac1(&key, &message);
        assert!(verify(&key, &message, &tag));
        let mut changed = message;
        changed[63] ^= 1;
        assert!(!verify(&key, &changed, &tag));
        assert!(!verify(&mac1_key(&other_x, &ek), &message, &tag));
        assert!(!verify(&key, &message, &tag[..MAC1_LEN - 1]));
    }

    /// Known answer, computed independently with Python's `hashlib`:
    /// `blake2s(MAC1_DST + bundle)` for the key, and
    /// `blake2s(message, key=key, digest_size=16)` for the mac. A
    /// 2,320-byte message, the length of a Noise message 1.
    #[test]
    fn known_answer_from_an_independent_implementation() {
        let key = mac1_key(&[0x11; X25519_PUBLIC_LEN], &[0x22; MLKEM768_EK_LEN]);
        assert_eq!(
            hex::encode(key),
            "5b837de470bcb848b6f23f71c73ce2131dd9dc96c10a586df39e22563df749b2"
        );
        let message: Vec<u8> = (0..2_320_usize)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        assert_eq!(
            hex::encode(mac1(&key, &message)),
            "81422da8958bceb200e31cb50c35f639"
        );
    }
}
