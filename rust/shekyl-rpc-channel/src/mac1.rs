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
//!
//! Each label is held at its input's type: the key derives from a
//! [`StaticPublic`] bundle, and a busy reply answers a [`Mac1Tag`], which
//! only [`Mac1Key::mac1`] makes and [`Mac1Key::verify`] hands back.

use blake2::digest::consts::U16;
use blake2::digest::{Digest, Mac};
use blake2::{Blake2s256, Blake2sMac};
use subtle::ConstantTimeEq;

use crate::handshake::StaticPublic;
use crate::{BUSY_LEN, MAC1_LEN};

/// The label the mac1 key is derived from: the key is BLAKE2s-256 of these
/// bytes followed by the daemon's public bundle (`RPC_CHANNEL.md` §4.3).
const MAC1_DST: &[u8] = b"shekyl/rpc-mac1-v1";

/// The label in front of what a busy reply authenticates: the reply is
/// keyed BLAKE2s-128 under the mac1 key over these bytes followed by the
/// mac1 of the message 1 it answers (`RPC_CHANNEL.md` §4.3, ruled
/// 2026-10-20).
const BUSY_DST: &[u8] = b"shekyl/rpc-busy-v1";

/// The length of the mac1 key.
const MAC1_KEY_LEN: usize = 32;

/// The mac1 key of one daemon's bundle.
pub(crate) struct Mac1Key([u8; MAC1_KEY_LEN]);

/// The mac1 of one message 1: made under a bundle's key, or read off the
/// wire and proved by recomputing it. There is no way to make one from
/// bytes, so a busy reply answers only a message 1 that passed mac1.
#[derive(Clone, Copy)]
pub struct Mac1Tag([u8; MAC1_LEN]);

impl Mac1Tag {
    /// The tag as it travels after the Noise message.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MAC1_LEN] {
        &self.0
    }
}

impl Mac1Key {
    /// BLAKE2s-256 of [`MAC1_DST`] then the bundle.
    pub(crate) fn of(bundle: &StaticPublic) -> Self {
        let mut hasher = Blake2s256::new();
        hasher.update(MAC1_DST);
        hasher.update(bundle.x25519());
        hasher.update(bundle.mlkem_ek());
        Self(hasher.finalize().into())
    }

    fn keyed(&self) -> Blake2sMac<U16> {
        // A 32-byte key is within BLAKE2s's limit, so this cannot fail.
        <Blake2sMac<U16> as Mac>::new_from_slice(&self.0).expect("a 32-byte BLAKE2s key")
    }

    /// The mac1 of a Noise message 1.
    pub(crate) fn mac1(&self, noise_message1: &[u8]) -> Mac1Tag {
        let mut mac = self.keyed();
        mac.update(noise_message1);
        Mac1Tag(mac.finalize().into_bytes().into())
    }

    /// The tag, when `tag` is the mac1 of `noise_message1`: compared in
    /// constant time, so the time taken does not say how many leading bytes
    /// of a forgery were right.
    pub(crate) fn verify(&self, noise_message1: &[u8], tag: &[u8]) -> Option<Mac1Tag> {
        let expected = self.mac1(noise_message1);
        (tag.len() == MAC1_LEN && bool::from(tag.ct_eq(expected.0.as_slice()))).then_some(expected)
    }

    /// The busy reply to the message 1 whose mac1 is `tag`: keyed
    /// BLAKE2s-128 over [`BUSY_DST`] then that mac1. It answers one message
    /// 1 only, since every message 1 carries a fresh ephemeral and so a
    /// fresh mac1.
    pub(crate) fn busy(&self, tag: &Mac1Tag) -> [u8; BUSY_LEN] {
        let mut mac = self.keyed();
        mac.update(BUSY_DST);
        mac.update(&tag.0);
        mac.finalize().into_bytes().into()
    }
}

/// Whether `reply` is `expected`. A different length is not busy; the bytes
/// of a same-length reply are compared without an early exit, so the time
/// taken does not say how many leading bytes of a forgery were right.
pub(crate) fn busy_matches(expected: &[u8; BUSY_LEN], reply: &[u8]) -> bool {
    reply.len() == BUSY_LEN && bool::from(reply.ct_eq(expected.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MLKEM768_EK_LEN, X25519_PUBLIC_LEN};

    fn bundle(x25519: [u8; X25519_PUBLIC_LEN], mlkem_ek: [u8; MLKEM768_EK_LEN]) -> StaticPublic {
        StaticPublic::from_parts(x25519, mlkem_ek).expect("a valid test bundle")
    }

    /// The key depends on every byte of the bundle and on the label; the
    /// mac depends on every byte of the message.
    #[test]
    fn the_key_and_the_mac_move_with_their_inputs() {
        let x = [0x11; X25519_PUBLIC_LEN];
        let ek = [0x22; MLKEM768_EK_LEN];
        let key = Mac1Key::of(&bundle(x, ek));
        let mut other_x = x;
        other_x[31] ^= 1;
        let mut other_ek = ek;
        other_ek[0] ^= 1;
        let other = Mac1Key::of(&bundle(other_x, ek));
        assert_ne!(key.0, other.0);
        assert_ne!(key.0, Mac1Key::of(&bundle(x, other_ek)).0);

        let message = [0x5a; 64];
        let tag = key.mac1(&message);
        let proved = key.verify(&message, tag.as_bytes()).expect("its own mac1");
        assert_eq!(proved.as_bytes(), tag.as_bytes());
        let mut changed = message;
        changed[63] ^= 1;
        assert!(key.verify(&changed, tag.as_bytes()).is_none());
        assert!(other.verify(&message, tag.as_bytes()).is_none());
        assert!(key
            .verify(&message, &tag.as_bytes()[..MAC1_LEN - 1])
            .is_none());
        let mut long = tag.as_bytes().to_vec();
        long.push(0);
        assert!(key.verify(&message, &long).is_none());
    }

    /// Known answer, computed independently with Python's `hashlib`:
    /// `blake2s(MAC1_DST + bundle)` for the key, and
    /// `blake2s(message, key=key, digest_size=16)` for the mac. A
    /// 2,320-byte message, the length of a Noise message 1. The busy reply
    /// is `blake2s(BUSY_DST + mac1, key=key, digest_size=16)`, answering
    /// that message 1.
    #[test]
    fn known_answers_from_an_independent_implementation() {
        let key = Mac1Key::of(&bundle([0x11; X25519_PUBLIC_LEN], [0x22; MLKEM768_EK_LEN]));
        assert_eq!(
            hex::encode(key.0),
            "5b837de470bcb848b6f23f71c73ce2131dd9dc96c10a586df39e22563df749b2"
        );
        let message: Vec<u8> = (0..2_320_usize)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        let tag = key.mac1(&message);
        assert_eq!(
            hex::encode(tag.as_bytes()),
            "81422da8958bceb200e31cb50c35f639"
        );
        assert_eq!(
            hex::encode(key.busy(&tag)),
            "d0bc52c26a1c24ad22c8ee575a786b52"
        );
    }
}
