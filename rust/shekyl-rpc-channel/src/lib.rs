// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! The RPC channel's domain strings and the two derivations that carry
//! them (`docs/design/RPC_CHANNEL.md`, round R1; encodings ruled as RT-O14).
//!
//! - [`prologue`]: what the channel's Noise handshake binds to before its
//!   first message, so a client of one network cannot complete a handshake
//!   with a daemon of another.
//! - [`static_fingerprint`]: the identity a daemon enrolls a client under.
//!
//! The third derivation of RT-O14, the rendezvous name, is
//! `shekyl-rpc-rendezvous`'s, with the instance rule and the rendezvous's
//! layout: a client that only finds a daemon carries none of the handshake.
//!
//! The handshake itself is [`handshake`]: Shekyl's own
//! `Noise_hybridXK_25519+MLKEM768_ChaChaPoly_BLAKE2s`, built on
//! `shekyl-noise`, which it shares with the P2P handshake. Slice RT-W8 fixed
//! the bytes of the three derivations first, against vectors in
//! `docs/test_vectors/RPC_CHANNEL_NAMES_V1/` that an independent generator
//! produced, and pinned the handshake's vectors from an independent
//! implementation; slice RT-W9 built the handshake against those.

use shekyl_crypto_hash::cshake256_32;

pub mod budget;
pub mod deadline;
pub mod handshake;
mod mac1;
pub mod retry;
mod static_public;

/// First part of the handshake prologue. Not a hash customization: the bytes
/// themselves are mixed into the handshake transcript, followed by the
/// network id.
pub const CHANNEL_DST: &[u8] = b"shekyl/rpc-channel-v1";

/// cSHAKE256 customization of [`static_fingerprint`].
pub const STATIC_FINGERPRINT_DST: &[u8] = b"shekyl/rpc-static-fingerprint-v1";

/// Length of the mac1 that follows the Noise message 1 on the wire.
pub const MAC1_LEN: usize = 16;

/// Length of a busy reply.
pub const BUSY_LEN: usize = 16;

/// The most live channel sessions one client key may hold
/// (`RPC_CHANNEL.md` §6.3, RT-O37). The daemon refuses a fingerprint's next
/// session past it (`bound.sessions`), and a client's session pool opens no
/// more than it.
///
/// **Assumption** (Rick, 2026-11-15). Basis: five clients fit in
/// `rpc-connections-max`'s default of 25 with five to spare, and the
/// console's four are its own, beyond that number. Without a cap, one
/// compromised enrolled key could hold every connection the daemon admits
/// and lock its administrator out of revoking it. RT-P10 measures whether
/// a pool of this size serves its load.
pub const SESSIONS_PER_CLIENT: usize = 4;

/// Length of the genesis-derived network id (`shekyl-p2p-transport`'s
/// `NetworkId`; a test holds the two equal).
pub const NETWORK_ID_LEN: usize = 16;

/// The genesis-derived network id.
pub type NetworkId = [u8; NETWORK_ID_LEN];

/// Length of an X25519 public key.
pub const X25519_PUBLIC_LEN: usize = 32;

/// Length of an ML-KEM-768 encapsulation key (`shekyl-crypto-pq` owns the
/// figure; a test holds the two equal).
pub const MLKEM768_EK_LEN: usize = 1184;

/// Length of [`prologue`]'s output.
pub const PROLOGUE_LEN: usize = CHANNEL_DST.len() + NETWORK_ID_LEN;

/// Length of a [`StaticFingerprint`].
pub const STATIC_FINGERPRINT_LEN: usize = 32;

/// The handshake prologue: [`CHANNEL_DST`], then the network id.
///
/// No separator and no length prefix. The first part is a constant and the
/// second has a fixed length, so the concatenation is unambiguous.
#[must_use]
pub fn prologue(network_id: &NetworkId) -> [u8; PROLOGUE_LEN] {
    let mut out = [0u8; PROLOGUE_LEN];
    let (label, id) = out.split_at_mut(CHANNEL_DST.len());
    label.copy_from_slice(CHANNEL_DST);
    id.copy_from_slice(network_id);
    out
}

/// The identity a daemon enrolls a client's static keys under.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StaticFingerprint([u8; STATIC_FINGERPRINT_LEN]);

impl StaticFingerprint {
    /// The raw bytes. How a fingerprint is shown to an operator is
    /// presentation and is not decided here.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; STATIC_FINGERPRINT_LEN] {
        &self.0
    }
}

/// The fingerprint of a static key bundle.
///
/// cSHAKE256 under [`STATIC_FINGERPRINT_DST`] over the X25519 public key and
/// then the ML-KEM-768 encapsulation key, the order the handshake sends
/// them in. Both keys are public; nothing here is secret.
#[must_use]
pub fn static_fingerprint(
    x25519_public: &[u8; X25519_PUBLIC_LEN],
    mlkem768_ek: &[u8; MLKEM768_EK_LEN],
) -> StaticFingerprint {
    let mut input = Vec::with_capacity(X25519_PUBLIC_LEN + MLKEM768_EK_LEN);
    input.extend_from_slice(x25519_public);
    input.extend_from_slice(mlkem768_ek);
    StaticFingerprint(cshake256_32(STATIC_FINGERPRINT_DST, &input))
}
