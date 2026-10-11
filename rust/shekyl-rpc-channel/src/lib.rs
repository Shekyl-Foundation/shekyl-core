// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! The RPC channel's domain strings and the three derivations that carry
//! them (`docs/design/RPC_CHANNEL.md`, round R1; encodings ruled as RT-O14).
//!
//! - [`prologue`]: what the channel's Noise handshake binds to before its
//!   first message, so a client of one network cannot complete a handshake
//!   with a daemon of another.
//! - [`rendezvous_name`]: the name a daemon's local rendezvous is found
//!   under. It is derived from the network and the instance, so an instance
//!   name never becomes a filesystem path component or an IPC object name.
//! - [`static_fingerprint`]: the identity a daemon enrols a client under.
//!
//! This crate holds no handshake yet. It is the home the handshake lands in
//! (slice RT-W9); slice RT-W8 fixes the bytes first, against vectors in
//! `docs/test_vectors/RPC_CHANNEL_NAMES_V1/` that an independent generator
//! produced.

use std::fmt;

use shekyl_crypto_hash::cshake256_32;

/// First part of the handshake prologue. Not a hash customization: the bytes
/// themselves are mixed into the handshake transcript, followed by the
/// network id.
pub const CHANNEL_DST: &[u8] = b"shekyl/rpc-channel-v1";

/// cSHAKE256 customization of [`static_fingerprint`].
pub const STATIC_FINGERPRINT_DST: &[u8] = b"shekyl/rpc-static-fingerprint-v1";

/// cSHAKE256 customization of [`rendezvous_name`].
pub const RENDEZVOUS_NAME_DST: &[u8] = b"shekyl/rpc-rendezvous-name-v1";

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

/// Length of a [`RendezvousName`] in bytes; it is written as twice as many
/// hex characters.
pub const RENDEZVOUS_NAME_LEN: usize = 12;

/// Length of a [`StaticFingerprint`].
pub const STATIC_FINGERPRINT_LEN: usize = 32;

/// Longest instance name an operator may give.
pub const INSTANCE_NAME_MAX: usize = 16;

/// The label the default instance carries in [`rendezvous_name`]. It is not
/// a name an operator may give: [`InstanceName::parse`] refuses it.
pub const DEFAULT_INSTANCE_LABEL: &str = "default";

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

/// Why a string is not an instance name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstanceNameError {
    /// The name is empty.
    Empty,
    /// The name is longer than [`INSTANCE_NAME_MAX`] characters.
    TooLong,
    /// The name's first character is not a lower-case letter or a digit.
    BadStart,
    /// The name holds a character other than a lower-case letter, a digit or
    /// a hyphen.
    BadCharacter,
    /// The name is [`DEFAULT_INSTANCE_LABEL`], which names the default
    /// instance.
    Reserved,
}

impl fmt::Display for InstanceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reserved => write!(
                f,
                "'{DEFAULT_INSTANCE_LABEL}' names the default instance and cannot be an instance name"
            ),
            Self::Empty | Self::TooLong | Self::BadStart | Self::BadCharacter => write!(
                f,
                "an instance name is 1 to {INSTANCE_NAME_MAX} lower-case letters, digits or \
                 hyphens, starting with a letter or digit"
            ),
        }
    }
}

impl std::error::Error for InstanceNameError {}

/// A name an operator gave a second node on one machine.
///
/// The rule is about what an operator can type and read, not about paths:
/// a name is only ever hashed ([`rendezvous_name`]) or shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceName(String);

impl InstanceName {
    /// Accept `name` if it is 1 to [`INSTANCE_NAME_MAX`] characters of
    /// `[a-z0-9-]`, starts with a letter or a digit, and is not
    /// [`DEFAULT_INSTANCE_LABEL`]. Nothing is trimmed, folded or repaired.
    ///
    /// # Errors
    ///
    /// The first rule `name` breaks.
    pub fn parse(name: &str) -> Result<Self, InstanceNameError> {
        let Some(first) = name.bytes().next() else {
            return Err(InstanceNameError::Empty);
        };
        if name.len() > INSTANCE_NAME_MAX {
            return Err(InstanceNameError::TooLong);
        }
        if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return Err(InstanceNameError::BadStart);
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(InstanceNameError::BadCharacter);
        }
        if name == DEFAULT_INSTANCE_LABEL {
            return Err(InstanceNameError::Reserved);
        }
        Ok(Self(name.to_owned()))
    }

    /// The name as given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which node on this machine, for one network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Instance {
    /// The one a client means by "this computer".
    Default,
    /// A deliberate second node, reached only by naming it.
    Named(InstanceName),
}

impl Instance {
    /// The bytes [`rendezvous_name`] hashes for this instance.
    #[must_use]
    pub fn label(&self) -> &str {
        match self {
            Self::Default => DEFAULT_INSTANCE_LABEL,
            Self::Named(name) => name.as_str(),
        }
    }
}

/// The derived name of a rendezvous: [`RENDEZVOUS_NAME_LEN`] bytes, shown as
/// lower-case hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RendezvousName([u8; RENDEZVOUS_NAME_LEN]);

impl RendezvousName {
    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RENDEZVOUS_NAME_LEN] {
        &self.0
    }
}

impl fmt::Display for RendezvousName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The rendezvous name of `instance` on the network `network_id`.
///
/// cSHAKE256 under [`RENDEZVOUS_NAME_DST`] over the network id followed by
/// the instance's label; the first [`RENDEZVOUS_NAME_LEN`] bytes. The
/// fixed-length part comes first, so the input needs no length prefix. A
/// daemon and a client compute the same name from the same two inputs.
#[must_use]
pub fn rendezvous_name(network_id: &NetworkId, instance: &Instance) -> RendezvousName {
    let label = instance.label().as_bytes();
    let mut input = Vec::with_capacity(NETWORK_ID_LEN + label.len());
    input.extend_from_slice(network_id);
    input.extend_from_slice(label);
    let digest = cshake256_32(RENDEZVOUS_NAME_DST, &input);
    let mut name = [0u8; RENDEZVOUS_NAME_LEN];
    name.copy_from_slice(&digest[..RENDEZVOUS_NAME_LEN]);
    RendezvousName(name)
}

/// The identity a daemon enrols a client's static keys under.
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
