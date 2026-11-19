// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The names a daemon's local rendezvous is found under, and where it is
//! (`docs/design/RPC_CHANNEL.md` RT-O10, RT-O14, RT-15, §7.1).
//!
//! **The contract: one derivation and one layout, read by the daemon that
//! publishes a rendezvous and by every client that resolves it, so the two
//! cannot disagree on a name, a path or a record; and nothing of the
//! channel's handshake.** Its one dependency is `shekyl-crypto-hash`
//! (Rick, 2026-11-14): a crate that only finds a daemon carries no Noise,
//! ML-KEM or X25519.
//!
//! - [`rendezvous_name`]: the name a rendezvous is found under, derived from
//!   the network and the instance, so an instance name never becomes a
//!   filesystem path component or an IPC object name.
//! - [`Instance`] and [`InstanceName`]: which node on this machine, and the
//!   rule an operator's instance name follows.
//! - [`file_name`], [`account_dir`], [`data_home`] and [`Record`]: the
//!   rendezvous file in its directory, and what a Windows record says.
//! - [`service_file_name`] and [`ServiceRecord`]: a service's machine-wide
//!   record, and what it says.
//!
//! The derivation's bytes are pinned by the vectors in
//! `docs/test_vectors/RPC_CHANNEL_NAMES_V1/`, which an independent generator
//! produced (`tests/names_kat.rs`).

#![deny(unsafe_code)]

use std::fmt;

use shekyl_crypto_hash::cshake256_32;

mod place;

pub use place::{
    account_dir, console_leg_place, data_home, file_name, service_file_name, service_record_at,
    service_record_path, service_rendezvous, Record, ServiceChannel, ServiceRecord,
    ServiceRecordAt, CHANNEL_BUNDLE_FILE, CHANNEL_KEY_FILE, CONSOLE_KEY_FILE, CONSOLE_PIPE_FILE,
    CONSOLE_PIPE_PREFIX, CONSOLE_SOCKET_FILE, PIPE_PREFIX, RECORD_FORMAT, RENDEZVOUS_DIR,
    SERVICE_DATA_HOME, SERVICE_RECORD_FORMAT,
};

/// cSHAKE256 customization of [`rendezvous_name`].
pub const RENDEZVOUS_NAME_DST: &[u8] = b"shekyl/rpc-rendezvous-name-v1";

/// Length of the genesis-derived network id the name is derived from
/// (`shekyl-network`'s `NetworkId`; a test holds the two equal).
pub const NETWORK_ID_LEN: usize = 16;

/// Length of a [`RendezvousName`] in bytes; it is written as twice as many
/// hex characters.
pub const RENDEZVOUS_NAME_LEN: usize = 12;

/// Longest instance name an operator may give.
pub const INSTANCE_NAME_MAX: usize = 16;

/// The label the default instance carries in [`rendezvous_name`]. It is not
/// a name an operator may give: [`InstanceName::parse`] refuses it.
pub const DEFAULT_INSTANCE_LABEL: &str = "default";

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

impl InstanceNameError {
    /// The rule the name broke, in the words a refusal shows. The numbers
    /// are [`INSTANCE_NAME_MAX`] and [`DEFAULT_INSTANCE_LABEL`]; a test
    /// holds the text to them.
    #[must_use]
    pub const fn rule(self) -> &'static str {
        match self {
            Self::Reserved => "`default` names the default instance and cannot be an instance name",
            Self::Empty | Self::TooLong | Self::BadStart | Self::BadCharacter => {
                "an instance name is 1 to 16 lower-case letters, digits or hyphens, \
                 starting with a letter or digit"
            }
        }
    }
}

impl fmt::Display for InstanceNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.rule())
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
pub fn rendezvous_name(network_id: &[u8; NETWORK_ID_LEN], instance: &Instance) -> RendezvousName {
    let label = instance.label().as_bytes();
    let mut input = Vec::with_capacity(NETWORK_ID_LEN + label.len());
    input.extend_from_slice(network_id);
    input.extend_from_slice(label);
    let digest = cshake256_32(RENDEZVOUS_NAME_DST, &input);
    let mut name = [0u8; RENDEZVOUS_NAME_LEN];
    name.copy_from_slice(&digest[..RENDEZVOUS_NAME_LEN]);
    RendezvousName(name)
}
