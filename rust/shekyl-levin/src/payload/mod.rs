// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Levin command schemas (LV-2b first drop: 1001 / 1002 / 1003 / 1007).
//!
//! Encode/decode sit on `shekyl-portable-storage`. Remaining cryptonote
//! notifies (2001–2004, 2006–2010) are the rest of LV-2b, not this module.

use shekyl_portable_storage::{load_from_binary, store_to_binary, Limits, Section};

mod address;
mod commands;
mod error;
mod get;
mod types;

pub use address::{NetworkAddress, ADDR_I2P, ADDR_IPV4, ADDR_IPV6, ADDR_TOR};
pub use commands::{
    HandshakeRequest, HandshakeResponse, PingRequest, PingResponse, SupportFlagsRequest,
    SupportFlagsResponse, TimedSyncRequest, TimedSyncResponse, COMMAND_HANDSHAKE, COMMAND_PING,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, PING_OK,
};
pub use error::Error;
pub use types::{BasicNodeData, CoreSyncData, PeerlistEntry};

/// A C++ `BEGIN_KV_SERIALIZE_MAP` as a portable_storage section.
pub trait PortableMap: Sized {
    /// Build the KV section (lexicographic keys, OPT omitted at default).
    fn to_section(&self) -> Result<Section, Error>;
    /// Parse a section. Extra keys are ignored (complete codec).
    fn from_section(section: &Section) -> Result<Self, Error>;

    /// `store_t_to_binary`.
    fn store(&self) -> Result<Vec<u8>, Error> {
        Ok(store_to_binary(&self.to_section()?)?)
    }

    /// `load_t_from_binary` with [`Limits::LEVIN`].
    fn load(bytes: &[u8]) -> Result<Self, Error> {
        Self::from_section(&load_from_binary(bytes, Limits::LEVIN)?)
    }
}
