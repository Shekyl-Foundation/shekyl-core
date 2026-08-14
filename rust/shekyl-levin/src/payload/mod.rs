// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Levin command schemas (LV-2b: 1001–1003 / 1007 and notifies 2001–2004 /
//! 2006–2010).
//!
//! Encode/decode sit on `shekyl-portable-storage`. Cryptonote blobs stay
//! opaque `Vec<u8>` (`shekyl-wire` owns those). RPC maps stay out.

use shekyl_portable_storage::{load_from_binary, store_to_binary, Limits, Section};

mod address;
mod block;
mod commands;
mod error;
mod get;
mod notifies;
mod types;

pub use address::{NetworkAddress, ADDR_I2P, ADDR_IPV4, ADDR_IPV6, ADDR_TOR};
pub use block::{BlockCompleteEntry, TxBlobEntry, ATTESTATION_WITNESS_MAX_BYTES};
pub use commands::{
    HandshakeRequest, HandshakeResponse, PingRequest, PingResponse, SupportFlagsRequest,
    SupportFlagsResponse, TimedSyncRequest, TimedSyncResponse, COMMAND_HANDSHAKE, COMMAND_PING,
    COMMAND_REQUEST_SUPPORT_FLAGS, COMMAND_TIMED_SYNC, PING_OK,
};
pub use error::Error;
pub use get::HASH_SIZE;
pub use notifies::{
    GetTxpoolComplement, NewBlock, NewFluffyBlock, NewTransactions, RequestChain,
    RequestFluffyMissingTx, RequestGetObjects, ResponseChainEntry, ResponseGetObjects,
    NOTIFY_GET_TXPOOL_COMPLEMENT, NOTIFY_NEW_BLOCK, NOTIFY_NEW_FLUFFY_BLOCK,
    NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_CHAIN, NOTIFY_REQUEST_FLUFFY_MISSING_TX,
    NOTIFY_REQUEST_GET_OBJECTS, NOTIFY_RESPONSE_CHAIN_ENTRY, NOTIFY_RESPONSE_GET_OBJECTS,
};
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
