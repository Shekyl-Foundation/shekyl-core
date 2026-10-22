// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Levin command schemas (LV-2b: 1001 / 1002 and notifies 2002–2004 /
//! 2006–2010, plus the chain-sync commands 2011–2014, which are not
//! admitted at ingress).
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
mod sync;
mod types;

pub use address::{NetworkAddress, ADDR_IPV4, ADDR_IPV6, ADDR_TOR};
pub use block::{BlockCompleteEntry, TxBlobEntry, ATTESTATION_WITNESS_MAX_BYTES};
pub use commands::{
    HandshakeRequest, HandshakeResponse, TimedSyncRequest, TimedSyncResponse, COMMAND_HANDSHAKE,
    COMMAND_TIMED_SYNC,
};
pub use error::Error;
pub use get::HASH_SIZE;
pub use notifies::{
    GetTxpoolComplement, NewCompactBlock, NewTransactions, RequestChain, RequestCompactMissingTx,
    RequestGetObjects, ResponseChainEntry, ResponseGetObjects, NOTIFY_GET_TXPOOL_COMPLEMENT,
    NOTIFY_NEW_COMPACT_BLOCK, NOTIFY_NEW_TRANSACTIONS, NOTIFY_REQUEST_BODIES, NOTIFY_REQUEST_CHAIN,
    NOTIFY_REQUEST_COMPACT_MISSING_TX, NOTIFY_REQUEST_GET_OBJECTS, NOTIFY_REQUEST_HEADERS,
    NOTIFY_RESPONSE_BODIES, NOTIFY_RESPONSE_CHAIN_ENTRY, NOTIFY_RESPONSE_GET_OBJECTS,
    NOTIFY_RESPONSE_HEADERS,
};
pub use sync::{
    body_budget_bytes, plan_bodies, BodiesFormFault, BodyPlan, RequestBodies, RequestHeaders,
    ResponseBodies, ResponseHeaders, BODIES_RESPONSE_BYTES, CAP_REQUEST_BODIES,
    CAP_REQUEST_HEADERS, CAP_RESPONSE_BODIES, CAP_RESPONSE_HEADERS, HEADERS_RESPONSE_BYTES,
    MIN_TX_SECTION_BYTES, RESPONSE_BODIES_MAX_FIELDS, RESPONSE_BODIES_MAX_OBJECTS,
    RESPONSE_BODIES_MAX_STRINGS, RESPONSE_BODIES_MAX_TXS, RESPONSE_HEADERS_MAX_STRINGS,
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
