// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Clearnet transport channel: prefix, Noise NNhfs, then length-prefixed records.
//!
//! Tor and I2P do not use this crate. Levin command bytes are plaintext in and
//! plaintext out; this crate never parses them.

mod channel;
mod conn;
mod noise;
mod prefix;

pub use channel::{Channel, Direction, RecordError, REKEY_NONCES};
pub use conn::{handshake_deadline, run_pair, AcceptError, ClearnetSocket, Link, PlainCallback};
pub use noise::{
    pinned_initiator, Handshake, HandshakeError, Role, MESSAGE1_LEN, MESSAGE2_LEN, PROTOCOL_NAME,
};
pub use prefix::{
    prefix_for, NetworkId, MAINNET_PREFIX, PREFIX_LEN, STAGENET_PREFIX, TESTNET_PREFIX,
    WIRE_PREFIX_DST,
};

/// Wire size of the initiator's first flight, prefix included.
pub const INITIATOR_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE1_LEN;
/// Wire size of the responder's flight, prefix included.
pub const RESPONDER_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE2_LEN;
