// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Clearnet network pipe: an 8-byte prefix, Noise NNhfs, then length-prefixed
//! records. The bytes above the pipe are plaintext. This crate does not parse
//! them, and it does not implement stem, fluff, or Levin.
//!
//! Tor and I2P are other network pipes. They are not built here.

mod aead;
mod channel;
mod noise;
mod pipe;
mod prefix;

pub use noise::{MESSAGE1_LEN, MESSAGE2_LEN, PROTOCOL_NAME};
pub use pipe::{
    ClosedCallback, Pipe, PipeError, PipeHooks, PlainCallback, ReadyCallback, WireCallback,
    HANDSHAKE_DEADLINE, PIPE_PLAINTEXT_BUDGET,
};
pub use prefix::{
    prefix_for, NetworkId, MAINNET_PREFIX, PREFIX_LEN, STAGENET_PREFIX, TESTNET_PREFIX,
    WIRE_PREFIX_DST,
};

/// Wire size of the initiator's first flight, prefix included.
pub const INITIATOR_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE1_LEN;
/// Wire size of the responder's flight, prefix included.
pub const RESPONDER_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE2_LEN;
