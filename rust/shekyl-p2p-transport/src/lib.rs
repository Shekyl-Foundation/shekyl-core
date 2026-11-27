// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

#![deny(unsafe_code)]

//! Clearnet Noise: an 8-byte prefix, NNhfs, then length-prefixed records.
//! The bytes above the channel are plaintext. This crate does not parse
//! them, and it does not implement stem, fluff, or Levin.
//!
//! Tor is its own connector. It is not built here.
//! `read_message1`, `read_message2`, `SendHalf::seal`, and `open_one` are
//! the Noise layer's public record path. The D11 fuzz targets call those
//! same methods. This crate stays the Noise layer.
//!
//! [`InitiatorFlight`] and [`ResponderFlight`] are the prefix and the
//! handshake message as one value. [`Initiator::open`] and
//! [`Responder::accept`] are the unbudgeted peer side of that flight.
//! The node's handshake writes the same bytes under its own budget.

mod channel;
mod flight;
mod noise;
mod open;
mod prefix;

/// Timing hooks for the C5 Pi-4 run. Not a wire API. Built only for that bench.
#[cfg(feature = "c5-bench")]
#[doc(hidden)]
pub mod c5_bench;

pub use channel::{RecordError, RecvHalf, SealEachError, SendHalf};
pub use flight::{InitiatorFlight, ResponderFlight};
pub use noise::{
    Established, HandshakeError, Initiator, Responder, ResponderReady, MESSAGE1_LEN, MESSAGE2_LEN,
    PROTOCOL_NAME,
};
pub use open::OpenError;
pub use prefix::{
    network_id_from_genesis, prefix_for, NetworkId, NETWORK_ID_DST, PREFIX_LEN, WIRE_PREFIX_DST,
};

/// Wire size of the initiator's first flight, prefix included.
pub const INITIATOR_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE1_LEN;
/// Wire size of the responder's flight, prefix included.
pub const RESPONDER_FLIGHT_LEN: usize = PREFIX_LEN + MESSAGE2_LEN;
