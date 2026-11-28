// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One handshake flight: the network prefix, then the Noise message.
//!
//! A peer writes [`InitiatorFlight::as_bytes`] or [`ResponderFlight::as_bytes`]
//! in one socket write. The prefix and the message are not two writes.
//! The node's own handshake is budgeted and writes the same bytes.

use crate::noise::{HandshakeError, MESSAGE1_LEN, MESSAGE2_LEN};
use crate::prefix::{prefix_for, NetworkId, PREFIX_LEN};
use crate::{INITIATOR_FLIGHT_LEN, RESPONDER_FLIGHT_LEN};

/// The initiator's first flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitiatorFlight([u8; INITIATOR_FLIGHT_LEN]);

/// The responder's flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResponderFlight([u8; RESPONDER_FLIGHT_LEN]);

fn lay_flight<const N: usize>(
    prefix: [u8; PREFIX_LEN],
    message: &[u8],
) -> Result<[u8; N], HandshakeError> {
    if PREFIX_LEN + message.len() != N {
        return Err(HandshakeError::Length);
    }
    let mut bytes = [0u8; N];
    bytes[..PREFIX_LEN].copy_from_slice(&prefix);
    bytes[PREFIX_LEN..].copy_from_slice(message);
    Ok(bytes)
}

fn prefix_of<const N: usize>(bytes: &[u8; N]) -> [u8; PREFIX_LEN] {
    let mut prefix = [0u8; PREFIX_LEN];
    prefix.copy_from_slice(&bytes[..PREFIX_LEN]);
    prefix
}

impl InitiatorFlight {
    /// `message` is message 1, [`MESSAGE1_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Length`] when `message` is not message 1.
    pub fn from_message(network_id: &NetworkId, message: &[u8]) -> Result<Self, HandshakeError> {
        Ok(Self(lay_flight(prefix_for(network_id), message)?))
    }

    /// A flight read off the wire, prefix not yet checked.
    #[must_use]
    pub fn from_bytes(bytes: [u8; INITIATOR_FLIGHT_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; INITIATOR_FLIGHT_LEN] {
        &self.0
    }

    #[must_use]
    pub fn prefix(&self) -> [u8; PREFIX_LEN] {
        prefix_of(&self.0)
    }

    /// Message 1. [`crate::Initiator::read_message2`] does not take this;
    /// [`crate::Responder::read_message1`] does.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.0[PREFIX_LEN..]
    }

    /// Whether this flight names `network_id`.
    #[must_use]
    pub fn for_network(&self, network_id: &NetworkId) -> bool {
        self.prefix() == prefix_for(network_id)
    }
}

impl ResponderFlight {
    /// `message` is message 2, [`MESSAGE2_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// [`HandshakeError::Length`] when `message` is not message 2.
    pub fn from_message(network_id: &NetworkId, message: &[u8]) -> Result<Self, HandshakeError> {
        Ok(Self(lay_flight(prefix_for(network_id), message)?))
    }

    /// A flight read off the wire, prefix not yet checked.
    #[must_use]
    pub fn from_bytes(bytes: [u8; RESPONDER_FLIGHT_LEN]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; RESPONDER_FLIGHT_LEN] {
        &self.0
    }

    #[must_use]
    pub fn prefix(&self) -> [u8; PREFIX_LEN] {
        prefix_of(&self.0)
    }

    /// Message 2. [`crate::Initiator::read_message2`] takes this.
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.0[PREFIX_LEN..]
    }

    /// Whether this flight names `network_id`.
    #[must_use]
    pub fn for_network(&self, network_id: &NetworkId) -> bool {
        self.prefix() == prefix_for(network_id)
    }
}

const _: () = assert!(INITIATOR_FLIGHT_LEN == PREFIX_LEN + MESSAGE1_LEN);
const _: () = assert!(RESPONDER_FLIGHT_LEN == PREFIX_LEN + MESSAGE2_LEN);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_flight_is_the_prefix_then_the_message() {
        let network = [0x11u8; 16];
        let message = vec![0x5a; MESSAGE1_LEN];
        let flight = InitiatorFlight::from_message(&network, &message).expect("message 1");
        assert_eq!(flight.prefix(), prefix_for(&network));
        assert_eq!(flight.message(), message.as_slice());
        assert!(flight.for_network(&network));
        assert!(!flight.for_network(&[0x22; 16]));
        assert!(InitiatorFlight::from_message(&network, &[0u8; MESSAGE1_LEN - 1]).is_err());
    }
}
