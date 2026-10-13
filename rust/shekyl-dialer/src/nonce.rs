// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The self-connection nonces (dialer brief, "`HandshakeNonceSet`").
//!
//! Each outbound handshake carries 32 random bytes minted for that
//! attempt. The nonce is in its connector's set before the request bytes
//! are written, because a dial to our own listener is one stream: the
//! listener reads the request before the dial's invoke can finish.
//! Detection is that order, not a timer.
//!
//! The nonce leaves the set on every end path. [`InFlightNonce`] is the
//! attempt's lifetime: dropping it erases the nonce, so no path can
//! forget to.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use shekyl_peerlist::ConnectorId;
use shekyl_relay_privacy::rng::RelayRng;

/// One attempt's nonce: 32 bytes, as `COMMAND_HANDSHAKE` carries it.
pub type HandshakeNonce = [u8; 32];

/// The nonces of the handshakes in flight, one set per connector.
///
/// Cloning shares the sets: the dialer mints into them and the inbound
/// handshake reads them through [`Self::take`].
#[derive(Debug, Clone)]
pub struct HandshakeNonceSet {
    sets: Arc<Mutex<Vec<BTreeSet<HandshakeNonce>>>>,
}

impl Default for HandshakeNonceSet {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeNonceSet {
    /// Empty sets, one per connector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sets: Arc::new(Mutex::new(vec![BTreeSet::new(); ConnectorId::COUNT])),
        }
    }

    fn with<T>(
        &self,
        connector: ConnectorId,
        f: impl FnOnce(&mut BTreeSet<HandshakeNonce>) -> T,
    ) -> T {
        let mut sets = self.sets.lock().expect("handshake nonce sets");
        f(&mut sets[connector.index()])
    }

    /// Mint a nonce for one attempt on `connector` and record it. The
    /// caller writes the request only after this returns. `rng` is the
    /// daemon's CSPRNG.
    pub fn mint<R: RelayRng + ?Sized>(&self, connector: ConnectorId, rng: &mut R) -> InFlightNonce {
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        self.with(connector, |set| set.insert(nonce));
        InFlightNonce {
            sets: self.clone(),
            connector,
            nonce,
        }
    }

    /// Whether `connector`'s set holds `nonce`, erasing it. The inbound
    /// handshake asks this with the inbound session's connector: `true`
    /// is our own request arriving at our own listener.
    #[must_use]
    pub fn take(&self, connector: ConnectorId, nonce: &HandshakeNonce) -> bool {
        self.with(connector, |set| set.remove(nonce))
    }

    /// How many handshakes are in flight on `connector`.
    #[must_use]
    pub fn in_flight(&self, connector: ConnectorId) -> usize {
        self.with(connector, |set| set.len())
    }
}

/// One attempt's recorded nonce. Dropping it erases the nonce from its
/// set, whatever path ended the attempt.
#[derive(Debug)]
pub struct InFlightNonce {
    sets: HandshakeNonceSet,
    connector: ConnectorId,
    nonce: HandshakeNonce,
}

impl InFlightNonce {
    /// The bytes the handshake request carries.
    #[must_use]
    pub fn bytes(&self) -> &HandshakeNonce {
        &self.nonce
    }
}

impl Drop for InFlightNonce {
    fn drop(&mut self) {
        // Already gone when our own listener took it; either way it is out.
        self.sets.with(self.connector, |set| {
            set.remove(&self.nonce);
        });
    }
}
