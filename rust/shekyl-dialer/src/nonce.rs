// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The handshake nonces this node put in flight (dialer brief,
//! "`HandshakeNonceSet`"; `TOR_SUPERVISOR.md` §4.5).
//!
//! Each outbound handshake carries 32 random bytes minted for that
//! attempt. The nonce is in its connector's set before the request bytes
//! are written, because a dial to our own listener is one stream: the
//! listener reads the request before the dial's invoke can finish.
//! Detection is that order, not a timer.
//!
//! One set, two kinds, so the inbound path stays one lookup. A
//! **self-connection** nonce is a peer dial's: arriving at our own
//! listener means the dialer drew this node. A **probe** nonce is the
//! managed Tor supervisor's dial of its own onion: arriving proves the
//! onion reachable end to end. Both are dropped on arrival. A probe is
//! not a peer dial: it is never counted in [`HandshakeNonceSet::in_flight`].
//! The set takes the probe's connector as data; the managed Tor's FFI is the
//! one caller, and it names the Tor connector.
//!
//! The nonce leaves the set on every end path. [`InFlightNonce`] is the
//! attempt's lifetime: dropping it erases the nonce, so no path can
//! forget to.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use shekyl_draw_rng::RelayRng;
use shekyl_peerlist::{ConnectorId, Tick};

/// One attempt's nonce: 32 bytes, as `COMMAND_HANDSHAKE` carries it.
pub type HandshakeNonce = [u8; 32];

/// Which dial a nonce was minted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// A peer dial.
    SelfConnection,
    /// The supervisor's probe of this node's own onion, minted at this tick.
    Probe { minted_at: Tick },
}

/// What the inbound handshake's nonce was.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceTake {
    /// Not one of ours: a peer's handshake.
    NotOurs,
    /// A peer dial of ours arrived at our own listener: drop it.
    SelfConnection,
    /// The probe minted at `minted_at` arrived on the connector it was
    /// minted for: our own onion is reachable. Drop the session; the supervisor hears the arrival.
    Probe {
        /// When the probe's nonce was minted, which names the probe.
        minted_at: Tick,
    },
    /// A probe nonce arrived on a connector it was not minted for. A defect
    /// of this node, never evidence: drop the session and log it.
    MisroutedProbe,
}

impl NonceTake {
    /// Whether the inbound session is this node's own dial, to be dropped.
    #[must_use]
    pub const fn is_ours(self) -> bool {
        !matches!(self, Self::NotOurs)
    }
}

/// The nonces of the handshakes in flight, one map per connector.
///
/// Cloning shares the maps: the dialer mints into them and the inbound
/// handshake reads them through [`Self::take`].
#[derive(Debug, Clone)]
pub struct HandshakeNonceSet {
    sets: Arc<Mutex<Vec<BTreeMap<HandshakeNonce, Kind>>>>,
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
            sets: Arc::new(Mutex::new(vec![BTreeMap::new(); ConnectorId::COUNT])),
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Vec<BTreeMap<HandshakeNonce, Kind>>) -> T) -> T {
        let mut sets = self.sets.lock().expect("handshake nonce sets");
        f(&mut sets)
    }

    fn insert<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        kind: Kind,
        rng: &mut R,
    ) -> InFlightNonce {
        let mut nonce = [0u8; 32];
        for chunk in nonce.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next_u64().to_le_bytes());
        }
        self.with(|sets| sets[connector.index()].insert(nonce, kind));
        InFlightNonce {
            sets: self.clone(),
            connector,
            nonce,
        }
    }

    /// Mint a nonce for one peer dial on `connector` and record it. The
    /// caller writes the request only after this returns. `rng` is the
    /// daemon's CSPRNG.
    pub fn mint<R: RelayRng + ?Sized>(&self, connector: ConnectorId, rng: &mut R) -> InFlightNonce {
        self.insert(connector, Kind::SelfConnection, rng)
    }

    /// Mint a probe nonce on `connector`, the connector whose own address
    /// is probed (the managed Tor's, named by its FFI). `minted_at` names the
    /// probe, so an arrival from a probe the supervisor has given up on is
    /// told apart.
    pub fn mint_probe<R: RelayRng + ?Sized>(
        &self,
        connector: ConnectorId,
        minted_at: Tick,
        rng: &mut R,
    ) -> InFlightNonce {
        self.insert(connector, Kind::Probe { minted_at }, rng)
    }

    /// What `nonce` is, erasing it. The inbound handshake asks this with the
    /// inbound session's connector.
    ///
    /// A self-connection nonce matches only on its own connector: a peer is
    /// handed that nonce, and testing another connector's set would let it
    /// replay the nonce there and read the drop as a cross-connector
    /// correlation oracle. A probe nonce is never handed to a peer: only
    /// this node's own Tor carries it, end to end to this node's own onion.
    /// So a probe nonce presented on another connector is found, erased,
    /// and reported as [`NonceTake::MisroutedProbe`]: a defect of this node,
    /// never evidence.
    #[must_use]
    pub fn take(&self, connector: ConnectorId, nonce: &HandshakeNonce) -> NonceTake {
        self.with(|sets| match sets[connector.index()].remove(nonce) {
            Some(Kind::SelfConnection) => NonceTake::SelfConnection,
            Some(Kind::Probe { minted_at }) => NonceTake::Probe { minted_at },
            None => {
                let elsewhere = sets
                    .iter_mut()
                    .find(|set| matches!(set.get(nonce), Some(Kind::Probe { .. })));
                match elsewhere {
                    Some(set) => {
                        set.remove(nonce);
                        NonceTake::MisroutedProbe
                    }
                    None => NonceTake::NotOurs,
                }
            }
        })
    }

    /// How many peer-dial handshakes are in flight on `connector`. A probe
    /// is not a peer dial and is not counted.
    #[must_use]
    pub fn in_flight(&self, connector: ConnectorId) -> usize {
        self.with(|sets| {
            sets[connector.index()]
                .values()
                .filter(|kind| **kind == Kind::SelfConnection)
                .count()
        })
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
        self.sets.with(|sets| {
            sets[self.connector.index()].remove(&self.nonce);
        });
    }
}
