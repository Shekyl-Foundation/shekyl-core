// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! What this node takes on the release's word — `validate`'s fourth input,
//! orthogonal to `RuleSet` (`PDM-Q5`, `PDM-Q-F27`).
//!
//! A rule set says what the chain's rules *are*. A [`Trust`] carries the
//! release's [`GenesisPin`] into `validate` (CEN-E1 reads it per block).
//! There is no posture arm: no coded checkpoint, so nothing is assumed
//! (S1, design review 2026-11-03).
//!
//! # Why a separate input
//!
//! - **Not on `RuleSet`.** An anchor addition would have been a *release*;
//!   a rule-set change is a *hard fork*. And `connect` compares the
//!   verdict's rule set with the one in force **by value** (`connect.rs`,
//!   RD-Q10): a table on the set would be refused whenever the driver's
//!   copy differed, or would have to be carved out of the comparison.
//! - **Not on `Substrate`.** That trait is *services with faults* — a clock
//!   that may be unavailable, a VM that may fail. The pin is static data with no
//!   failure mode and nothing to serve; a method returning it would make
//!   the trait carry configuration, and its mock in every test would have
//!   to answer with a pin it has no reason to hold.
//! - **Not on the `form` token.** `form` is stateless and has no height;
//!   E1 is view-bound.
//!
//! [`Trust::full`] is the constructor; every network a release runs,
//! regtest included, carries its table genesis. `Trust::UNPINNED`
//! (`full(GenesisPin::NONE)`) exists in test and harness builds only, for
//! a harness chain that mines its own genesis.

use shekyl_network::{network_id_from_genesis, NetworkId};
use shekyl_types::BlockHeight;

use crate::genesis_pin::GenesisPin;

/// The genesis pin this node holds a height-0 candidate to.
///
/// Construct with [`Trust::full`]. The field is private: callers read
/// [`genesis_pin`](Self::genesis_pin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trust {
    genesis: GenesisPin,
}

impl Trust {
    /// Nothing pinned: a harness chain that mines its own genesis. Test
    /// and harness builds only; every network a release runs is
    /// [`full`](Self::full)`(GenesisPin::for_network(_))`, regtest
    /// included (`NETWORK_IDENTITY.md` NI-Q8).
    #[cfg(any(test, feature = "harness"))]
    pub const UNPINNED: Self = Self::full(GenesisPin::NONE);

    /// Carry `genesis` into `validate`.
    #[must_use]
    pub const fn full(genesis: GenesisPin) -> Self {
        Self { genesis }
    }

    /// The genesis pin this node holds a candidate to.
    #[must_use]
    pub const fn genesis_pin(&self) -> &GenesisPin {
        &self.genesis
    }

    /// The id of the network this trust pins: derived from its genesis
    /// (`NETWORK_IDENTITY.md` NI-R10), the id every spend signature's hash
    /// binds (NI-Q4). Under [`Trust::UNPINNED`] it is
    /// [`HARNESS_NETWORK_ID`], the id every harness signer signs under.
    #[must_use]
    pub fn network_id(&self) -> NetworkId {
        match self.genesis.expected_at(BlockHeight::ZERO) {
            Some(genesis) => network_id_from_genesis(genesis.as_bytes()),
            #[cfg(any(test, feature = "harness"))]
            None => HARNESS_NETWORK_ID,
            #[cfg(not(any(test, feature = "harness")))]
            None => unreachable!("only a harness build has a pin with no genesis"),
        }
    }
}

/// The network id of a harness chain that mines its own genesis
/// ([`Trust::UNPINNED`]), re-exported from `shekyl-network` for test and
/// harness builds.
#[cfg(any(test, feature = "harness"))]
pub use shekyl_network::HARNESS_NETWORK_ID;
