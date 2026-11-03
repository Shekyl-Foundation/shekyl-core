// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The release-carried genesis pin: the block the binary **defines** as
//! each network's block 0 — the network table's genesis
//! (`shekyl_network::Genesis`, `NETWORK_IDENTITY.md` NI-Q3), the block the
//! genesis tool assembles from each network's recipients file (CEN-F11's
//! "as configured" half; `CHAIN_RULES_SLICE_4.md` Q3).
//!
//! The pin is chain identity, not trust: the network *is* its genesis, and
//! every node that runs a network agrees on it. It is verified by equality,
//! never assumed. Nothing above height 0 is pinned. A coded checkpoint is a
//! maintainer choosing the chain, and the release carries none (S1, design
//! review 2026-11-03): the chain is chosen by work alone, and the cost of a
//! deep reorganization while little work is behind the chain is answered by
//! the honest hashrate floor, not by a pin.
//!
//! # What reads it
//!
//! - **CEN-E1** judges a height-0 candidate against the pin
//!   ([`expected_at`](GenesisPin::expected_at)).
//! - **CEN-E5** holds the file a node opens to it: a store whose block 0 is
//!   another network's is refused (`rules::genesis`). The comparison is
//!   [`GenesisPin::conflict`]; [`GenesisPin::conflict_with`] reads a view
//!   and calls it.
//! - **`Trust`** carries the pin into `validate`.
//!
//! The hashes are **read**, not restated: [`for_network`](GenesisPin::for_network)
//! takes the table's genesis hash, which the genesis tool's table test
//! rebuilds from each network's recipients file.

use core::fmt;

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

/// The release-carried pin for one network: its genesis identity.
///
/// There is no public constructor from an arbitrary hash: the only tables
/// are the per-network constants [`for_network`](Self::for_network) selects
/// and [`NONE`](Self::NONE) — nettype selects *data*, never control flow
/// (rule 71), and no path exists for a pin the release did not carry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GenesisPin {
    /// The genesis identity the binary defines for this network; verified
    /// by equality (CEN-E1 at height 0, CEN-E5 at open), assumed by nothing.
    /// `None` only on the table no release vouches for ([`NONE`](Self::NONE)).
    genesis: Option<BlockHash>,
}

impl GenesisPin {
    /// Nothing pinned: the table no release vouches for.
    /// [`Trust::UNPINNED`](crate::Trust::UNPINNED) carries this into
    /// `validate`, so a harness chain can mine its own genesis.
    pub const NONE: Self = Self { genesis: None };

    const fn genesis_only(genesis: [u8; 32]) -> Self {
        Self {
            genesis: Some(BlockHash::from_bytes(genesis)),
        }
    }

    /// The genesis pin the release carries for `network`: the table's
    /// genesis hash. One lookup, the same for every network (rule 71).
    #[must_use]
    pub const fn for_network(network: Network) -> Self {
        Self::genesis_only(network.genesis().hash())
    }

    /// A pin from an explicit hash, for fixtures only. Production tables
    /// are the table's ([`for_network`](Self::for_network)).
    #[cfg(any(test, feature = "harness"))]
    #[must_use]
    pub const fn for_tests(genesis: Option<BlockHash>) -> Self {
        Self { genesis }
    }

    /// The hash the release pins at exactly `height`: the genesis identity
    /// at height 0, and `None` at every other height. CEN-E1's read.
    #[must_use]
    pub fn expected_at(&self, height: BlockHeight) -> Option<BlockHash> {
        if height == BlockHeight::ZERO {
            self.genesis
        } else {
            None
        }
    }
}

impl fmt::Debug for GenesisPin {
    // A failing assertion wants to know whether genesis is pinned, not
    // thirty-two bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenesisPin")
            .field(
                "genesis",
                &if self.genesis.is_some() {
                    "pinned"
                } else {
                    "none"
                },
            )
            .finish()
    }
}

#[cfg(test)]
#[path = "genesis_pin_tests.rs"]
mod genesis_pin_tests;
