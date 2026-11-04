// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The release-carried genesis pin: the block the binary **defines** as
//! each public network's block 0 — `GENESIS_TX` and `GENESIS_NONCE` in
//! `cryptonote_config.h`, the block `generate_genesis_block` assembles from
//! them (CEN-F11's "as configured" half; `CHAIN_RULES_SLICE_4.md` Q3).
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
//! The hashes are **derived**, not restated: `genesis_pin_tests` rebuilds each
//! network's genesis block from `cryptonote_config.h`'s pins through the
//! genesis tool and asserts the table equals it, and asserts the table
//! equals the client identity's copy (`shekyl_rpc_types::genesis_hash_for`,
//! `VC-D18`), so the two Rust homes cannot drift.

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
    /// Nothing pinned. [`Trust::UNPINNED`](crate::Trust::UNPINNED) carries
    /// this into `validate`, so a harness chain can mine its own genesis.
    /// A regtest node's open pins [`FAKECHAIN`](Self::FAKECHAIN) instead:
    /// the store is held to the block a regtest node connects, and
    /// `validate` is not.
    pub const NONE: Self = Self { genesis: None };

    /// Regtest's genesis. A regtest node connects mainnet's configured
    /// genesis block (`get_config(FAKECHAIN)`, `shekyl-node`'s `genesis.rs`),
    /// so its block 0 is mainnet's. The pin is the chain's identity: a store
    /// opened as regtest whose block 0 is testnet's or stagenet's is
    /// refused. A mainnet store shares regtest's block 0, so only the
    /// network marker tells those two apart.
    pub const FAKECHAIN: Self = Self::MAINNET;

    /// Mainnet: its genesis (`geblock block-id --network mainnet`; derived
    /// from `cryptonote_config.h` in `genesis_pin_tests`).
    const MAINNET: Self = Self::genesis_only([
        0xd7, 0xaf, 0x38, 0x23, 0x39, 0xb2, 0xcd, 0x0c, 0x4e, 0xe4, 0xb2, 0xea, 0x0a, 0xfe, 0x74,
        0x26, 0xf3, 0x4b, 0xc2, 0x97, 0x14, 0x95, 0xd9, 0x87, 0x3f, 0xd4, 0xce, 0xc2, 0x10, 0x7a,
        0xd8, 0xed,
    ]);
    /// Testnet: its genesis.
    const TESTNET: Self = Self::genesis_only([
        0xe8, 0x95, 0xbf, 0x2b, 0xaa, 0x4e, 0xa4, 0xcc, 0xb0, 0x76, 0x20, 0xd3, 0x54, 0xe5, 0x44,
        0xa4, 0xbe, 0x24, 0x3b, 0xf3, 0x29, 0x92, 0x5f, 0x6a, 0x8a, 0x51, 0x63, 0x1d, 0xa1, 0x80,
        0x33, 0xda,
    ]);
    /// Stagenet: its genesis.
    const STAGENET: Self = Self::genesis_only([
        0x37, 0x1e, 0x8f, 0xa3, 0x10, 0xaf, 0xb0, 0xc6, 0x08, 0x9e, 0x47, 0x39, 0x8e, 0xbe, 0x02,
        0xc4, 0xe2, 0xaa, 0x18, 0x20, 0xe8, 0xcc, 0xfd, 0x32, 0xe3, 0x28, 0x55, 0x8b, 0x99, 0x67,
        0x7c, 0x60,
    ]);

    const fn genesis_only(genesis: [u8; 32]) -> Self {
        Self {
            genesis: Some(BlockHash::from_bytes(genesis)),
        }
    }

    /// The genesis pin the release carries for `network`. Three values,
    /// one lookup.
    #[must_use]
    pub const fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
            Network::Stagenet => Self::STAGENET,
        }
    }

    /// A pin from an explicit hash, for fixtures only. Production tables
    /// are the constants above.
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
