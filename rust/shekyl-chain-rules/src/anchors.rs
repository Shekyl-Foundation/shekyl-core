// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The release-carried anchors — the Rust home of the anchor model
//! `PDM-Q5` ratified (`ARCHIVAL_PRUNED_DAEMON_MODE.md` §`PDM-Q5`, RULED
//! 2026-09-18; `CHAIN_RULES_SLICE_3.md` §0).
//!
//! *"A release-carried checkpoint `C` on the `assumevalid` argument; three
//! bands (`≤ C` skeleton, trusted with the binary; `(C, tip − W]` filled
//! from archivers; above from peers); the tip-relative trust horizon and
//! the operator trust-below fallback REJECTED."* An anchor is a block the
//! **binary** vouches for: below the current anchor `C` a fresh node holds
//! the chain's skeleton and asserts, rather than checks, the proofs the
//! anchor stands behind. The table is therefore **data shipped with the
//! release** and nothing else — a `const` per network beside
//! [`RuleSchedule`](crate::RuleSchedule), never a file an operator can
//! edit: an operator-supplied anchor is exactly the trust channel the
//! ruling rejects (`PDM-Q-F23` deleted the runtime `checkpoints.json` for
//! that reason), and *"trusted with the binary"* is the whole of the
//! semantics.
//!
//! # What reads it
//!
//! - **CEN-E1**, the anchor's own rule (`PDM-Q11`): a block connecting at an
//!   anchored height must carry that anchor's hash.
//! - **CEN-E5**, the binary's anchors agree with the file it opens. The
//!   check and its remedy live with the rule (`rules::anchors`): the writer
//!   calls [`ReleaseAnchors::conflict_with`] once, at open.
//! - **`Trust`** (`CHAIN_RULES_SLICE_3.md` §4.1): the input that carries the
//!   anchors into `validate`, and — from slice 6 — the below-anchor posture
//!   `PDM-Q5` `:293` defines as band 1's skeleton. `Trust::below_anchor` is
//!   mintable only from this table's [`current`](ReleaseAnchors::current)
//!   entry (`PDM-Q-F27`), so `D_max` never has to defend a node below its
//!   anchor.
//!
//! # The only anchor is genesis, until the first checkpoint release
//!
//! Every public network's table holds one entry: `(0, genesis_hash)` —
//! CEN-F11's "as configured" half (`CHAIN_RULES_SLICE_4.md` Q3, ruled (a)
//! 2026-09-22). The genesis block's identity is a per-network fact the
//! binary carries — `GENESIS_TX` and `GENESIS_NONCE` in
//! `cryptonote_config.h`, the block `generate_genesis_block` assembles from
//! them — which is exactly the definition of an anchor: a block the binary
//! vouches for. One mechanism for one kind of fact, and the two behaviours
//! F11 asks for are the two this table already has: CEN-E1 judges a
//! height-0 candidate against it, and CEN-E5 refuses a file whose genesis is
//! another network's at open (`Remedy::RefuseToRun`). The hashes are
//! **derived**, not restated: `anchors_tests` rebuilds each network's genesis
//! block from `cryptonote_config.h`'s pins through the genesis tool and
//! asserts the table equals it, and asserts the table equals the client
//! identity's copy (`shekyl_rpc_types::genesis_hash_for`, `VC-D18`) so the
//! two Rust homes cannot drift.
//!
//! No release has shipped a *checkpoint* anchor: `PDM-Q5`'s launch-window
//! item puts the first before day ~195, then one per `≤ W`. That is an
//! observation about the release calendar, not about this type — the C++
//! `init_default_checkpoints` is the same empty table (`checkpoints.cpp:136`).
//! `the_only_anchor_is_genesis_until_the_first_checkpoint_release` pins the
//! fact so the first checkpoint entry is a deliberate edit that fails a
//! test, never a quiet one. Where `PDM-Q5` says "`C`", read "the last anchor
//! above genesis" when the distinction matters; band 1 (`≤ C`) still reads
//! correctly, since below genesis there is nothing. `PDM :304` ships the
//! first release with `assumevalid = 0`; whether that state is "genesis is
//! the anchor" or "no anchor at all" is the one question this slice put to
//! the PDM lane (`CHAIN_RULES_SLICE_4.md` Q3).

use core::fmt;

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

/// One release-carried anchor: the block the binary vouches for at
/// `height`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The anchored height — an absolute chain instant.
    pub height: BlockHeight,
    /// The block identity (CEN-B6) the chain must carry there.
    pub hash: BlockHash,
}

/// The release-carried anchor table for one network — data, strictly
/// ascending by height, `const`-asserted well formed (a table out of order
/// or with a repeated height is a compile error, as a malformed
/// [`RuleSchedule`](crate::RuleSchedule) is).
///
/// There is no public constructor from arbitrary entries: the only tables
/// are the per-network constants [`for_network`](Self::for_network) selects
/// and [`EMPTY`](Self::EMPTY) — nettype selects *data*, never control flow
/// (rule 71), and no path exists for a table the release did not carry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleaseAnchors {
    entries: &'static [Anchor],
}

impl ReleaseAnchors {
    /// No anchors: what a Fakechain always has — no release vouches for a
    /// regtest chain, not even for its genesis (`Trust::UNANCHORED`).
    pub const EMPTY: Self = Self { entries: &[] };

    /// Mainnet's anchors: genesis (`geblock block-id --network mainnet`;
    /// derived from `cryptonote_config.h` in `anchors_tests`).
    const MAINNET: Self = Self {
        entries: &[genesis_anchor([
            0xb6, 0x29, 0x3d, 0x3e, 0xc8, 0x14, 0xd4, 0xb7, 0xac, 0xdc, 0xba, 0x7d, 0x79, 0xd2,
            0xd2, 0x2b, 0x03, 0x5e, 0xaa, 0xe5, 0x2b, 0xb3, 0x5c, 0xb3, 0xf8, 0x62, 0xad, 0xac,
            0x16, 0xc1, 0x40, 0x31,
        ])],
    };
    /// Testnet's anchors: genesis.
    const TESTNET: Self = Self {
        entries: &[genesis_anchor([
            0xb0, 0xb2, 0xa6, 0x3a, 0xa9, 0x1c, 0x4e, 0x23, 0xbc, 0xf6, 0x86, 0x09, 0x5c, 0x2f,
            0xcc, 0xb2, 0x77, 0x60, 0xcb, 0x9e, 0xc1, 0x92, 0x8c, 0xca, 0x3b, 0xf1, 0x7e, 0x17,
            0xf8, 0x11, 0x2a, 0x7c,
        ])],
    };
    /// Stagenet's anchors: genesis.
    const STAGENET: Self = Self {
        entries: &[genesis_anchor([
            0xad, 0x10, 0x1a, 0x4d, 0x8b, 0x47, 0xa8, 0xc9, 0xa3, 0xfa, 0x4f, 0xf6, 0x25, 0xb6,
            0xc7, 0x17, 0x6d, 0x0b, 0xf9, 0x5f, 0x68, 0x61, 0x50, 0xe9, 0x44, 0xc2, 0xc7, 0x78,
            0xde, 0xe5, 0x23, 0x96,
        ])],
    };

    /// The anchors the release carries for `network`. Three values, one
    /// lookup.
    #[must_use]
    pub const fn for_network(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::MAINNET,
            Network::Testnet => Self::TESTNET,
            Network::Stagenet => Self::STAGENET,
        }
    }

    /// A table from explicit entries, for fixtures only. Production tables
    /// are the constants above; a test that needs an anchored height builds
    /// one here (the `RuleSet::admitting_for_tests` shape). Must be well
    /// formed — the fixture is checked at construction so a test cannot
    /// pass by feeding a table the compile-time gate would have refused.
    #[cfg(any(test, feature = "harness"))]
    #[must_use]
    pub const fn for_tests(entries: &'static [Anchor]) -> Self {
        let table = Self { entries };
        assert!(
            well_formed(&table),
            "fixture anchor table is not strictly ascending"
        );
        table
    }

    /// The hash the release vouches for at exactly `height`, if it anchors
    /// one — CEN-E1's read. `None` at every unanchored height, which is
    /// every height today.
    #[must_use]
    pub fn expected_at(&self, height: BlockHeight) -> Option<BlockHash> {
        // Ascending by construction: a binary search is correct, and the
        // table is small enough that it is also unnecessary; the linear
        // scan keeps the invariant it relies on visible.
        self.entries
            .iter()
            .find(|anchor| anchor.height == height)
            .map(|anchor| anchor.hash)
    }

    /// The current anchor `C` — the last entry — or `None` when no release
    /// has shipped one. The value `Trust::below_anchor` is minted from
    /// (`PDM-Q-F27`) and the ceiling of band 1.
    #[must_use]
    pub const fn current(&self) -> Option<Anchor> {
        match self.entries.last() {
            Some(anchor) => Some(*anchor),
            None => None,
        }
    }

    /// Whether `height` lies in band 1 — at or below the current anchor
    /// (`PDM-Q5` `:293`, *"`≤ C` skeleton"*). What the C++ called
    /// `is_in_checkpoint_zone`; `false` on an empty table, so an unanchored
    /// node verifies everything.
    #[must_use]
    pub fn covers(&self, height: BlockHeight) -> bool {
        self.current().is_some_and(|anchor| height <= anchor.height)
    }

    /// The entries, ascending. Crate-private: callers read through the
    /// named accessors so the table is never mistaken for a list to consult
    /// freely; the rules iterate it.
    pub(crate) const fn entries(&self) -> &'static [Anchor] {
        self.entries
    }
}

impl fmt::Debug for ReleaseAnchors {
    // A failing assertion wants the heights, not thirty-two bytes per row.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseAnchors")
            .field("count", &self.entries.len())
            .field(
                "heights",
                &format_args!(
                    "{:?}",
                    self.entries
                        .iter()
                        .map(|a| a.height.to_raw())
                        .collect::<Vec<_>>()
                ),
            )
            .finish()
    }
}

/// The table invariant: strictly ascending by height. Two anchors at one
/// height would make [`ReleaseAnchors::expected_at`] ambiguous and the
/// last-entry-is-current reading of [`ReleaseAnchors::current`] false.
/// The height-0 anchor for a network's genesis block.
const fn genesis_anchor(hash: [u8; 32]) -> Anchor {
    Anchor {
        height: BlockHeight::ZERO,
        hash: BlockHash::from_bytes(hash),
    }
}

const fn well_formed(table: &ReleaseAnchors) -> bool {
    let mut i = 1;
    while i < table.entries.len() {
        if table.entries[i].height.to_raw() <= table.entries[i - 1].height.to_raw() {
            return false;
        }
        i += 1;
    }
    true
}

// Every table `for_network` can return is well formed, at compile time.
const _: () = {
    assert!(well_formed(&ReleaseAnchors::MAINNET));
    assert!(well_formed(&ReleaseAnchors::TESTNET));
    assert!(well_formed(&ReleaseAnchors::STAGENET));
};

// Declared here rather than in `lib.rs` because the tests build fixture
// tables against the private constructor and read `well_formed`.
#[cfg(test)]
#[path = "anchors_tests.rs"]
mod anchors_tests;
