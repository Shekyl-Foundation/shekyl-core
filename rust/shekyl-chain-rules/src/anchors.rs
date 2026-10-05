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
//! # Genesis is a pin, not an anchor
//!
//! Every public network's table also carries its **genesis identity** —
//! CEN-F11's "as configured" half (`CHAIN_RULES_SLICE_4.md` Q3, ruled (a)
//! 2026-09-22) — and keeps it **apart from the anchors**, because it is a
//! different kind of fact (the PDM lane's answer to Q3's question,
//! 2026-09-22): an anchor is a block the binary *trusts*; genesis is a block
//! the binary *defines* — `GENESIS_TX` and `GENESIS_NONCE` in
//! `cryptonote_config.h`, the block `generate_genesis_block` assembles from
//! them. It is verified **by equality, never by assumption**, and belongs
//! to no trust band. So `PDM :304`'s first release, `assumevalid = 0`, is
//! *no anchor at all* — `Trust::Full`, band 1 empty — and not "genesis is
//! the anchor". The two would do the same verification work at height 0
//! (genesis has no proofs to skip) but not leave the same store: a node
//! connecting genesis under a below-anchor posture records the proof rows'
//! absence in coverage and in `connect`'s provenance, marking the file
//! "never parity evidence" — and the release gate that builds the first
//! checkpoint from a node run at `assumevalid = 0` would rest on a file the
//! charter says is not evidence.
//!
//! The type makes "genesis is the anchor" unrepresentable rather than
//! unintended: an [`Anchor`] is a checkpoint, at height `≥ 1` by the
//! compile-time gate, and [`current`](ReleaseAnchors::current) — the value
//! `Trust::below_anchor` is minted from — is the last *checkpoint*, `None`
//! until a release ships one. The equality reads see both kinds of pin
//! through one accessor, [`expected_at`](ReleaseAnchors::expected_at):
//! CEN-E1 judges a height-0 candidate against the genesis pin as it judges
//! a checkpointed height against its anchor, and CEN-E5 refuses a file
//! whose genesis is another network's at open (`Remedy::RefuseToRun`). The
//! hashes are **derived**, not restated: `anchors_tests` rebuilds each
//! network's genesis block from `cryptonote_config.h`'s pins through the
//! genesis tool and asserts the table equals it, and asserts the table
//! equals the client identity's copy (`shekyl_rpc_types::genesis_hash_for`,
//! `VC-D18`) so the two Rust homes cannot drift.
//!
//! No release has shipped a checkpoint: `PDM-Q5`'s launch-window item puts
//! the first before day ~195, then one per `≤ W`. That is an observation
//! about the release calendar, not about this type — the C++
//! `init_default_checkpoints` is the same empty table
//! (`checkpoints.cpp:136`).
//! `band_one_is_empty_until_the_first_checkpoint_release` pins the fact so
//! the first checkpoint entry is a deliberate edit that fails a test, never
//! a quiet one.

use core::fmt;

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

/// One release-carried anchor — a checkpoint: the block the binary vouches
/// for at `height`. Never genesis: `height ≥ 1` in every table the release
/// carries (the compile-time gate), because genesis is defined by the
/// binary, not trusted with it, and sits in no trust band.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    /// The anchored height — an absolute chain instant, `≥ 1`.
    pub height: BlockHeight,
    /// The block identity (CEN-B6) the chain must carry there.
    pub hash: BlockHash,
}

/// The release-carried table for one network — the network's genesis
/// identity, and its anchors (checkpoints) strictly ascending from height
/// `≥ 1` — `const`-asserted well formed (a table out of order, with a
/// repeated height, or anchoring height 0 is a compile error, as a
/// malformed [`RuleSchedule`](crate::RuleSchedule) is).
///
/// There is no public constructor from arbitrary entries: the only tables
/// are the per-network constants [`for_network`](Self::for_network) selects
/// and [`EMPTY`](Self::EMPTY) — nettype selects *data*, never control flow
/// (rule 71), and no path exists for a table the release did not carry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ReleaseAnchors {
    /// The genesis identity the binary defines for this network; verified
    /// by equality (CEN-E1 at height 0, CEN-E5 at open), assumed by nothing.
    /// `None` only on the table no release vouches for ([`EMPTY`](Self::EMPTY)).
    genesis: Option<BlockHash>,
    /// The anchors proper, ascending, every height `≥ 1`. Band 1 is
    /// `≤ current()`, and empty while this is.
    checkpoints: &'static [Anchor],
}

impl ReleaseAnchors {
    /// Nothing pinned: what a Fakechain always has — no release defines a
    /// regtest chain's genesis or vouches for any of its blocks
    /// (`Trust::UNANCHORED`).
    pub const EMPTY: Self = Self {
        genesis: None,
        checkpoints: &[],
    };

    /// Mainnet: its genesis (`geblock block-id --network mainnet`; derived
    /// from `cryptonote_config.h` in `anchors_tests`), no checkpoint yet.
    const MAINNET: Self = Self::genesis_only([
        0x16, 0xc6, 0x16, 0xa5, 0x04, 0xe5, 0xd3, 0x3a, 0x78, 0xe2, 0xec, 0x3a, 0x5d, 0xd7, 0xd8,
        0x7f, 0xfd, 0xd3, 0xed, 0xd4, 0x6a, 0x35, 0x11, 0x99, 0xcf, 0xfc, 0xc7, 0xc3, 0x0a, 0xf7,
        0x70, 0xe3,
    ]);
    /// Testnet: its genesis, no checkpoint yet.
    const TESTNET: Self = Self::genesis_only([
        0x52, 0x42, 0x5d, 0x8d, 0xa3, 0xa9, 0x0e, 0x41, 0xff, 0x54, 0x78, 0x01, 0x29, 0xbd, 0xbe,
        0x98, 0x97, 0xaa, 0x28, 0xc3, 0xd0, 0xa9, 0xc8, 0x0b, 0x04, 0xb4, 0xb5, 0xea, 0x35, 0xc9,
        0x11, 0xd8,
    ]);
    /// Stagenet: its genesis, no checkpoint yet.
    const STAGENET: Self = Self::genesis_only([
        0x65, 0x17, 0x39, 0x01, 0xb0, 0x49, 0x46, 0x81, 0x33, 0xe5, 0xf8, 0x21, 0xf6, 0x68, 0x77,
        0x2f, 0x13, 0x93, 0x6b, 0x1a, 0xbd, 0xff, 0x0e, 0x2a, 0xdd, 0x80, 0xff, 0x3b, 0x03, 0xcc,
        0xf5, 0xf0,
    ]);

    /// A public network's table before its first checkpoint release: the
    /// genesis pin alone, band 1 empty (`assumevalid = 0` ≡ `Trust::Full`).
    const fn genesis_only(genesis: [u8; 32]) -> Self {
        Self {
            genesis: Some(BlockHash::from_bytes(genesis)),
            checkpoints: &[],
        }
    }

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

    /// A table from explicit pins, for fixtures only. Production tables
    /// are the constants above; a test that needs an anchored height builds
    /// one here (the `RuleSet::admitting_for_tests` shape). Must be well
    /// formed — the fixture is checked at construction so a test cannot
    /// pass by feeding a table the compile-time gate would have refused
    /// (out of order, or an "anchor" at genesis).
    #[cfg(any(test, feature = "harness"))]
    #[must_use]
    pub const fn for_tests(genesis: Option<BlockHash>, checkpoints: &'static [Anchor]) -> Self {
        let table = Self {
            genesis,
            checkpoints,
        };
        assert!(
            well_formed(&table),
            "fixture anchor table is not strictly ascending from height 1"
        );
        table
    }

    /// The hash the release pins at exactly `height`, if it pins one —
    /// CEN-E1's read, and the one accessor that sees both kinds of pin:
    /// the genesis identity at height 0, an anchor at a checkpointed
    /// height. `None` at every other height, which is every height above
    /// genesis today.
    #[must_use]
    pub fn expected_at(&self, height: BlockHeight) -> Option<BlockHash> {
        if height == BlockHeight::ZERO {
            return self.genesis;
        }
        // Ascending by construction: a binary search is correct, and the
        // table is small enough that it is also unnecessary; the linear
        // scan keeps the invariant it relies on visible.
        self.checkpoints
            .iter()
            .find(|anchor| anchor.height == height)
            .map(|anchor| anchor.hash)
    }

    /// The current anchor `C` — the last checkpoint — or `None` when no
    /// release has shipped one. The value `Trust::below_anchor` is minted
    /// from (`PDM-Q-F27`) and the ceiling of band 1. Never genesis: a table
    /// holding only its genesis pin has no anchor, so `assumevalid = 0` has
    /// one constructible meaning, `Trust::Full`.
    #[must_use]
    pub const fn current(&self) -> Option<Anchor> {
        match self.checkpoints.last() {
            Some(anchor) => Some(*anchor),
            None => None,
        }
    }

    /// Whether `height` lies in band 1 — at or below the current anchor
    /// (`PDM-Q5` `:293`, *"`≤ C` skeleton"*). What the C++ called
    /// `is_in_checkpoint_zone`; `false` everywhere while no checkpoint has
    /// shipped — genesis included, which sits in no band — so such a node
    /// verifies everything.
    #[must_use]
    pub fn covers(&self, height: BlockHeight) -> bool {
        self.current().is_some_and(|anchor| height <= anchor.height)
    }

    /// Every pin in height order — the genesis identity, then the anchors —
    /// as `(height, hash)`: what CEN-E5 holds the recorded chain to at open.
    /// Crate-private: callers read through the named accessors so the table
    /// is never mistaken for a list to consult freely.
    pub(crate) fn pins(&self) -> impl Iterator<Item = (BlockHeight, BlockHash)> + '_ {
        self.genesis
            .map(|hash| (BlockHeight::ZERO, hash))
            .into_iter()
            .chain(
                self.checkpoints
                    .iter()
                    .map(|anchor| (anchor.height, anchor.hash)),
            )
    }
}

impl fmt::Debug for ReleaseAnchors {
    // A failing assertion wants the heights, not thirty-two bytes per row.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleaseAnchors")
            .field(
                "genesis",
                &if self.genesis.is_some() {
                    "pinned"
                } else {
                    "none"
                },
            )
            .field(
                "checkpoints",
                &format_args!(
                    "{:?}",
                    self.checkpoints
                        .iter()
                        .map(|a| a.height.to_raw())
                        .collect::<Vec<_>>()
                ),
            )
            .finish()
    }
}

/// The table invariant: the checkpoints are strictly ascending from height
/// `≥ 1`. Two anchors at one height would make
/// [`ReleaseAnchors::expected_at`] ambiguous and the last-is-current reading
/// of [`ReleaseAnchors::current`] false; an anchor at height 0 would make
/// genesis an anchor, which it is not — that slot is the genesis pin's, and
/// no trust band contains it.
const fn well_formed(table: &ReleaseAnchors) -> bool {
    let checkpoints = table.checkpoints;
    if !checkpoints.is_empty() && checkpoints[0].height.to_raw() == 0 {
        return false;
    }
    let mut i = 1;
    while i < checkpoints.len() {
        if checkpoints[i].height.to_raw() <= checkpoints[i - 1].height.to_raw() {
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
