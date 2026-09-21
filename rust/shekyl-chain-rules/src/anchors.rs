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
//! - **CEN-E5**, the binary's anchors agree with the file it opens:
//!   [`ReleaseAnchors::conflict_with`] over a recorded chain, run by the
//!   writer at open; the remedy (pop, or refuse to run) is the writer's.
//! - **`Trust`** (`CHAIN_RULES_SLICE_3.md` §4.1): the input that carries the
//!   anchors into `validate`, and — from slice 6 — the below-anchor posture
//!   `PDM-Q5` `:293` defines as band 1's skeleton. `Trust::below_anchor` is
//!   mintable only from this table's [`current`](ReleaseAnchors::current)
//!   entry (`PDM-Q-F27`), so `D_max` never has to defend a node below its
//!   anchor.
//!
//! # Every table is empty today
//!
//! No release has shipped an anchor: `PDM-Q5`'s launch-window item puts the
//! first checkpoint release before day ~195, then one per `≤ W`. That is an
//! observation about the release calendar, not about this type — the C++
//! `init_default_checkpoints` is the same empty table (`checkpoints.cpp:136`),
//! and `no_release_has_shipped_an_anchor_yet` pins the fact so the first
//! entry is a deliberate edit that fails a test, never a quiet one.

use core::fmt;

use shekyl_address::Network;
use shekyl_types::{BlockHash, BlockHeight};

use crate::rules::anchors::{rollback_target, E5};
use crate::view::ChainView;

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
    /// No anchors: what every network's table is today, and what a
    /// Fakechain always has — no release vouches for a regtest chain.
    pub const EMPTY: Self = Self { entries: &[] };

    /// Mainnet's anchors.
    const MAINNET: Self = Self::EMPTY;
    /// Testnet's anchors.
    const TESTNET: Self = Self::EMPTY;
    /// Stagenet's anchors.
    const STAGENET: Self = Self::EMPTY;

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

    /// **CEN-E5.** The first anchor the recorded chain contradicts, if any.
    ///
    /// The writer runs this **once, at open**, before connecting anything:
    /// a file whose recorded block at an anchored height is not the anchor
    /// is on a chain this binary does not vouch for, and the writer applies
    /// [`AnchorConflict::remedy`] — pops to the rollback target, or refuses
    /// to run when no pop can help. Anchors above the tip are not yet
    /// checkable and are skipped; an empty file contradicts nothing.
    ///
    /// # Errors
    ///
    /// The view's own fault, when it could not answer. A fault is not a
    /// conflict.
    pub fn conflict_with<'id, V: ChainView<'id>>(
        &self,
        view: &V,
    ) -> Result<Option<AnchorConflict>, V::Fault> {
        E5::conflict_with(self, view)
    }

    /// The entries, ascending. Crate-private: callers read through the
    /// named accessors so the table is never mistaken for a list to consult
    /// freely; the rules iterate it.
    pub(crate) const fn entries(&self) -> &'static [Anchor] {
        self.entries
    }
}

/// A recorded chain that contradicts a release-carried anchor (CEN-E5's
/// finding). Carries what the binary vouched for and what the file holds;
/// [`remedy`](Self::remedy) says what the writer does about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorConflict {
    /// The anchored height.
    pub height: BlockHeight,
    /// The identity the release vouches for there.
    pub expected: BlockHash,
    /// The identity the file recorded there — `None` when the file has no
    /// block at a height at or below its own tip (a hole where the store's
    /// density invariant says there cannot be one).
    pub recorded: Option<BlockHash>,
}

impl AnchorConflict {
    /// What the writer does with this conflict — C2-R1b clause (3), the
    /// rule the C++ `check_against_checkpoints` applies, stated once here
    /// so no writer re-derives the floor.
    #[must_use]
    pub const fn remedy(&self) -> Remedy {
        if self.height.is_zero() {
            Remedy::RefuseToRun
        } else {
            Remedy::PopTo(rollback_target(self.height))
        }
    }
}

/// The writer's response to an [`AnchorConflict`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// The conflict is **at genesis**: no pop can resolve it — genesis
    /// cannot be popped, and rolling back to a chain whose height-0 block
    /// still mismatches would report the conflict resolved while fixing
    /// nothing. The file is on the wrong network for this binary; the
    /// writer does not run (`blockchain.cpp:6383`–`:6395`, the
    /// reports-success shape's fourth instance).
    RefuseToRun,
    /// Pop until the tip is at this height — two blocks before the
    /// conflict, floored at 1 — then resync. A pop the store refuses
    /// (`StoreCannot::PopBelowFloor`: the undo log's watermark, `≥ D_max`
    /// once S-PRUNE raises it) is itself a reason not to run: a node may
    /// not keep running in contradiction with an anchor it accepted
    /// (C2-R1b F-1(b)).
    PopTo(BlockHeight),
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
