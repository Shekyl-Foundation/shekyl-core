// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Census 4.E — the anchor model's rules (`CHAIN_RULES_SLICE_3.md`).
//!
//! The rows of [`ReleaseAnchors`](crate::ReleaseAnchors), `PDM-Q5`'s
//! release-carried table. Two are this crate's; one is not yet:
//!
//! - **CEN-E5** — the binary's anchors agree with the file it opens. Not a
//!   per-block predicate: it is run **once, at open**, over the recorded
//!   chain ([`E5::conflict_over`]; [`E5::conflict_with`] is that walk over a
//!   [`ChainView`]), and its finding is an [`AnchorConflict`] the writer
//!   remedies (pop to a chain count, or refuse to run) rather than a
//!   consensus verdict. The check, the conflict, and the remedy live in
//!   this module; the table ([`ReleaseAnchors`](crate::ReleaseAnchors))
//!   stays data. The first row this crate enforces at a site other than
//!   `validate` — `RowStatus::EnforcedAt` is its registry status (slice 3
//!   Q4), excluded from per-block completeness because no per-block
//!   coverage could ever contain it.
//! - **CEN-E1** — a block connecting at an anchored height carries that
//!   anchor's hash. Per block, view-bound ([`E1`]); reads the anchors from
//!   the `Trust` input that carries them into `validate`.
//! - **CEN-E2** — an alternative block at or below the last anchor is
//!   refused; `D_max`'s second band lands in the same function (`PDM-Q11`).
//!   **No Rust site**: the store admits no alternative block, and on the
//!   main chain the floor holds by construction (a candidate at `tip + 1`
//!   is above every anchor `≤ tip`). Subsumed behind the alt `ChainView`
//!   (slice 9) *and* `D_max`'s numeric (`PDM-Q11`, provisional) — the D5
//!   shape, with two blockers rather than one.

use shekyl_types::{BlockCount, BlockHash, BlockHeight, ChainCount};

use crate::anchors::ReleaseAnchors;
use crate::census::CenRow;
use crate::rules::{BlockContext, BlockRule, Rule};
use crate::verdict::{refused, Locus, Verdict};
use crate::view::{AtHeight, ChainView, Tip};

/// CEN-E1: a block connecting at an anchored height carries that anchor's
/// hash — the anchor's own rule (`PDM-Q11`), the `assumevalid` argument
/// made a predicate.
///
/// Reads the release's anchors through the [`Trust`](crate::Trust) input
/// (`cx.trust`) and the block's identity through the token (`form` derived
/// it once, CEN-B6). At an unanchored height — every height today — the
/// rule is vacuously satisfied and **recorded as evaluated**, which the C++
/// (`blockchain.cpp:5545` main, `:2186` alt: `check_block`) does not do;
/// the coverage says the row ran. One predicate for both C++ arms: the
/// main arm's `is_in_checkpoint_zone` guard is a lookup short-cut, not a
/// rule (slice 3 F11). The alt arm's *forced reorg on a match* is an
/// alt-chain consequence and lands with CEN-E2's alt home (slice 9).
///
/// `form` cannot evaluate it: the connecting height is the view's
/// (F12) — the C++ files the refusal as `reject_block_form`, the Rust as a
/// view-bound `InvalidBlock { rule: E1, locus: Block }`.
pub(crate) struct E1;

impl Rule for E1 {
    const ROW: CenRow = CenRow::E1;
}

impl BlockRule for E1 {
    fn check<'id, V: ChainView<'id>>(
        cx: &BlockContext<'_>,
        _view: &V,
    ) -> Result<Verdict<()>, V::Fault> {
        match cx.trust.anchors().expected_at(cx.connecting) {
            Some(expected) if expected != cx.formed.hash() => refused(Self::ROW, Locus::Block),
            Some(_) | None => Ok(Ok(())),
        }
    }
}

/// CEN-E5: at open, every anchor the binary carries at or below the
/// recorded tip names the block the file actually recorded there.
///
/// What survives of the census row after `PDM-Q-F23` removed the runtime
/// checkpoint file: C2-R1b clause (3), run once at open over the
/// release-carried table. The check is [`E5::conflict_over`];
/// [`E5::conflict_with`] is that walk over a [`ChainView`]. The remedy is
/// [`AnchorConflict::remedy`]. The writer executes the remedy. This crate
/// has no store handle and cannot pop. The store's public-network open
/// refuses on the conflict and does not pop; the pop stays the ingest
/// driver's (`docs/FOLLOWUPS.md`).
pub(crate) struct E5;

impl Rule for E5 {
    const ROW: CenRow = CenRow::E5;
}

impl E5 {
    /// The first pin the recorded chain contradicts, if any, in height
    /// order — the genesis identity at 0, then the anchors.
    ///
    /// `tip` is the recorded tip. `None` is an empty file, which
    /// contradicts nothing: there is no block for a pin to disagree with
    /// (the C++ skips every point at or above height 0 when the DB is
    /// empty). `recorded_at` answers a pinned height at or below that tip:
    /// `Some` is the block's identity, `None` is a hole where the chain
    /// claims a block. Pins above the tip are not yet checkable and are
    /// skipped, as the C++ `continue`s past `pt.first >= blockchain_height`.
    ///
    /// `Err` is the reader failing to answer — a fault, not a conflict.
    /// [`conflict_with`](Self::conflict_with) is this walk over a view.
    pub(crate) fn conflict_over<E>(
        anchors: &ReleaseAnchors,
        tip: Option<Tip>,
        mut recorded_at: impl FnMut(BlockHeight) -> Result<Option<BlockHash>, E>,
    ) -> Result<Option<AnchorConflict>, E> {
        let Some(tip) = tip else {
            return Ok(None);
        };
        for (height, expected) in anchors.pins() {
            if height > tip.height {
                break;
            }
            // Heights at or below the tip are dense (the store's
            // invariant). A hole at a pinned height is the file missing a
            // block it claims to have — a conflict, with nothing recorded
            // to name. A reader that cannot answer returns `Err` instead,
            // and that stays a fault.
            let recorded = recorded_at(height)?;
            if recorded != Some(expected) {
                return Ok(Some(AnchorConflict {
                    height,
                    expected,
                    recorded,
                }));
            }
        }
        Ok(None)
    }

    /// [`conflict_over`](Self::conflict_over) over `view`: the tip, then
    /// each pinned block's identity.
    pub(crate) fn conflict_with<'id, V: ChainView<'id>>(
        anchors: &ReleaseAnchors,
        view: &V,
    ) -> Result<Option<AnchorConflict>, V::Fault> {
        Self::conflict_over(anchors, view.tip()?, |height| {
            Ok(match view.block_at(height)? {
                AtHeight::Recorded(block) => Some(block.hash),
                AtHeight::AboveTip => None,
            })
        })
    }
}

/// A recorded chain that contradicts a release-carried anchor (CEN-E5's
/// finding). Carries what the binary vouched for and what the file holds.
/// [`remedy`](Self::remedy) says what the writer does about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnchorConflict {
    /// The anchored height.
    pub height: BlockHeight,
    /// The identity the release vouches for there.
    pub expected: BlockHash,
    /// The identity the file recorded there. `None` when the file has no
    /// block at a height at or below its own tip — a hole where the store's
    /// density invariant says there cannot be one.
    pub recorded: Option<BlockHash>,
}

impl AnchorConflict {
    /// What the writer does with this conflict (C2-R1b clause (3)).
    ///
    /// Genesis refuses to run: the floor that fixes every later conflict
    /// would leave the height-0 block in place. Every other height pops
    /// to the chain count [`Remedy::PopTo`] carries.
    #[must_use]
    pub const fn remedy(&self) -> Remedy {
        if self.height.is_zero() {
            Remedy::RefuseToRun
        } else {
            Remedy::PopTo(rollback_count(self.height))
        }
    }
}

/// The writer's response to an [`AnchorConflict`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// The conflict is at genesis. No pop can resolve it: genesis cannot be
    /// popped, and a chain that still holds that block still mismatches.
    /// The file is on the wrong network for this binary; the writer does
    /// not run.
    RefuseToRun,
    /// Pop until the chain has this many blocks, then resync.
    ///
    /// The payload is a block count, not a tip height. The tip it leaves
    /// is [`ChainCount::tip`]: the conflicting block and the two blocks
    /// before it are gone, and a chain too short for that keeps genesis
    /// alone. A conflict at height 1, 2, or 3 therefore leaves genesis.
    /// Reading the count as a tip height keeps a height-1 conflict.
    ///
    /// A pop the store refuses (`StoreCannot::PopBelowFloor`, the undo-log
    /// watermark, `≥ D_max` once S-PRUNE raises it) is itself a reason not
    /// to run (C2-R1b F-1(b)). The writer applies this; this crate has no
    /// store.
    PopTo(ChainCount),
}

impl ReleaseAnchors {
    /// **CEN-E5.** The first pin the recorded chain contradicts, if any.
    ///
    /// `tip` is the recorded tip (`None`: an empty file, which contradicts
    /// nothing). `recorded_at` answers a pinned height at or below that
    /// tip. Pins above the tip are not yet checkable. Run once, at open,
    /// before connecting anything.
    ///
    /// [`conflict_with`](Self::conflict_with) is this walk over a
    /// [`ChainView`](crate::ChainView). A reader that is not a view — the
    /// store's snapshot, whose `ChainView` impl is deferred — calls this
    /// with the tip and the identity it recorded, so the two cannot grow
    /// different policies.
    ///
    /// # Errors
    ///
    /// `recorded_at`'s error, when the reader could not answer. A fault is
    /// not a conflict.
    pub fn conflict_over<E>(
        &self,
        tip: Option<Tip>,
        recorded_at: impl FnMut(BlockHeight) -> Result<Option<BlockHash>, E>,
    ) -> Result<Option<AnchorConflict>, E> {
        E5::conflict_over(self, tip, recorded_at)
    }

    /// **CEN-E5** over a [`ChainView`](crate::ChainView).
    ///
    /// [`conflict_over`](Self::conflict_over) is the walk. This is that walk
    /// with the view's tip and `block_at`.
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
}

/// Blocks a CEN-E5 rollback discards: the conflicting anchor and the two
/// blocks before it (C2-R1b clause (3), "a couple of blocks before").
const ROLLBACK_DEPTH: BlockCount = {
    const BEFORE_THE_ANCHOR: u64 = 2;
    const THE_ANCHOR: u64 = 1;
    BlockCount::from_raw(BEFORE_THE_ANCHOR + THE_ANCHOR)
};

/// The chain length at which a pop stops.
///
/// The kept tip is [`ROLLBACK_DEPTH`] below `conflict_at`. The length of
/// the chain whose newest block is that tip is one more than
/// [`ChainCount::from_next_height`] of it — the inverse of
/// [`ChainCount::tip`]. A chain that cannot rewind that far keeps genesis
/// alone ([`ChainCount`] of one). `conflict_at` of zero is not a pop;
/// [`AnchorConflict::remedy`] refuses it.
pub(crate) const fn rollback_count(conflict_at: BlockHeight) -> ChainCount {
    chain_with_tip(conflict_at.saturating_sub_count(ROLLBACK_DEPTH))
}

/// The chain whose newest block is `tip`.
///
/// Inverse of [`ChainCount::tip`]. [`ChainCount::from_next_height`] is the
/// chain whose *next* block would be `tip`; this chain also holds `tip`.
const fn chain_with_tip(tip: BlockHeight) -> ChainCount {
    match ChainCount::from_next_height(tip).checked_add(BlockCount::ONE) {
        Some(count) => count,
        // `tip` is `BlockHeight::MAX`. The rollback depth is non-zero, so
        // a kept tip is at most `MAX - 1` and this arm does not run.
        None => panic!("a chain whose tip is BlockHeight::MAX does not fit in ChainCount"),
    }
}

#[cfg(test)]
#[path = "anchors_tests.rs"]
mod anchors_tests;
