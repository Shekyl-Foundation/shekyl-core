// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! One finality comparison, two seats.
//!
//! [`ForkCursor`] is the producer's walk: it confirms a fork only when a
//! stored hash matches the daemon at a depth inside `W`, and it refuses
//! when the walk passes `W` or the hash record ends while a deeper fork
//! is still possible. [`rollback_past_finality`] is the ingest backstop,
//! the same comparison against the **tree** tip.
//!
//! The two tips are different subjects. The tree is acknowledged before
//! the ledger commits, a rescan clears the ledger and not the tree, and
//! birthday backfill climbs the tree below the scan floor. Neither seat
//! stands in for the other. The store primitive is not a third: it must
//! still truncate arbitrarily deep.

use shekyl_curve_tree::{FINALITY_DEPTH_BLOCKS, REORG_HASH_WINDOW_BLOCKS};
use shekyl_types::{BlockCount, BlockHeight};

use super::error::{FinalityBreach, FinalityStop};

/// The cursor and the retained hash window describe one rewind.
///
/// [`REORG_HASH_WINDOW_BLOCKS`] holds the `W` blocks a maximal repairable
/// rewind drops, plus the one kept block whose hash confirms it. One more
/// disagreement is past finality.
const _: () = assert!(REORG_HASH_WINDOW_BLOCKS == FINALITY_DEPTH_BLOCKS + 1);

fn finality_depth() -> BlockCount {
    BlockCount::from_raw(FINALITY_DEPTH_BLOCKS)
}

/// Walk state for [`super::local_refresh`] finding a fork.
///
/// Constructed at the persisted tip. Each disagreed block advances the
/// span; a match, a missing hash, or genesis ends the walk.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ForkCursor {
    tip: BlockHeight,
    mismatches: BlockCount,
}

impl ForkCursor {
    /// A walk that starts at `tip` with nothing yet disagreed.
    pub(crate) fn at_tip(tip: BlockHeight) -> Self {
        Self {
            tip,
            mismatches: BlockCount::ZERO,
        }
    }

    /// `matched` agreed with the daemon. The first dropped height is the next one.
    ///
    /// A match inside this cursor cannot exceed `W`: [`Self::disagreed`]
    /// already refused the block past the window. The disagreements above
    /// `matched` are exactly the span from the tip, which is what makes the
    /// returned height the fork rather than a guess.
    pub(crate) fn agreed(self, matched: BlockHeight) -> BlockHeight {
        debug_assert_eq!(
            self.tip
                .checked_sub(matched)
                .expect("ForkCursor::agreed: the matching height is at or below the walk's tip",),
            self.mismatches,
            "every height above the match was a mismatch"
        );
        matched.saturating_add(BlockCount::ONE)
    }

    /// The block under the cursor disagreed.
    ///
    /// `Ok` through `W` disagreements. The next one is
    /// [`FinalityBreach::Measured`] with depth `W + 1`: the kept block at
    /// the bottom of a maximal repairable rewind disagreed, so the fork
    /// is past finality.
    pub(crate) fn disagreed(&mut self) -> Result<(), FinalityStop> {
        self.mismatches = self.mismatches + BlockCount::ONE;
        let window = finality_depth();
        if self.mismatches > window {
            Err(FinalityStop {
                depth: self.mismatches,
                finality_depth: window,
                breach: FinalityBreach::Measured,
            })
        } else {
            Ok(())
        }
    }

    /// No stored hash at `missing_at`. Every height above it was a mismatch.
    ///
    /// The shallowest fork still possible is a match at `missing_at`.
    /// The walk meets a gap past `W` as the `(W + 1)`th disagreement
    /// ([`Self::disagreed`]) before it falls off the record; a gap that
    /// arrives here with that span is the same measured refusal. A gap
    /// still inside `W` on a chain taller than `W` is
    /// [`FinalityBreach::RecordEnded`]: the depth is the mismatches
    /// actually seen, and a fork is not invented below the record. When
    /// the whole chain is inside `W`, the rewind to the record's end is
    /// repairable — nothing at that tip can be frozen.
    pub(crate) fn record_ended(self, missing_at: BlockHeight) -> Result<BlockHeight, FinalityStop> {
        let shallowest = self
            .tip
            .checked_sub(missing_at)
            .expect("ForkCursor::record_ended: the missing height is at or below the walk's tip");
        debug_assert_eq!(
            self.mismatches, shallowest,
            "every height above the gap was a mismatch"
        );
        let window = finality_depth();
        if shallowest > window {
            Err(FinalityStop {
                depth: shallowest,
                finality_depth: window,
                breach: FinalityBreach::Measured,
            })
        } else if self.tip.saturating_sub(BlockHeight::ZERO) > window {
            Err(FinalityStop {
                depth: self.mismatches,
                finality_depth: window,
                breach: FinalityBreach::RecordEnded,
            })
        } else {
            Ok(missing_at.saturating_add(BlockCount::ONE))
        }
    }

    /// The walk reached genesis. Genesis is the common ancestor, so the
    /// first dropped height is 1.
    ///
    /// Only reachable when the chain is inside `W`: a taller chain would
    /// have stopped in [`Self::disagreed`].
    pub(crate) fn reached_genesis(self) -> BlockHeight {
        debug_assert!(
            self.tip.saturating_sub(BlockHeight::ZERO) <= finality_depth(),
            "reached genesis on a chain taller than the finality window"
        );
        BlockHeight::ZERO.saturating_add(BlockCount::ONE)
    }
}

/// `Some` when keeping `keep` on a tree whose tip is `tip` drops more
/// than `W` blocks.
///
/// Keeping exactly `tip − W` drops nothing frozen: a segment ending at
/// `e` freezes once `tip − e >= W`, and every such `e` is at or below
/// the kept height. One block deeper is the first illegal keep. `keep`
/// ahead of `tip` drops nothing.
#[must_use]
pub(crate) fn rollback_past_finality(tip: BlockHeight, keep: BlockHeight) -> Option<FinalityStop> {
    let depth = tip.checked_sub(keep)?;
    let window = finality_depth();
    (depth > window).then_some(FinalityStop {
        depth,
        finality_depth: window,
        breach: FinalityBreach::Measured,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shekyl_curve_tree::SEGMENT_FREEZE_REORG_MARGIN_BLOCKS;

    fn tip(raw: u64) -> BlockHeight {
        BlockHeight::from_raw(raw)
    }

    #[test]
    fn a_match_at_the_finality_floor_is_the_deepest_repairable_rewind() {
        let tip = tip(10_000);
        let mut cursor = ForkCursor::at_tip(tip);
        for _ in 0..FINALITY_DEPTH_BLOCKS {
            cursor
                .disagreed()
                .expect("a rewind of exactly W is inside the window");
        }
        let kept = tip.saturating_sub_count(BlockCount::from_raw(FINALITY_DEPTH_BLOCKS));
        let fork = cursor.agreed(kept);
        assert_eq!(fork, kept.saturating_add(BlockCount::ONE));
        assert!(rollback_past_finality(tip, kept).is_none());
    }

    #[test]
    fn one_block_past_the_window_is_measured() {
        let mut cursor = ForkCursor::at_tip(tip(10_000));
        for _ in 0..FINALITY_DEPTH_BLOCKS {
            cursor.disagreed().expect("depth W still folds");
        }
        let stop = cursor.disagreed().expect_err("depth W + 1 refuses");
        assert_eq!(stop.breach, FinalityBreach::Measured);
        assert_eq!(stop.depth, BlockCount::from_raw(FINALITY_DEPTH_BLOCKS + 1));
        assert_eq!(stop.finality_depth, finality_depth());
        assert!(!stop.to_string().contains(".curvetree"));

        let keep = tip(10_000).saturating_sub_count(stop.depth);
        let ingested = rollback_past_finality(tip(10_000), keep).expect("same bound");
        assert_eq!(ingested, stop);
    }

    #[test]
    fn the_band_between_the_ring_and_w_still_folds() {
        let tip = tip(10_000);
        // One block past the ring, still inside W.
        let depth = SEGMENT_FREEZE_REORG_MARGIN_BLOCKS + 1;
        assert!(depth < FINALITY_DEPTH_BLOCKS);
        let keep = tip.saturating_sub_count(BlockCount::from_raw(depth));
        assert!(rollback_past_finality(tip, keep).is_none());
    }

    #[test]
    fn a_short_record_on_a_tall_chain_does_not_invent_a_fork() {
        let tip = tip(10_000);
        let mut cursor = ForkCursor::at_tip(tip);
        let seen = 100;
        for _ in 0..seen {
            cursor.disagreed().expect("100 is inside W");
        }
        let missing_at = tip.saturating_sub_count(BlockCount::from_raw(seen));
        let stop = cursor.record_ended(missing_at).expect_err("unconfirmed");
        assert_eq!(stop.breach, FinalityBreach::RecordEnded);
        assert_eq!(stop.depth, BlockCount::from_raw(seen));
        let message = stop.to_string();
        assert!(message.contains("100"), "{message}");
        assert!(message.contains("hash record ended"), "{message}");
        assert!(!message.contains("731"), "{message}");
    }

    #[test]
    fn a_gap_already_past_the_window_is_measured() {
        let tip = tip(10_000);
        let span = FINALITY_DEPTH_BLOCKS + 5;
        let mut cursor = ForkCursor::at_tip(tip);
        for _ in 0..FINALITY_DEPTH_BLOCKS {
            cursor.disagreed().expect("depth W still folds");
        }
        for _ in 0..5 {
            assert!(
                cursor.disagreed().is_err(),
                "past W the cursor has already stopped, and it still counts"
            );
        }
        let missing_at = tip.saturating_sub_count(BlockCount::from_raw(span));
        let stop = cursor
            .record_ended(missing_at)
            .expect_err("shallowest depth is past W");
        assert_eq!(stop.breach, FinalityBreach::Measured);
        assert_eq!(stop.depth, BlockCount::from_raw(span));
    }

    #[test]
    fn a_chain_inside_the_window_may_rewind_to_the_record_or_to_genesis() {
        let tip = tip(4);
        let cursor = ForkCursor::at_tip(tip);
        assert_eq!(
            cursor.record_ended(tip).expect("no hash at a young tip"),
            tip.saturating_add(BlockCount::ONE)
        );
        let mut cursor = ForkCursor::at_tip(tip);
        cursor.disagreed().unwrap();
        cursor.disagreed().unwrap();
        let missing_at = tip.saturating_sub_count(BlockCount::from_raw(2));
        assert_eq!(
            cursor.record_ended(missing_at).expect("young chain"),
            missing_at.saturating_add(BlockCount::ONE)
        );
        assert_eq!(
            ForkCursor::at_tip(tip).reached_genesis(),
            BlockHeight::from_raw(1)
        );
    }

    #[test]
    fn keeping_the_tip_drops_nothing() {
        let tip = tip(10_000);
        assert!(rollback_past_finality(tip, tip).is_none());
        assert!(rollback_past_finality(tip, tip.saturating_add(BlockCount::ONE)).is_none());
    }
}
