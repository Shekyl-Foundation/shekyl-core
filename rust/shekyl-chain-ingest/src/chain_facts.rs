// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The chain operands one snapshot gives a block producer.
//!
//! [`chain_facts_on`] reads every operand the validator will judge the
//! next block by, off that snapshot and through the validator's own
//! definitions. [`TemplateFacts`](crate::connector::TemplateFacts) is the
//! connector message that asks for this.

use shekyl_chain_rules::{
    recorded, AtHeight, ChainView, Corrupt, EffectiveMedian, HeaderView, PerHeightRecord, ViewRead,
};
use shekyl_chain_store::store::{ReadSnapshot, SnapshotView, StoreError};
use shekyl_types::{BlockCount, BlockHash, BlockHeight};
use shekyl_units::AtomicUnits;

/// [`TemplateFacts`]' reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChainFacts {
    /// The height the next block connects at (`tip + 1`; `0` when empty).
    pub connecting: BlockHeight,
    /// The tip's identity, [`BlockHash::NULL`] when empty (CEN-A2).
    pub previous: BlockHash,
    /// The tree state at `connecting` (CEN-B5).
    pub curve_tree_root: shekyl_types::CurveTreeRoot,
    /// The parent's gross emission (CEN-F13's accumulator); zero at genesis.
    pub parent_coins_generated: shekyl_units::AtomicUnits,
    /// Everything burned through the tip.
    pub total_burned: shekyl_units::AtomicUnits,
    /// CEN-F17's `n` at `connecting`: the archival shards the parent
    /// chain's fold has closed, read through the validator's own definition
    /// (`shekyl_chain_rules::closed_shards_before`, `shekyl_types::shard_of`
    /// the parent's `cumulative_archival_len`), so the producer prices the
    /// fee split at the operand the validator reads
    /// (`rules::miner::BurnOperands`; E6 slice 7 wave B, re-keyed from the
    /// leaf count's frozen-segment count by DRS-E4 commit 4).
    pub closed_shards: shekyl_economics::ClosedShardCount,
    /// CEN-F20's window at `connecting`.
    pub tx_volume: shekyl_economics::TxVolume,
    /// CEN-C2's median at `connecting`; `None` at genesis.
    pub median_timestamp: Option<shekyl_types::Timestamp>,
    /// CEN-G6/G6b's two medians at `connecting` — what the producer's
    /// coinbase is priced against and its body bounded by, read through
    /// the validator's own definition (`effective_median_at`, slice 7 Q4:
    /// one derivation, two consumers) and never from the store's recorded
    /// `long_term_effective_median(tip)`, which is one block stale.
    pub medians: EffectiveMedian,
}

/// Why [`chain_facts_on`] has no facts.
#[derive(Debug)]
pub(crate) enum FactsStop {
    /// A read failed, or found the store corrupt.
    Read(ViewRead<StoreError>),
    /// The tip is the last height there is.
    NoNextHeight {
        /// The tip.
        tip: BlockHeight,
    },
}

/// The block producer's chain operands, all read on `snap`.
///
/// Every operand comes off the one snapshot, `total_burned` included, and
/// `closed_shards_before`, `tx_volume_window`, `mtp_median_at` and
/// `effective_median_at` are the rules' own definitions, so a template is
/// priced at what the validator will judge it by. The tip follower's
/// producer reads its claims and the pool's selection on the same
/// snapshot (`DRS_X_STORE_FLIP.md` DX-Q3, Q3).
///
/// # Errors
///
/// [`FactsStop`]. A curve-tree root the snapshot does not hold at the
/// connecting height is a hole below the tip.
pub(crate) fn chain_facts_on(snap: &ReadSnapshot<'_>) -> Result<ChainFacts, FactsStop> {
    let fault = |store: StoreError| FactsStop::Read(ViewRead::View(store));
    let view = SnapshotView::new(snap);
    let total_burned = snap.total_burned().map_err(fault)?;
    let tip = HeaderView::tip(&view).map_err(fault)?;
    let (connecting, previous) = match tip {
        None => (BlockHeight::ZERO, BlockHash::NULL),
        Some(t) => (
            t.height
                .checked_add(BlockCount::ONE)
                .ok_or(FactsStop::NoNextHeight { tip: t.height })?,
            t.hash,
        ),
    };
    let curve_tree_root = match view.root_at(connecting).map_err(fault)? {
        AtHeight::Recorded(root) => root,
        AtHeight::AboveTip => {
            return Err(FactsStop::Read(ViewRead::Corrupt(Corrupt::HoleBelowTip {
                at: connecting,
                record: PerHeightRecord::CurveTreeRoot,
            })))
        }
    };
    let parent_coins_generated = match tip {
        None => AtomicUnits::ZERO,
        Some(t) => {
            recorded(&view, t.height)
                .map_err(FactsStop::Read)?
                .coins_generated
        }
    };
    Ok(ChainFacts {
        connecting,
        previous,
        curve_tree_root,
        parent_coins_generated,
        total_burned,
        closed_shards: shekyl_chain_rules::closed_shards_before(&view, connecting)
            .map_err(FactsStop::Read)?,
        tx_volume: shekyl_chain_rules::tx_volume_window(&view, connecting)
            .map_err(FactsStop::Read)?,
        median_timestamp: shekyl_chain_rules::mtp_median_at(&view, connecting)
            .map_err(FactsStop::Read)?,
        medians: shekyl_chain_rules::effective_median_at(&view, connecting)
            .map_err(FactsStop::Read)?,
    })
}
