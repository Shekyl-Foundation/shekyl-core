// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`SnapshotView`]: the validator's [`ChainView`] over a committed
//! [`ReadSnapshot`] — what the pool door judges a transaction against
//! (DRS-E5 PR-b, `DRS_E5_POOL_ALT_PRUNE.md` §2.2). The reservation in
//! [`BatchView`](super::BatchView)'s module docs ("a `ReadSnapshot`-backed
//! view … is a later, separate implementor") is this type.
//!
//! # Same bodies, the snapshot's fault policy
//!
//! Every read is the body [`BatchView`](super::BatchView) calls — the
//! shared `chain_reads`, `curve_reads`, `leaf_reads`, `tx_reads` and
//! `archival_reads` — over the snapshot's transaction. The one difference
//! is what a fault does: a snapshot reader arms nothing (the halt is the
//! writer's state), so an invariant fault comes back as the plain
//! [`StoreError`] the snapshot's own reads return, never a verdict. A
//! reader that reproduced a body instead of calling it would re-create the
//! two-readers-of-one-table drift the shared modules exist to prevent.
//!
//! # No brand, so no connect
//!
//! The type carries no `'id`: it implements the view traits for every
//! brand, so a `ChainValid` judged over it names `SnapshotView`, which
//! `connect` (`ChainValid<'id, BatchView<'_, 'id>>`) does not accept. The
//! pool judges; only the writer connects.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::{
    AtHeight, BlockDrawsFloor, BlockOutputs, ChainView, Claimable, EpochFloor, HeaderRecord,
    HeaderView, Pricing, RecordedBlock, RecordedWeights, ReleaseJournalFloor, Settling,
    SlashLogFloor, Tip, TreeFrontier,
};
use shekyl_types::archival::{
    BlockDraws, CompleteTreeSet, DrawableDigest, IndexedDraw, IssuedDigest, PassCount, ServedShard,
    SettlementRow, SupportCount,
};
use shekyl_types::{
    BlockCount, BlockHash, BlockHeight, CurveTreeRoot, KeyImage, LongTermWeight, PCanonicalId,
    SettlementEpoch, ShardId, TxHash,
};
use shekyl_units::AtomicUnits;

use crate::codec::{BlockInfo, BondRecord, CodecError, RMarket, SigmaWorkMilli, SlashLogEntry};

use super::archival_reads;
use super::chain_reads::{self, ReadFault};
use super::curve_reads;
use super::error::{CellFault, StoreError, StoreInvariant};
use super::leaf_reads;
use super::read::ReadSnapshot;
use super::tx_reads;

/// The committed chain as one snapshot holds it, as a [`ChainView`].
#[derive(Clone, Copy)]
pub struct SnapshotView<'s> {
    snapshot: &'s ReadSnapshot<'s>,
}

impl core::fmt::Debug for SnapshotView<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotView").finish_non_exhaustive()
    }
}

impl<'s> SnapshotView<'s> {
    /// The chain `snapshot` holds.
    #[must_use]
    pub const fn new(snapshot: &'s ReadSnapshot<'s>) -> Self {
        Self { snapshot }
    }

    /// The recorded tip as this snapshot holds it: its height and decoded
    /// `block_info` row, `None` for an empty chain.
    fn tip_row(&self) -> Result<Option<(u64, BlockInfo)>, StoreError> {
        chain_reads::tip_of(self.snapshot.txn()).map_err(ReadFault::into_plain)
    }
}

impl<'id> HeaderView<'id> for SnapshotView<'_> {
    type Fault = StoreError;

    fn tip(&self) -> Result<Option<Tip>, StoreError> {
        Ok(self.tip_row()?.map(|(height, info)| Tip {
            height: BlockHeight::from_raw(height),
            hash: info.hash,
        }))
    }

    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreError> {
        Ok(match self.block_at(height)? {
            AtHeight::AboveTip => AtHeight::AboveTip,
            AtHeight::Recorded(block) => AtHeight::Recorded(block.header),
        })
    }
}

impl<'id> ChainView<'id> for SnapshotView<'_> {
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, StoreError> {
        chain_reads::has_key_image(self.snapshot.txn(), key_image).map_err(ReadFault::into_plain)
    }

    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, StoreError> {
        let tip = self.tip_row()?;
        let body = chain_reads::block_body(self.snapshot.txn(), tip.as_ref(), height.to_raw())
            .map_err(ReadFault::into_plain)?;
        Ok(match body {
            AtHeight::AboveTip => AtHeight::AboveTip,
            AtHeight::Recorded((info, block)) => AtHeight::Recorded(RecordedBlock {
                header: HeaderRecord {
                    hash: info.hash,
                    header: block.header,
                    cumulative_difficulty: info.cumulative_difficulty,
                },
                coins_generated: info.coins_generated,
                cumulative_tx_count: info.cumulative_tx_count,
                cumulative_archival_len: info.cumulative_archival_len,
            }),
        })
    }

    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, StoreError> {
        chain_reads::height_of(self.snapshot.txn(), hash).map_err(ReadFault::into_plain)
    }

    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError> {
        curve_reads::root_at(self.snapshot.txn(), height).map_err(ReadFault::into_plain)
    }

    fn tree_frontier(&self) -> Result<TreeFrontier, StoreError> {
        leaf_reads::frontier(self.snapshot.txn()).map_err(ReadFault::into_plain)
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, StoreError> {
        leaf_reads::leaf_count_at(self.snapshot.txn(), height).map_err(ReadFault::into_plain)
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, StoreError> {
        let tip = self.tip_row()?;
        leaf_reads::outputs_at(self.snapshot.txn(), tip.as_ref(), height)
            .map_err(ReadFault::into_plain)
    }

    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, StoreError> {
        let tip = self.tip_row()?;
        chain_reads::weights_below(self.snapshot.txn(), tip.as_ref(), end, at_most)
            .map_err(ReadFault::into_plain)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, StoreError> {
        tx_reads::has_transaction(self.snapshot.txn(), hash).map_err(ReadFault::into_plain)
    }

    fn total_burned(&self) -> Result<AtomicUnits, StoreError> {
        self.snapshot.total_burned()
    }

    fn long_term_effective_median_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<LongTermWeight>, StoreError> {
        let tip = self.tip_row()?;
        Ok(
            match chain_reads::info_at(self.snapshot.txn(), tip.as_ref(), height.to_raw())
                .map_err(ReadFault::into_plain)?
            {
                AtHeight::Recorded(info) => AtHeight::Recorded(info.long_term_effective_median),
                AtHeight::AboveTip => AtHeight::AboveTip,
            },
        )
    }

    /// The `total_burned` fold less the `block_burn` rows in
    /// `(height, tip]`, as [`BatchView`](super::BatchView) reads it; a fold
    /// below its rows is SI-7 on the `total_burned` cell, returned plain.
    fn burned_through(&self, height: BlockHeight) -> Result<AtHeight<AtomicUnits>, StoreError> {
        let Some((tip, _)) = self.tip_row()? else {
            return Ok(AtHeight::AboveTip);
        };
        if height.to_raw() > tip {
            return Ok(AtHeight::AboveTip);
        }
        let fold = self.snapshot.total_burned()?;
        let above = chain_reads::burned_in(self.snapshot.txn(), height.to_raw(), tip)
            .map_err(ReadFault::into_plain)?;
        match fold.checked_sub(above) {
            Some(through) => Ok(AtHeight::Recorded(through)),
            None => Err(ReadFault::Invariant(StoreInvariant::CellCorrupt {
                key: "total_burned",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "total_burned",
                    reason: "the burned fold is below the block_burn rows it sums",
                }),
            })
            .into_plain()),
        }
    }

    fn bond_record(&self, persona: &PCanonicalId) -> Result<Option<BondRecord>, StoreError> {
        archival_reads::bond_record(self.snapshot.txn(), persona).map_err(ReadFault::into_plain)
    }

    fn slash_log_after(
        &self,
        persona: &PCanonicalId,
        height: BlockHeight,
        floor: SlashLogFloor,
    ) -> Result<Vec<SlashLogEntry>, StoreError> {
        archival_reads::slash_log_after(self.snapshot.txn(), persona, height, floor)
            .map_err(ReadFault::into_plain)
    }

    fn last_served_epoch(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
    ) -> Result<Option<SettlementEpoch>, StoreError> {
        archival_reads::last_served_epoch(self.snapshot.txn(), persona, shard)
            .map_err(ReadFault::into_plain)
    }

    fn served_shards(&self, persona: &PCanonicalId) -> Result<Vec<ServedShard>, StoreError> {
        archival_reads::served_shards(self.snapshot.txn(), persona).map_err(ReadFault::into_plain)
    }

    fn pass_count(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<PassCount, StoreError> {
        archival_reads::pass_count(self.snapshot.txn(), persona, shard, epoch)
            .map_err(ReadFault::into_plain)
    }

    fn r_market(
        &self,
        shard: ShardId,
        epoch: SettlementEpoch,
        floor: EpochFloor<Pricing>,
    ) -> Result<Option<RMarket>, StoreError> {
        archival_reads::r_market(self.snapshot.txn(), shard, epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn sigma_work(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Claimable>,
    ) -> Result<Option<SigmaWorkMilli>, StoreError> {
        archival_reads::sigma_work(self.snapshot.txn(), epoch, floor).map_err(ReadFault::into_plain)
    }

    fn budget(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Claimable>,
    ) -> Result<Option<AtomicUnits>, StoreError> {
        archival_reads::budget(self.snapshot.txn(), epoch, floor).map_err(ReadFault::into_plain)
    }

    fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, StoreError> {
        self.snapshot.last_settled_slash_epoch()
    }

    fn bond_records(&self) -> Result<Vec<(PCanonicalId, BondRecord)>, StoreError> {
        archival_reads::bond_records(self.snapshot.txn()).map_err(ReadFault::into_plain)
    }

    fn slash_applied(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<bool, StoreError> {
        archival_reads::slash_applied(self.snapshot.txn(), persona, shard, epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn budget_accruing(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, StoreError> {
        archival_reads::budget_accruing(self.snapshot.txn(), epoch).map_err(ReadFault::into_plain)
    }

    fn settlement_row(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
        floor: EpochFloor<Claimable>,
    ) -> Result<Option<SettlementRow>, StoreError> {
        archival_reads::settlement_row(self.snapshot.txn(), persona, shard, epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn issued_draws(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<Vec<IndexedDraw>, StoreError> {
        archival_reads::issued_draws(self.snapshot.txn(), epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn support_issued(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<Vec<IndexedDraw>, StoreError> {
        archival_reads::support_issued(self.snapshot.txn(), epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn support_settlement(
        &self,
        persona: &PCanonicalId,
        epoch: SettlementEpoch,
        floor: EpochFloor<Claimable>,
    ) -> Result<Option<SettlementRow>, StoreError> {
        archival_reads::support_settlement(self.snapshot.txn(), persona, epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn issued_digest(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<IssuedDigest, StoreError> {
        archival_reads::issued_digest(self.snapshot.txn(), epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn served_at(
        &self,
        persona: &PCanonicalId,
        epochs: &BTreeSet<SettlementEpoch>,
        floor: EpochFloor<Claimable>,
    ) -> Result<BTreeMap<SettlementEpoch, Vec<ShardId>>, StoreError> {
        archival_reads::served_at(self.snapshot.txn(), persona, epochs, floor)
            .map_err(ReadFault::into_plain)
    }

    fn block_draws(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<BlockDraws>, StoreError> {
        archival_reads::block_draws(self.snapshot.txn(), height, floor)
            .map_err(ReadFault::into_plain)
    }

    fn support_block_count(
        &self,
        height: BlockHeight,
        floor: BlockDrawsFloor,
    ) -> Result<Option<SupportCount>, StoreError> {
        archival_reads::support_block_count(self.snapshot.txn(), height, floor)
            .map_err(ReadFault::into_plain)
    }

    fn drawable_digest(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Settling>,
    ) -> Result<Option<DrawableDigest>, StoreError> {
        archival_reads::drawable_digest(self.snapshot.txn(), epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn complete_trees(
        &self,
        epoch: SettlementEpoch,
        floor: EpochFloor<Claimable>,
    ) -> Result<Option<CompleteTreeSet>, StoreError> {
        archival_reads::complete_trees(self.snapshot.txn(), epoch, floor)
            .map_err(ReadFault::into_plain)
    }

    fn release_journal_after(
        &self,
        height: BlockHeight,
        floor: ReleaseJournalFloor,
    ) -> Result<Vec<archival_reads::ReleasedRecord>, StoreError> {
        archival_reads::release_journal_after(self.snapshot.txn(), height, floor)
            .map_err(ReadFault::into_plain)
    }

    fn slash_log_rows_after(
        &self,
        height: BlockHeight,
        floor: SlashLogFloor,
    ) -> Result<Vec<archival_reads::LoggedSlash>, StoreError> {
        archival_reads::slash_log_rows_after(self.snapshot.txn(), height, floor)
            .map_err(ReadFault::into_plain)
    }
}

#[cfg(test)]
#[path = "snapshot_view_tests.rs"]
mod snapshot_view_tests;
