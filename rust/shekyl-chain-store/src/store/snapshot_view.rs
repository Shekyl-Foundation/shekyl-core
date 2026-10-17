// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The committed chain as the rules crate reads it, over a read snapshot
//! (DRS-X PR 3, `DRS_X_STORE_FLIP.md` DX-Q3): [`SnapshotView`] implements
//! [`HeaderView`] and [`ChainView`] over a [`ReadSnapshot`] with the same
//! bodies [`BatchView`](super::view::BatchView) reads a write batch
//! through (`chain_reads`, `curve_reads`, `leaf_reads`, `tx_reads`,
//! `archival_reads`), so the RPC facts derive every chain-state value —
//! the next target, the medians, the volume window, the fee operands —
//! through the rules crate's one derivation and never a second copy.
//!
//! **The one difference from `BatchView` is the fault policy.** A batch
//! arms its poison on an invariant row, because a write must not commit
//! over it; a snapshot has nothing to poison, so a row it reads broken is
//! the plain [`StoreError`] (`ReadFault::into_plain`), as every other
//! [`ReadSnapshot`] read reports it.
//!
//! **It cannot connect anything.** `validate` over this view mints a
//! `ChainValid<'id, SnapshotView>`, and `connect` takes only
//! `ChainValid<'id, BatchView<'_, 'id>>`: a verdict judged against a
//! snapshot has no batch to land in. The RPC reads it for derivations
//! and nothing else.

use std::collections::{BTreeMap, BTreeSet};

use shekyl_chain_rules::{
    AtHeight, BlockOutputs, ChainView, HeaderRecord, HeaderView, RecordedBlock, RecordedWeights,
    SlashLogFloor, Tip, TreeFrontier,
};
use shekyl_types::archival::{
    BlockDraws, DrawableDigest, IndexedDraw, IssuedDigest, PassCount, ServedShard, SettlementRow,
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

/// The committed chain as one [`ReadSnapshot`] sees it (module docs).
#[must_use = "a SnapshotView is a projection of the snapshot; dropping it reads nothing"]
pub struct SnapshotView<'v, 's> {
    snap: &'v ReadSnapshot<'s>,
}

impl<'v, 's> SnapshotView<'v, 's> {
    /// The view over `snap`. Every read is the snapshot's: one committed
    /// tip for the view's whole life.
    pub const fn new(snap: &'v ReadSnapshot<'s>) -> Self {
        Self { snap }
    }

    /// The tip row through the shared body — the one read every by-height
    /// classification here is made against, as `BatchView`'s is.
    fn tip_row(&self) -> Result<Option<(u64, BlockInfo)>, StoreError> {
        chain_reads::tip_of(self.snap.txn()).map_err(ReadFault::into_plain)
    }
}

impl<'id> HeaderView<'id> for SnapshotView<'_, '_> {
    type Fault = StoreError;

    /// `block_info.last()` through the shared read body — the same row
    /// `block_at` / `root_at` classify against, so the tip a rule reads and
    /// the tip absence is judged by are one read (SCW-13). `None` is the
    /// empty chain; an undecodable last row is SI-7 through `arm`.
    fn tip(&self) -> Result<Option<Tip>, StoreError> {
        Ok(self.tip_row()?.map(|(height, info)| Tip {
            height: BlockHeight::from_raw(height),
            hash: info.hash,
        }))
    }

    /// The header half of [`ChainView::block_at`], from the **same** read
    /// ([`chain_reads::block_body`]): the store has no header-only table —
    /// the header lives inside the `blocks` blob, which must hash to the
    /// identity `block_info` records (CEN-B6) — so a header fact costs the
    /// store exactly what the whole record does. The partition is by
    /// field, not by table (DRS-E5 `E5-13`); what the narrower return buys
    /// is the bound, not a cheaper read. Absence classifies as `block_at`
    /// does: `AboveTip` above the tip, SI-7 at or below it.
    fn header_at(&self, height: BlockHeight) -> Result<AtHeight<HeaderRecord>, StoreError> {
        Ok(match self.block_at(height)? {
            AtHeight::AboveTip => AtHeight::AboveTip,
            AtHeight::Recorded(block) => AtHeight::Recorded(block.header),
        })
    }
}

impl<'id> ChainView<'id> for SnapshotView<'_, '_> {
    /// `spent_keys` membership — the chain half of CEN-L1 / CEN-I7, read
    /// from the table SI-1 guards. The body is [`chain_reads::has_key_image`],
    /// shared with the read snapshot (S-OUT-KI K1); a membership read has no
    /// invariant arm to classify, so the batch's poison policy has nothing
    /// to do here and the fault passes through plain.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, StoreError> {
        chain_reads::has_key_image(self.snap.txn(), key_image)
            .map_err(chain_reads::ReadFault::into_plain)
    }

    /// `block_info[height]` for the identity, `blocks[height]` for the
    /// header — the header is inside the recorded blob, exactly as LMDB
    /// keeps it, so it is parsed from the bytes the rules will be persisted
    /// against, and the blob must hash to the identity `block_info` records
    /// (CEN-B6): a replaced or corrupted blob is never exposed to a rule as
    /// a `(hash, header)` pair that does not belong together.
    ///
    /// `height > tip` (or an empty chain) is [`AtHeight::AboveTip`]; a
    /// missing `block_info` or `blocks` row at or below the tip is SI-7
    /// (module docs).
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, StoreError> {
        let tip = self.tip_row()?;
        let body = chain_reads::block_body(self.snap.txn(), tip.as_ref(), height.to_raw())
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

    /// `block_heights[hash]` — CEN-I10's read. The body is
    /// [`chain_reads::height_of`], shared with `ReadSnapshot::height_of`;
    /// an undecodable row is SI-7 and is SI-7 (the snapshot's plain policy), as every
    /// classified read here does.
    fn height_of(&self, hash: &BlockHash) -> Result<Option<BlockHeight>, StoreError> {
        chain_reads::height_of(self.snap.txn(), hash).map_err(ReadFault::into_plain)
    }

    /// `curve_tree_roots[height]` — the tree state **at** `height`, written
    /// by the connect of `height − 1` (module docs). Height 0 is the empty
    /// tree, [`CurveTreeRoot::EMPTY`]; `1..=tip + 1` must be present (SI-7
    /// otherwise); above that is [`AtHeight::AboveTip`].
    ///
    /// The body is `curve_reads::root_at` — the store's public **C2** read
    /// (S-CURVE), shared with `ReadSnapshot::root_at` so the batch and the
    /// committed snapshot cannot disagree about the table's key or its
    /// absence rule; here a fault poisons the batch.
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError> {
        curve_reads::root_at(self.snap.txn(), height).map_err(ReadFault::into_plain)
    }

    /// The three DRS-E3 reads (`leaf_reads`): the frontier from the
    /// summary and the layer table, the per-height leaf count from its
    /// own table, and a recorded block's outputs assembled from the rows
    /// the connect wrote — never from a pending table (CTW-10).
    fn tree_frontier(&self) -> Result<TreeFrontier, StoreError> {
        leaf_reads::frontier(self.snap.txn()).map_err(ReadFault::into_plain)
    }

    fn leaf_count_at(&self, height: BlockHeight) -> Result<AtHeight<u64>, StoreError> {
        leaf_reads::leaf_count_at(self.snap.txn(), height).map_err(ReadFault::into_plain)
    }

    fn outputs_at(&self, height: BlockHeight) -> Result<AtHeight<BlockOutputs>, StoreError> {
        let tip = self.tip_row()?;
        leaf_reads::outputs_at(self.snap.txn(), tip.as_ref(), height).map_err(ReadFault::into_plain)
    }

    /// The two E6 slice 7 reads. The window is one range cursor over
    /// `block_info` ([`chain_reads::weights_below`], shared with
    /// `ReadSnapshot::weights_window`), classified against the same tip row
    /// every other height-keyed read here uses; a hole inside the window is
    /// SI-7 and is SI-7 (the snapshot's plain policy). Membership is `tx_indices`'s
    /// ([`tx_reads::has_transaction`], shared with the snapshot).
    fn weights_window(
        &self,
        end: BlockHeight,
        at_most: BlockCount,
    ) -> Result<AtHeight<Vec<RecordedWeights>>, StoreError> {
        let tip = self.tip_row()?;
        chain_reads::weights_below(self.snap.txn(), tip.as_ref(), end, at_most)
            .map_err(ReadFault::into_plain)
    }

    fn has_transaction(&self, hash: &TxHash) -> Result<bool, StoreError> {
        tx_reads::has_transaction(self.snap.txn(), hash).map_err(ReadFault::into_plain)
    }

    /// The E6 slice 7 wave-B read: the `total_burned` register as this
    /// batch holds it — the fold `connect` maintains under SI-8, before
    /// this block's own burn is folded in ([`WriteBatch::total_burned`],
    /// the same body the batch's other callers use). CEN-F17 nets it off
    /// the parent's accumulator; the validator, not the store, judges the
    /// pair (`Corrupt::BurnExceedsEmission` → [`WriteBatch::refuse_corrupt`]).
    ///
    /// [`WriteBatch::total_burned`]: super::write::WriteBatch::total_burned
    /// [`WriteBatch::refuse_corrupt`]: super::write::WriteBatch::refuse_corrupt
    fn total_burned(&self) -> Result<AtomicUnits, StoreError> {
        self.snap.total_burned()
    }

    /// `block_info[height].long_term_effective_median` — the row connect
    /// wrote for the block (FL-R3-STORE), through the same classified read
    /// as every other height-keyed projection here.
    fn long_term_effective_median_at(
        &self,
        height: BlockHeight,
    ) -> Result<AtHeight<LongTermWeight>, StoreError> {
        let tip = self.tip_row()?;
        Ok(
            match chain_reads::info_at(self.snap.txn(), tip.as_ref(), height.to_raw())
                .map_err(ReadFault::into_plain)?
            {
                AtHeight::Recorded(info) => AtHeight::Recorded(info.long_term_effective_median),
                AtHeight::AboveTip => AtHeight::AboveTip,
            },
        )
    }

    /// The `total_burned` fold less the `block_burn` rows in
    /// `(height, tip]` ([`chain_reads::burned_in`]): the fold as it stood
    /// after the block at `height` connected. A fold below the rows above
    /// it is a register that does not hold the sum of its rows — SI-7 on
    /// the `total_burned` cell, its reason spelled — .
    fn burned_through(&self, height: BlockHeight) -> Result<AtHeight<AtomicUnits>, StoreError> {
        let Some((tip, _)) = self.tip_row()? else {
            return Ok(AtHeight::AboveTip);
        };
        if height.to_raw() > tip {
            return Ok(AtHeight::AboveTip);
        }
        let fold = self.snap.total_burned()?;
        let above = chain_reads::burned_in(self.snap.txn(), height.to_raw(), tip)
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

    // The archival reads (DRS-E4 commit 2): the same bodies
    // `ReadSnapshot` reads the committed chain through (`archival_reads`),
    // over this batch's transaction, with a fault arming the poison. Every
    // absence rule is the body's; nothing is classified here.

    fn bond_record(&self, persona: &PCanonicalId) -> Result<Option<BondRecord>, StoreError> {
        archival_reads::bond_record(self.snap.txn(), persona).map_err(ReadFault::into_plain)
    }

    fn slash_log_after(
        &self,
        persona: &PCanonicalId,
        height: BlockHeight,
        floor: SlashLogFloor,
    ) -> Result<Vec<SlashLogEntry>, StoreError> {
        archival_reads::slash_log_after(self.snap.txn(), persona, height, floor)
            .map_err(ReadFault::into_plain)
    }

    fn last_served_epoch(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
    ) -> Result<Option<SettlementEpoch>, StoreError> {
        archival_reads::last_served_epoch(self.snap.txn(), persona, shard)
            .map_err(ReadFault::into_plain)
    }

    fn served_shards(&self, persona: &PCanonicalId) -> Result<Vec<ServedShard>, StoreError> {
        archival_reads::served_shards(self.snap.txn(), persona).map_err(ReadFault::into_plain)
    }

    fn pass_count(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<PassCount, StoreError> {
        archival_reads::pass_count(self.snap.txn(), persona, shard, epoch)
            .map_err(ReadFault::into_plain)
    }

    fn r_market(
        &self,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<RMarket>, StoreError> {
        archival_reads::r_market(self.snap.txn(), shard, epoch).map_err(ReadFault::into_plain)
    }

    fn sigma_work(&self, epoch: SettlementEpoch) -> Result<Option<SigmaWorkMilli>, StoreError> {
        archival_reads::sigma_work(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }

    fn budget(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, StoreError> {
        archival_reads::budget(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }

    /// The watermark is a property cell, read through the batch's own
    /// property read (the same body `ReadSnapshot::last_settled_slash_epoch`
    /// is), so its faults are already the batch's.
    fn last_settled_slash_epoch(&self) -> Result<Option<SettlementEpoch>, StoreError> {
        self.snap.last_settled_slash_epoch()
    }

    fn bond_records(&self) -> Result<Vec<(PCanonicalId, BondRecord)>, StoreError> {
        archival_reads::bond_records(self.snap.txn()).map_err(ReadFault::into_plain)
    }

    fn slash_applied(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<bool, StoreError> {
        archival_reads::slash_applied(self.snap.txn(), persona, shard, epoch)
            .map_err(ReadFault::into_plain)
    }

    fn budget_accruing(&self, epoch: SettlementEpoch) -> Result<Option<AtomicUnits>, StoreError> {
        archival_reads::budget_accruing(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }

    fn settlement_row(
        &self,
        persona: &PCanonicalId,
        shard: ShardId,
        epoch: SettlementEpoch,
    ) -> Result<Option<SettlementRow>, StoreError> {
        archival_reads::settlement_row(self.snap.txn(), persona, shard, epoch)
            .map_err(ReadFault::into_plain)
    }

    fn issued_draws(&self, epoch: SettlementEpoch) -> Result<Vec<IndexedDraw>, StoreError> {
        archival_reads::issued_draws(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }

    fn issued_digest(&self, epoch: SettlementEpoch) -> Result<IssuedDigest, StoreError> {
        archival_reads::issued_digest(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }

    fn served_at(
        &self,
        persona: &PCanonicalId,
        epochs: &BTreeSet<SettlementEpoch>,
    ) -> Result<BTreeMap<SettlementEpoch, Vec<ShardId>>, StoreError> {
        archival_reads::served_at(self.snap.txn(), persona, epochs).map_err(ReadFault::into_plain)
    }

    fn block_draws(&self, height: BlockHeight) -> Result<Option<BlockDraws>, StoreError> {
        archival_reads::block_draws(self.snap.txn(), height).map_err(ReadFault::into_plain)
    }

    fn drawable_digest(
        &self,
        epoch: SettlementEpoch,
    ) -> Result<Option<DrawableDigest>, StoreError> {
        archival_reads::drawable_digest(self.snap.txn(), epoch).map_err(ReadFault::into_plain)
    }
}
