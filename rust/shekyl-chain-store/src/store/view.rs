// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! [`BatchView`]: the validator's [`ChainView`] projected from a
//! [`WriteBatch`] (S-CHAIN-W commit 5; `DRS_E1_SCHAIN_W.md` §3.4, SCW-13).
//!
//! # Why a batch projection and not a snapshot
//!
//! A multi-block batch connects block *h* and then validates block *h+1*
//! against a chain that already contains *h*: the second block's
//! `has_key_image` must see the first block's spent keys, or a double spend
//! across two blocks of one batch would pass validation and be caught only
//! by SI-1's belt — as a *fatal*, not a verdict. redb tables opened in a
//! write transaction observe that transaction's own writes, so projecting
//! the view from the batch gives block *h+1* the chain block *h* left.
//!
//! A `ReadSnapshot`-backed view (RPC-side re-validation, DRS-E5's pool
//! decorator) is a later, separate implementor. It carries no batch brand,
//! and so cannot mint a `ChainValid` that `connect` accepts — which is the
//! point of the brand (C2-R8 Q3).
//!
//! # The root at `h` is key `h`
//!
//! [`ChainView::root_at`]`(h)` is the tree state **at** chain height `h` —
//! after the block at `h − 1` connected, before the block at `h` drained its
//! own leaves. That is the anchor CEN-I12 verifies a spend referencing `h`
//! against and the root the header at `h` must carry (CEN-B5). The daemon
//! keys exactly that state at `h`: block `h − 1`'s connect writes its
//! post-drain root as `store_curve_tree_root_at_height(prev_height + 1, …)`
//! (`src/blockchain_db/blockchain_db.cpp:664`), and so does this store's
//! `connect` (`curve_tree_roots[h + 1]` from `ConnectFacts::root_after`).
//! So this view reads key `h`, never `h + 1` — reading `h + 1` would hand a
//! rule the *next* anchor (S-CHAIN-W SCW-19). The test holds both ends.
//!
//! # Absence is classified against the tip, never mapped to a rule outcome
//!
//! `AtHeight::AboveTip` is permitted **only above the dense tip**: the
//! recorded chain has one `block_info` and one `blocks` row per height
//! `0..=tip` (SI-2) and one `curve_tree_roots` row per key `1..=tip + 1`
//! (SI-4; key 0 is never written — nothing connects *into* height 0). A
//! missing row **inside** those ranges is store corruption, and it comes
//! back as SI-7 (`CellCorrupt { fault: Absent }`) through the trait's
//! `Fault`, poisoning the batch — never as `AboveTip`, which a rule would
//! read as an ordinary "not yet" and turn into an `InvalidBlock`. The same
//! shape the LMDB reader got wrong for `curve_tree_roots[0]` (returning
//! 32 zero bytes, a *valid* encoding of the identity point) is what this
//! module makes unrepresentable: absence is a case the caller must handle,
//! not a value that reads as data.
//!
//! Height 0 has no root row in either store; its state is the empty tree,
//! [`CurveTreeRoot::EMPTY`], and that is what `root_at(0)` returns. Whether a
//! *rule* accepts a reference to genesis is CEN-I12's question (E6 slice 6),
//! not this view's.
//!
//! # Faults are faults
//!
//! Every engine or codec failure comes back as [`StoreError`] through the
//! trait's `Fault`, never as a verdict (the module docs of `view.rs` in the
//! rules crate). A typed cell that does not decode, a row missing below the
//! tip, or a block blob that does not hash to the identity `block_info`
//! records for it is SI-7 and **poisons the batch** through the same latch
//! every other read arms, so a verdict minted over a corrupt read cannot
//! commit.

use redb::ReadableTable;
use shekyl_chain_rules::{AtHeight, ChainView, RecordedBlock};
use shekyl_types::{BlockHash, BlockHeight, CurveTreeRoot, KeyImage};
use shekyl_wire::Block;

use crate::codec::{BlockInfo, Canonical, CodecError, CurveRoot};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{BLOCKS, BLOCK_INFO, CURVE_TREE_ROOTS, SPENT_KEYS};

use super::error::{CellFault, EngineError, StoreError, StoreInvariant};
use super::write::WriteBatch;

/// The recorded chain as this batch sees it — including the batch's own
/// uncommitted writes.
///
/// Minted only by [`WriteBatch::chain_view`], so the `'id` it carries is
/// the batch's brand: a `ChainValid<'id, BatchView<'_, 'id>>` can be handed
/// back to this batch's `connect` and to nothing else.
#[must_use = "a BatchView is a projection of the batch; dropping it reads nothing"]
pub struct BatchView<'b, 'id> {
    batch: &'b WriteBatch<'b, 'id>,
}

impl<'b, 'id> BatchView<'b, 'id> {
    pub(super) const fn new(batch: &'b WriteBatch<'b, 'id>) -> Self {
        Self { batch }
    }

    /// The recorded tip height as this batch sees it, `None` for an empty
    /// chain. `block_info` is dense (SI-2), so its last key is the tip.
    fn tip(&self) -> Result<Option<u64>, StoreError> {
        let table = self
            .batch
            .txn()
            .open_table(BLOCK_INFO)
            .map_err(EngineError::Table)?;
        let tip = table
            .last()
            .map_err(EngineError::Storage)?
            .map(|(height, _)| height.value());
        Ok(tip)
    }

    /// Read a typed cell of table `T` at `key`, decoding under `V`; absent
    /// is `Ok(None)`, undecodable is SI-7 and poisons the batch.
    fn cell<V: Canonical>(
        &self,
        table: redb::TableDefinition<'static, u64, &'static [u8]>,
        key: u64,
        cell_name: &'static str,
    ) -> Result<Option<V>, StoreError> {
        let table = self
            .batch
            .txn()
            .open_table(table)
            .map_err(EngineError::Table)?;
        let Some(guard) = table.get(key).map_err(EngineError::Storage)? else {
            return Ok(None);
        };
        V::decode(guard.value()).map(Some).map_err(|cause| {
            self.batch.poison().arm(StoreInvariant::CellCorrupt {
                key: cell_name,
                fault: CellFault::Undecodable(cause),
            })
        })
    }

    /// SI-7 for a row that the dense ranges say must exist and does not:
    /// poisons the batch and returns the fault.
    fn absent_below_tip(&self, cell_name: &'static str) -> StoreError {
        self.batch.poison().arm(StoreInvariant::CellCorrupt {
            key: cell_name,
            fault: CellFault::Absent,
        })
    }

    /// SI-7 for a `blocks` row that is present but not a canonical block for
    /// its height.
    fn blocks_invalid(&self, reason: &'static str) -> StoreError {
        self.batch.poison().arm(StoreInvariant::CellCorrupt {
            key: "blocks",
            fault: CellFault::Undecodable(CodecError::Invalid {
                codec: "block",
                reason,
            }),
        })
    }
}

impl<'id> ChainView<'id> for BatchView<'_, 'id> {
    type Fault = StoreError;

    /// `spent_keys` membership — the chain half of CEN-L1 / CEN-I7, read
    /// from the table SI-1 guards.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, StoreError> {
        let table = self
            .batch
            .txn()
            .open_table(SPENT_KEYS)
            .map_err(EngineError::Table)?;
        table
            .get(LmdbHashKey::from_bytes(*key_image.as_bytes()))
            .map(|found| found.is_some())
            .map_err(|e| EngineError::Storage(e).into())
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
        let h = height.to_raw();
        match self.tip()? {
            Some(tip) if h <= tip => {}
            _ => return Ok(AtHeight::AboveTip),
        }
        let info = self
            .cell::<BlockInfo>(BLOCK_INFO, h, "block_info")?
            .ok_or_else(|| self.absent_below_tip("block_info"))?;
        let table = self
            .batch
            .txn()
            .open_table(BLOCKS)
            .map_err(EngineError::Table)?;
        let blob = table
            .get(h)
            .map_err(EngineError::Storage)?
            .ok_or_else(|| self.absent_below_tip("blocks"))?;
        let block = Block::from_bytes(blob.value())
            .map_err(|_| self.blocks_invalid("block blob does not parse"))?;
        if block.hash() != info.hash.to_bytes() {
            return Err(self.blocks_invalid("block blob does not hash to block_info.hash"));
        }
        Ok(AtHeight::Recorded(RecordedBlock {
            hash: BlockHash::from_bytes(info.hash.to_bytes()),
            header: block.header,
        }))
    }

    /// `curve_tree_roots[height]` — the tree state **at** `height`, written
    /// by the connect of `height − 1` (module docs). Height 0 is the empty
    /// tree, [`CurveTreeRoot::EMPTY`]; `1..=tip + 1` must be present (SI-7
    /// otherwise); above that is [`AtHeight::AboveTip`].
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError> {
        let h = height.to_raw();
        if h == 0 {
            return Ok(AtHeight::Recorded(CurveTreeRoot::EMPTY));
        }
        match self.tip()? {
            // `tip + 1` is the state a candidate at `tip + 1` is checked
            // against — CEN-B5's read — and the last row `connect` wrote.
            Some(tip) if h <= tip.saturating_add(1) => {}
            _ => return Ok(AtHeight::AboveTip),
        }
        let root = self
            .cell::<CurveRoot>(CURVE_TREE_ROOTS, h, "curve_tree_roots")?
            .ok_or_else(|| self.absent_below_tip("curve_tree_roots"))?;
        Ok(AtHeight::Recorded(CurveTreeRoot::from_bytes(
            *root.as_bytes(),
        )))
    }
}
