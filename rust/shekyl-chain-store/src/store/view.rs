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
//! # The off-by-one is the contract
//!
//! [`ChainView::root_at`]`(h)` is documented as the root **after** the
//! block at `h`. LMDB keys that root at `h + 1`
//! (`store_curve_tree_root_at_height(prev_height + 1, …)`,
//! `blockchain_db.cpp:664`), and so does the redb table. This module is the
//! one place the two numberings meet; the test holds both ends.
//!
//! # Faults are faults
//!
//! Every engine or codec failure comes back as [`StoreError`] through the
//! trait's `Fault`, never as a verdict (the module docs of `view.rs` in the
//! rules crate). A typed cell that does not decode is SI-7 and **poisons
//! the batch** through the same latch every other read arms, so a verdict
//! minted over a corrupt read cannot commit.

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
    /// against. Absent `block_info` is [`AtHeight::AboveTip`]; a present
    /// `block_info` with no `blocks` row is SI-7 (the two are written by one
    /// connect and are dense together).
    fn block_at(&self, height: BlockHeight) -> Result<AtHeight<RecordedBlock>, StoreError> {
        let h = height.to_raw();
        let Some(info) = self.cell::<BlockInfo>(BLOCK_INFO, h, "block_info")? else {
            return Ok(AtHeight::AboveTip);
        };
        let table = self
            .batch
            .txn()
            .open_table(BLOCKS)
            .map_err(EngineError::Table)?;
        let corrupt = |reason: &'static str| {
            self.batch.poison().arm(StoreInvariant::CellCorrupt {
                key: "blocks",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "block",
                    reason,
                }),
            })
        };
        let Some(blob) = table.get(h).map_err(EngineError::Storage)? else {
            return Err(corrupt(
                "block_info is recorded at this height but blocks is not",
            ));
        };
        let block =
            Block::from_bytes(blob.value()).map_err(|_| corrupt("block blob does not parse"))?;
        Ok(AtHeight::Recorded(RecordedBlock {
            hash: BlockHash::from_bytes(info.hash.to_bytes()),
            header: block.header,
        }))
    }

    /// `curve_tree_roots[height + 1]` — the root **after** the block at
    /// `height`, under LMDB's `h + 1` keying (module docs).
    fn root_at(&self, height: BlockHeight) -> Result<AtHeight<CurveTreeRoot>, StoreError> {
        let Some(after) = height.to_raw().checked_add(1) else {
            return Ok(AtHeight::AboveTip);
        };
        Ok(
            match self.cell::<CurveRoot>(CURVE_TREE_ROOTS, after, "curve_tree_roots")? {
                Some(root) => AtHeight::Recorded(CurveTreeRoot::from_bytes(*root.as_bytes())),
                None => AtHeight::AboveTip,
            },
        )
    }
}
