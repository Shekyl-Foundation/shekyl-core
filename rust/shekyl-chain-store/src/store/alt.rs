// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The alt-chain write surface (DRS-E1 S-ALT, `DRS_E1_SALT.md` §3.2): **AL1**
//! `insert_alt_block`, **AL2** `remove_alt_block`, **AL3** `drop_alt_blocks`,
//! on the same [`WriteBatch`] that connects and pops — and the batch-side
//! reads (AL4, AL5) a switch decides against.
//!
//! # One transaction, or it is not a switch
//!
//! The C++ commits a chain switch as separately committed writes and
//! compensates for a failure with `rollback_blockchain_switching`
//! (`blockchain.cpp:1080`). Here the batch already pops repeatedly and
//! connects repeatedly (`pop.rs`, `connect.rs`), so a switch is one closure:
//!
//! ```text
//! // Judged over the pre-pop snapshot (SAL-13). The snapshot stays live
//! // through the write: the verdict is `AltValid<'_, AltView<'_>>`, branded
//! // to that view, and does not outlive it.
//! let demoted: Vec<AltValid<'_, AltView<'_>>> = each block above the split;
//! store.write(|batch| {
//!     batch.pop()?;                                           // ×N to the split
//!     batch.insert_alt_block(demoted)?;                       // ×N (CEN-K7)
//!     batch.connect(valid, facts, in_force)?;                 // ×M from the alt chain
//!     batch.remove_alt_block(&promoted)?;                     // ×M
//!     Ok(())
//! })
//! ```
//!
//! A failure anywhere aborts everything; the store never shows a
//! half-switched chain, and there is nothing to roll back (SAL-1, SAL-14).
//! Whether a demoted block re-enters through the tier, as the sketch has it
//! and as the C++ did (`handle_alternative_block` from the switch, CEN-K7),
//! or through a constructor of its own is the switch's to rule
//! (`DRS_E5_POOL_ALT_PRUNE.md` §5 a5); AL1 takes the verdict either way.
//!
//! # Not chain state, so not journaled
//!
//! Alt rows are `Excluded` from every digest (§11.2) and are **not**
//! pop-journaled: a pop must not delete an alt block that was demoted in the
//! same batch. The journal records only while a `connect` holds its
//! recording (`undo.rs`, *Recording is a property of the verb*), and these
//! writes run between connects, never inside one — the batch's own sequence
//! guarantees it, and the debug assertion below says so where it matters.
//! For the same reason the rows are written through the raw table with the
//! store's validated insertion boundary (`check_row`) rather than through a
//! journaling handle: the handle's belt on a present key is an `SI-` row
//! and poisons the batch, and a present alt key is not an invariant
//! violation — it is the caller's contract, refused as [`AltCannot`].
//! [`WriteBatch::alt_table`] asserts the recording is not live, in every
//! build: the same class of crate bug [`WriteBatch::replay_undo`] refuses
//! with `assert!`.

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_chain_rules::AltValid;
use shekyl_store_codec::{Canonical, Coded};
use shekyl_types::{BlockHash, BlockHeight};

use crate::codec::AltBlock;
use crate::lmdb_order::LmdbHashKey;
use crate::schema::ALT_BLOCKS;

use super::alt_reads::{self, key, AltEntry, ALT_BLOCKS_CELL};
use super::error::{AltCannot, EngineError, StoreError, StoreInvariant};
use super::keyed::check_row;
use super::write::WriteBatch;
use super::AltView;

impl WriteBatch<'_, '_> {
    /// Open the alt table for this batch's writes. Never while a connect's
    /// recording is live — see the module docs. `assert!`, not
    /// `debug_assert!`: a release build must not journal-skip this by
    /// accident, and [`WriteBatch::replay_undo`] guards the same way.
    fn alt_table(&self) -> Result<redb::Table<'_, LmdbHashKey, Coded<AltBlock>>, StoreError> {
        assert!(
            !self.journal().is_recording(),
            "alt writes are not chain state and must not run inside a connect's recording"
        );
        self.txn()
            .open_table(ALT_BLOCKS)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// **AL1.** Store the block the cheap tier `admitted`, under its hash.
    ///
    /// The only way a row enters `alt_blocks`: the argument is the verdict
    /// of [`alt_against`](shekyl_chain_rules::alt_against) over **this**
    /// store's stitched [`AltView`]. The verdict is branded to the view
    /// type that minted it, so a verdict from any other `AltChainView`
    /// does not unify with this argument — the same belt `connect` wears
    /// for `ChainValid`. The tier and the write stay two operations: the
    /// token is minted on a snapshot, and the snapshot stays live through
    /// the write (a later switch judges, then pops, then inserts). The row
    /// is [`AltBlock::admitted`] of the verdict — the block, its witness,
    /// and the height, cumulative difficulty and weight the tier derived.
    /// The key is the verdict's hash (CEN-B6 over the block it stores), so
    /// there is no caller-supplied identity for the store to verify
    /// (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, `AltValid → AL1`).
    ///
    /// # Errors
    ///
    /// [`AltCannot::AlreadyHeld`] if the store already holds the hash —
    /// CEN-K3's belt, typed; the caller need not (and inside a batch, cannot
    /// usefully) pre-read (SAL-4). Engine faults otherwise.
    pub fn insert_alt_block(&self, admitted: AltValid<'_, AltView<'_>>) -> Result<(), StoreError> {
        let id = admitted.hash();
        let encoded = AltBlock::admitted(admitted).encoded();
        check_row::<Coded<AltBlock>>(ALT_BLOCKS_CELL, &encoded.as_encoded())?;
        let mut table = self.alt_table()?;
        let key = key(&id);
        if table.get(key).map_err(EngineError::Storage)?.is_some() {
            return Err(AltCannot::AlreadyHeld.into());
        }
        table
            .insert(key, encoded.as_encoded())
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// **SI-27.** Halt the writer for the recorded block at `height` the
    /// cheap tier refused when a switch demoted it (the register row; the
    /// switch judges before its write, so this batch has done no chain
    /// work and the height is noted here for the halt to name). Returns
    /// the error the caller replies with; the batch commits nothing.
    pub fn refuse_demotion(&self, height: BlockHeight) -> StoreError {
        self.journal().note_height(height.to_raw());
        self.poison().arm(StoreInvariant::DemotedBlockRefused {
            height: height.to_raw(),
        })
    }

    /// **AL2.** Remove the alt block under `id`. Its witness leaves with it —
    /// the witness is a field of the row (CW-2, structural).
    ///
    /// # Errors
    ///
    /// [`AltCannot::NotHeld`] if the store does not hold `id` — the switch
    /// removes exactly the blocks it enumerated, so an absent key is its own
    /// bookkeeping gone wrong, surfaced so the batch aborts (`SAL-Q3`).
    /// Engine faults otherwise.
    pub fn remove_alt_block(&self, id: &BlockHash) -> Result<(), StoreError> {
        let mut table = self.alt_table()?;
        let removed = table.remove(key(id)).map_err(EngineError::Storage)?;
        if removed.is_none() {
            return Err(AltCannot::NotHeld.into());
        }
        Ok(())
    }

    /// **AL3.** Remove every alt block; returns how many there were. The
    /// `--keep-alt-blocks` default at init, and the reset's second half — in
    /// the caller's batch, not a transaction of its own (SAL-9).
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn drop_alt_blocks(&self) -> Result<u64, StoreError> {
        let mut table = self.alt_table()?;
        let count = table.len().map_err(EngineError::Storage)?;
        table.retain(|_, _| false).map_err(EngineError::Storage)?;
        Ok(count)
    }

    /// **AL4**, on this batch: [`super::read::ReadSnapshot::alt_block`],
    /// including this batch's own writes. A switch reads the alt chain it
    /// is about to promote through the transaction that will remove it.
    ///
    /// An invariant (undecodable row, or a block that does not hash to
    /// `id`) poisons the batch, so the switch does not commit. It does not
    /// by itself halt the writer: that latch notes a height only for
    /// connect, pop, and [`WriteBatch::chain_view`](Self::chain_view), and
    /// an alt row is not chain work.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`]; engine faults.
    pub fn alt_block(&self, id: &BlockHash) -> Result<Option<AltBlock>, StoreError> {
        alt_reads::alt_block(self.txn(), id).map_err(|f| self.arm_read_fault(f))
    }

    /// **AL5**, on this batch: whether `alt_blocks` holds `id`, seeing this
    /// batch's own writes, without decoding the row.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn has_alt_block(&self, id: &BlockHash) -> Result<bool, StoreError> {
        alt_reads::has_alt_block(self.txn(), id).map_err(|f| self.arm_read_fault(f))
    }

    /// **AL6**, on this batch: how many alt blocks, seeing this batch's own
    /// writes.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn alt_block_count(&self) -> Result<u64, StoreError> {
        alt_reads::alt_block_count(self.txn()).map_err(|f| self.arm_read_fault(f))
    }

    /// **AL7**, on this batch: every alt block, key order, seeing this
    /// batch's own writes. Each row is held to AL4's rule.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`] for a row that does not
    /// decode or whose block does not hash to its key; engine faults.
    pub fn alt_blocks(&self) -> Result<Vec<AltEntry>, StoreError> {
        alt_reads::alt_blocks(self.txn()).map_err(|f| self.arm_read_fault(f))
    }
}
