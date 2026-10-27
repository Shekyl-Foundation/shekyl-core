// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The alt-chain write surface (DRS-E1 S-ALT, `DRS_E1_SALT.md` §3.2): **AL1**
//! `insert_alt_block`, **AL2** `remove_alt_block`, **AL3** `drop_alt_blocks`,
//! the dead-row sweep `retire_alt_blocks` — on the same [`WriteBatch`] that
//! connects and pops — and the batch-side reads (AL4–AL8) a switch decides
//! against.
//!
//! Every write touches both alt tables: `alt_blocks` and
//! `alt_block_bodies` (the block's listed bodies, consensus data a switch
//! connects — [`AltBodies`]) are written and removed together, and AL8
//! holds them to each other at every read.
//!
//! # The death rule
//!
//! An alternative row at height `h` can be promoted only by a switch whose
//! fork point is at or above `h − 1`, which pops `tip − h + 1` blocks. Once
//! that exceeds the reorg cap in force, no switch reaches it: the cap is
//! checked before any pop (`E5-Q6`), and the tip only rises. So the connect
//! that advances the tip to `t` removes, in its own write, every row at or
//! below `t − cap` with its bodies ([`WriteBatch::retire_alt_blocks`]); the
//! writer also removes every row at or below the anchor floor (CEN-E2),
//! which the store does not know. The lifetime of an alt row is the cap —
//! no constant of its own.
//!
//! **A dead row takes its descendants.** A row above the line whose chain
//! runs down through a removed row has lost the only path by which it could
//! connect: an offer on top of it is `Unlinked`, and no switch can promote
//! it. So the death rule removes the closure — every row at or below the
//! line and every row descending from one of them — and a branch that
//! straddles the line leaves whole.
//!
//! # A block id has one home
//!
//! **Invariant:** a block id is in at most one of the main chain and the
//! alt table. Every connect — an `Apply` and a switch's promotion alike —
//! removes a same-id alt row, with its bodies, in its own write
//! ([`WriteBatch::connect`](super::WriteBatch::connect), after the seal);
//! AL1 refuses a hash the main chain records as [`AltCannot::AlreadyHeld`].
//! A switch's pops take a block off the main chain before its demoted row
//! goes in, so a demotion never meets its own row. The live router places
//! two copies of one block from two sessions against snapshots the other
//! copy's write can move, and the store holds the invariant for both orders
//! of arrival. So the closure below never reaches a recorded block, and the
//! listing never meets a tip the main chain holds.
//!
//! # Every stored chain reaches the main chain
//!
//! **Invariant:** every stored alternative row's chain — the row, its
//! parent if that is a stored row, and so on down — ends at a block the
//! main chain holds. A row enters only on a held parent (AL1 takes an
//! admitted verdict, and admission refuses an `Unlinked` block). It leaves
//! by promotion, which makes its descendants' parent a main-chain block; by
//! refusal ([`WriteBatch::remove_alt_branches`]), the death rule
//! ([`WriteBatch::retire_alt_blocks`]) or a rewind
//! ([`WriteBatch::retire_alt_blocks_on`]), each of which removes the
//! descendants with the row; or by a reset (AL3), which removes them all. A
//! switch's pops demote what they pop into rows, so a branch that hung from
//! a popped block hangs from a row. The reader is
//! [`ReadSnapshot::alternate_chains`](super::ReadSnapshot::alternate_chains):
//! each tip is [`AltChain::build`](super::AltChain::build), and a stored
//! chain that does not reach a recorded block comes back
//! [`AltCannot::Unlinked`](super::AltCannot::Unlinked) rather than a parent
//! the main chain does not hold. The lowest block of every chain that
//! listing returns names a main-chain block as its parent.
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
//!     batch.connect(valid, in_force)?;  // ×M from the alt chain; each
//!                                       // takes its block's own alt row
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

use crate::codec::{AltBlock, AltBodies};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{ALT_BLOCKS, ALT_BLOCK_BODIES};

use super::alt_reads::{self, key, AltEntry, AltLinks, ALT_BLOCKS_CELL, ALT_BODIES_CELL};
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

    /// The bodies table, under [`Self::alt_table`]'s rule.
    fn alt_bodies_table(
        &self,
    ) -> Result<redb::Table<'_, LmdbHashKey, Coded<AltBodies>>, StoreError> {
        assert!(
            !self.journal().is_recording(),
            "alt writes are not chain state and must not run inside a connect's recording"
        );
        self.txn()
            .open_table(ALT_BLOCK_BODIES)
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
    /// and the height, cumulative difficulty and weight the tier derived —
    /// and its listed bodies go to `alt_block_bodies` under the same key.
    /// The key is the verdict's hash (CEN-B6 over the block it stores), so
    /// there is no caller-supplied identity for the store to verify
    /// (`DRS_E5_POOL_ALT_PRUNE.md` §2.1, `AltValid → AL1`).
    ///
    /// # Errors
    ///
    /// [`AltCannot::AlreadyHeld`] if the store already holds the hash, as
    /// an alt row (CEN-K3's belt, typed) or on the main chain (a block id
    /// has one home, module docs). Read in this batch, so a connect that
    /// committed after the caller's snapshot is seen; the caller need not
    /// (and inside a batch, cannot usefully) pre-read (SAL-4). Engine
    /// faults otherwise.
    pub fn insert_alt_block(&self, admitted: AltValid<'_, AltView<'_>>) -> Result<(), StoreError> {
        let id = admitted.hash();
        if super::chain_reads::height_of(self.txn(), &id)
            .map_err(|fault| self.arm_read_fault(fault))?
            .is_some()
        {
            return Err(AltCannot::AlreadyHeld.into());
        }
        let (row, bodies) = AltBlock::admitted(admitted);
        let encoded = row.encoded();
        let bodies = bodies.encoded();
        check_row::<Coded<AltBlock>>(ALT_BLOCKS_CELL, &encoded.as_encoded())?;
        check_row::<Coded<AltBodies>>(ALT_BODIES_CELL, &bodies.as_encoded())?;
        let key = key(&id);
        let mut table = self.alt_table()?;
        if table.get(key).map_err(EngineError::Storage)?.is_some() {
            return Err(AltCannot::AlreadyHeld.into());
        }
        table
            .insert(key, encoded.as_encoded())
            .map_err(EngineError::Storage)?;
        drop(table);
        self.alt_bodies_table()?
            .insert(key, bodies.as_encoded())
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
        self.poison()
            .arm(StoreInvariant::DemotedBlockRefused { height })
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
        if self.take_alt_block(id)? {
            Ok(())
        } else {
            Err(AltCannot::NotHeld.into())
        }
    }

    /// Remove the alt block under `id`, with its bodies, if the table holds
    /// it; whether it did. The connect's half of "a block id has one home"
    /// (module docs): the block it records leaves the alt table in the same
    /// write. Its children stay: their parent is now a main-chain block.
    pub(super) fn take_alt_block(&self, id: &BlockHash) -> Result<bool, StoreError> {
        let mut table = self.alt_table()?;
        let removed = table.remove(key(id)).map_err(EngineError::Storage)?;
        let held = removed.is_some();
        drop(removed);
        drop(table);
        if held {
            self.alt_bodies_table()?
                .remove(key(id))
                .map_err(EngineError::Storage)?;
        }
        Ok(held)
    }

    /// **The death rule** (module docs): remove every alt block at or below
    /// `through`, and every alt block descending from one of them, with
    /// their bodies; returns how many. `connect` calls it with the tip less
    /// the cap in force; the writer calls it with the anchor floor.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`] for a row that does not
    /// decode; engine faults.
    pub fn retire_alt_blocks(&self, through: BlockHeight) -> Result<u64, StoreError> {
        let removed = self.remove_alt_closure(|entry| entry.block.height() <= through)?;
        Ok(u64::try_from(removed.len()).expect("fewer than 2^64 alt rows"))
    }

    /// Remove the rows `roots` names and every row descending from one of
    /// them, with their bodies. Returns the removed hashes, ascending by
    /// height, and in the alt table's key order within one height. A
    /// refused block's suffix is its descendants, and so is any other
    /// branch built on it: a chain through a refused block can never be
    /// valid.
    ///
    /// # Errors
    ///
    /// [`AltCannot::NotHeld`] if a root is not held — the caller names the
    /// rows it enumerated, so an absent one is its bookkeeping gone wrong;
    /// [`super::StoreInvariant::CellCorrupt`] for a row that does not
    /// decode; engine faults.
    pub fn remove_alt_branches(&self, roots: &[BlockHash]) -> Result<Vec<BlockHash>, StoreError> {
        for root in roots {
            if !self.has_alt_block(root)? {
                return Err(AltCannot::NotHeld.into());
            }
        }
        self.remove_alt_closure(|entry| roots.contains(&entry.id))
    }

    /// Remove every row whose parent is one of `parents` and every row
    /// descending from one of them, with their bodies; returns how many. A
    /// rewind calls it with the blocks it popped, which no longer stand on
    /// the main chain, so the branches built on them no longer reach it.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`] for a row that does not
    /// decode; engine faults.
    pub fn retire_alt_blocks_on(&self, parents: &[BlockHash]) -> Result<u64, StoreError> {
        let removed = self
            .remove_alt_closure(|entry| parents.contains(&entry.block.block().header.previous))?;
        Ok(u64::try_from(removed.len()).expect("fewer than 2^64 alt rows"))
    }

    /// Remove the rows `root` selects and every row descending from one of
    /// them (the closure under "names as its parent"), with their bodies.
    /// Returns the removed hashes ascending by height, the alt table's key
    /// order breaking a tie.
    fn remove_alt_closure(
        &self,
        root: impl Fn(&AltEntry) -> bool,
    ) -> Result<Vec<BlockHash>, StoreError> {
        let entries = self.alt_blocks()?;
        let dead = AltLinks::of(&entries).closure(
            entries
                .iter()
                .filter(|entry| root(entry))
                .map(|entry| entry.id),
        );
        let mut removed: Vec<&AltEntry> = entries
            .iter()
            .filter(|entry| dead.contains(&entry.id))
            .collect();
        removed.sort_by_key(|entry| entry.block.height());
        let removed: Vec<BlockHash> = removed.iter().map(|entry| entry.id).collect();
        for id in &removed {
            self.remove_alt_block(id)?;
        }
        Ok(removed)
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
        drop(table);
        self.alt_bodies_table()?
            .retain(|_, _| false)
            .map_err(EngineError::Storage)?;
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

    /// **AL8**, on this batch: the alt block's listed bodies, held to its
    /// row, seeing this batch's own writes.
    ///
    /// # Errors
    ///
    /// [`super::StoreInvariant::CellCorrupt`]; engine faults.
    pub fn alt_block_bodies(&self, id: &BlockHash) -> Result<Option<AltBodies>, StoreError> {
        alt_reads::alt_block_bodies(self.txn(), id).map_err(|f| self.arm_read_fault(f))
    }
}
