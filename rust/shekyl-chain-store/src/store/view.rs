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
//!
//! # One body, two transactions
//!
//! The decode / verify / classify work is not here: it is
//! [`chain_reads`](super::chain_reads), generic over the transaction and
//! shared with the read snapshot (S-CHAIN-R, SCR-13). This type contributes
//! exactly one thing to each read — **what a fault does** ([`Self::arm`]):
//! an **invariant** fault (SI-7 — a hole below the tip, an undecodable row,
//! a blob that does not hash to its recorded identity) **arms the batch's
//! poison**, so a verdict minted over the corrupt read cannot commit; an
//! **engine** fault passes through unchanged, because it implies nothing
//! about the file and there is nothing to latch. The snapshot reader
//! differs on the first branch only (it returns the row, arming nothing —
//! the halt is the writer's state). A reader that reproduces the body
//! instead of calling it has re-created the two-readers-of-one-table drift
//! the shared module exists to prevent.
//!
//! One tightening arrived with the shared body and is deliberate: the tip
//! is read **decoded**, so an undecodable `block_info[tip]` is SI-7 on
//! every classified read, not only on a read of the tip itself
//! (`chain_reads` module docs, *The tip is one decoded read*).

use shekyl_chain_rules::{AtHeight, ChainView, RecordedBlock, Tip};
use shekyl_types::{BlockHeight, CurveTreeRoot, KeyImage};

use crate::codec::BlockInfo;

use super::chain_reads::{self, ReadFault};
use super::curve_reads;
use super::error::StoreError;
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

    /// What a fault does on this reader: an invariant violation **arms the
    /// batch's poison** (the first row wins; `complete` refuses with it on
    /// both arms), an engine failure passes through. This is the one line
    /// that distinguishes `BatchView` from a snapshot reader over the same
    /// body.
    fn arm(&self, fault: ReadFault) -> StoreError {
        match fault {
            ReadFault::Engine(e) => e.into(),
            ReadFault::Invariant(row) => self.batch.poison().arm(row),
        }
    }

    /// The recorded tip as this batch sees it — its height and decoded
    /// `block_info` row — `None` for an empty chain. The trait's `tip()`
    /// projects the rules crate's `Tip` from this; `block_at` / `root_at`
    /// classify absence against it.
    fn tip_row(&self) -> Result<Option<(u64, BlockInfo)>, StoreError> {
        chain_reads::tip_of(self.batch.txn()).map_err(|f| self.arm(f))
    }
}

impl<'id> ChainView<'id> for BatchView<'_, 'id> {
    type Fault = StoreError;

    /// `spent_keys` membership — the chain half of CEN-L1 / CEN-I7, read
    /// from the table SI-1 guards. The body is [`chain_reads::has_key_image`],
    /// shared with the read snapshot (S-OUT-KI K1); a membership read has no
    /// invariant arm to classify, so the batch's poison policy has nothing
    /// to do here and the fault passes through plain.
    fn has_key_image(&self, key_image: &KeyImage) -> Result<bool, StoreError> {
        chain_reads::has_key_image(self.batch.txn(), key_image)
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
        let body = chain_reads::block_body(self.batch.txn(), tip.as_ref(), height.to_raw())
            .map_err(|f| self.arm(f))?;
        Ok(match body {
            AtHeight::AboveTip => AtHeight::AboveTip,
            AtHeight::Recorded((info, block)) => AtHeight::Recorded(RecordedBlock {
                hash: info.hash,
                header: block.header,
                cumulative_difficulty: info.cumulative_difficulty,
            }),
        })
    }

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
        curve_reads::root_at(self.batch.txn(), height).map_err(|f| self.arm(f))
    }
}
