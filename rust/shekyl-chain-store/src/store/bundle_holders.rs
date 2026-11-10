// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Who holds a stored bundle body (SI-41; `ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.5; `SO-D12` 4b, C3).
//!
//! A body in `archival_bundle_body` has a holder, and the specification
//! names three:
//!
//! - **the queue**: an `archival_bundle_queue` entry whose reference names
//!   it;
//! - **a main-chain block not past the pop horizon**: a block whose stored
//!   section (`archival_bundle_references`) names it, while the block is
//!   still within this store's undo retention, `D_max` in production. A
//!   pop of that block returns the bundle to the queue, so the body has to
//!   be here when the pop runs; and a peer's 2016 for a recent block is
//!   answered from it;
//! - **an alternative block**: an `alt_blocks` row whose section names it,
//!   until a switch connects the block or the branch is removed.
//!
//! The holders are **derived from those rows**, not recorded beside the
//! body. The section row is chain state — `connect` writes it and `pop`
//! undoes it — while the queue and the body store are not journaled, so a
//! holder set stored in the body row would be unjournaled state that a
//! journaled operation has to keep in step by hand. Deriving it keeps one
//! source of truth: [`WriteBatch::bundle_held`] is the one definition of
//! held, and every path that can leave a body without a holder asks it.
//!
//! # The transitions
//!
//! - **connect** of a block admitting a bundle: the body is stored, and the
//!   queue entry for its `h` leaves ([`WriteBatch::hold_section`]). An
//!   entry the block did not admit — another valid bundle for the same
//!   `h` — leaves too, and its body goes unless something else holds it.
//! - **pop** of that block: each bundle returns to the queue, against the
//!   tip the pop leaves ([`WriteBatch::return_section`]). It was admitted
//!   against that chain, so it is not judged again here; the queue's
//!   upkeep re-judges an entry whose tip leaves the chain.
//! - **the horizon**: at each connect, the block that has just passed the
//!   undo retention gives up its bodies ([`WriteBatch::sweep_section`]).
//!   A pop can no longer reach it.
//! - **an alternative block's removal** and **a queue entry's departure**
//!   drop the bodies they alone held ([`WriteBatch::drop_unheld`]).
//!
//! None of these writes is inside a connect's recording: the queue and the
//! body store are not chain state (`bundle_queue.rs`).

use std::collections::BTreeSet;

use shekyl_archival_retention::{BundleBody, BundleRef};
use shekyl_chain_rules::{Admitted, AtHeight};
use shekyl_types::{BlockHash, BlockHeight};

use crate::codec::{Canonical, QueuedBody, QueuedBundle};

use super::archival_reads;
use super::bundle_queue::{BODY_CELL, QUEUE_CELL};
use super::chain_reads::undecodable;
use super::error::{EngineError, StoreError};
use super::keyed::check_row;
use super::write::WriteBatch;
use redb::ReadableTable;

/// The prunable hash a stored section's reference names. The section was
/// admitted, so each reference parses; one that does not is a row no
/// writer stores.
fn named_hash(bytes: &[u8]) -> Option<[u8; 32]> {
    BundleRef::decode(bytes)
        .ok()
        .map(|reference| *reference.prunable_hash())
}

impl WriteBatch<'_, '_> {
    /// Whether anything holds the body stored under `hash`, for the bundle
    /// of block `h` (the module's three holders).
    ///
    /// The main-chain holder is looked for in the blocks above `h` and
    /// within the undo retention of the tip: a bundle is admitted only by a
    /// block above its own `h`.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub(super) fn bundle_held(&self, h: BlockHeight, hash: &[u8; 32]) -> Result<bool, StoreError> {
        if let Some(queued) = self.queue_row(h)? {
            if queued.reference.prunable_hash() == hash {
                return Ok(true);
            }
        }
        if let Some(tip) = self.tip_height()? {
            let floor = self.holder_floor(tip);
            let mut at = h.max(floor).to_raw().saturating_add(1);
            while at <= tip.to_raw() {
                if self.section_names(BlockHeight::from_raw(at), hash)? {
                    return Ok(true);
                }
                at += 1;
            }
        }
        for entry in self.alt_blocks()? {
            if let Some(section) = entry.block.bundle_references() {
                if section
                    .as_slice()
                    .iter()
                    .any(|bytes| named_hash(bytes).as_ref() == Some(hash))
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Remove each body in `candidates` — `(h, prunable hash)` — that
    /// [`Self::bundle_held`] says nothing holds.
    ///
    /// # Errors
    ///
    /// As [`Self::bundle_held`].
    pub(super) fn drop_unheld(
        &self,
        candidates: &[(BlockHeight, [u8; 32])],
    ) -> Result<(), StoreError> {
        for (h, hash) in candidates {
            if !self.bundle_held(*h, hash)? {
                self.body_table()?
                    .remove(*hash)
                    .map_err(EngineError::Storage)?;
            }
        }
        Ok(())
    }

    /// Connect, after the seal: the block now holds the bodies of the
    /// bundles it admitted, and each admitted `h` leaves the queue. A queue
    /// entry for an admitted `h` that names another body — a second valid
    /// bundle for the same block — leaves too, with its body unless
    /// something else holds it.
    ///
    /// `admitted` and `bodies` are the verdict's, in section order.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub(super) fn hold_section(
        &self,
        admitted: &[Admitted],
        bodies: &[BundleBody],
    ) -> Result<(), StoreError> {
        let mut released = Vec::new();
        for (bundle, body) in admitted.iter().zip(bodies) {
            let hash = body.prunable_hash();
            let stored = QueuedBody(body.clone()).encoded();
            check_row::<crate::codec::Coded<QueuedBody>>(BODY_CELL, &stored.as_encoded())?;
            self.body_table()?
                .insert(hash, stored.as_encoded())
                .map_err(EngineError::Storage)?;
            let h = bundle.kept.h;
            if let Some(queued) = self.take_queue_row(h)? {
                let queued_hash = *queued.reference.prunable_hash();
                if queued_hash != hash {
                    released.push((h, queued_hash));
                }
            }
        }
        self.drop_unheld(&released)
    }

    /// Pop, after the undo: return each bundle the popped block admitted
    /// to the queue, judged against `(tip_height, tip_hash)`, the tip the
    /// pop leaves. It was admitted against that chain, so it is not judged
    /// again here; the queue's upkeep re-judges an entry whose tip leaves
    /// the chain.
    ///
    /// The body is the one the block held, still stored while the block
    /// was within the undo retention. A rewind deeper than the retention
    /// reaches a block whose bodies the horizon already released: that
    /// bundle is not returned. Its window had closed against every tip
    /// since its block passed the horizon, and a peer can offer it again.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub(super) fn return_section(
        &self,
        references: &[BundleRef],
        tip_height: BlockHeight,
        tip_hash: BlockHash,
    ) -> Result<(), StoreError> {
        for reference in references {
            let present = self
                .body_table()?
                .get(*reference.prunable_hash())
                .map_err(EngineError::Storage)?
                .is_some();
            if !present {
                continue;
            }
            let row = QueuedBundle {
                reference: reference.clone(),
                tip_height,
                tip_hash,
            }
            .encoded();
            check_row::<crate::codec::Coded<QueuedBundle>>(QUEUE_CELL, &row.as_encoded())?;
            self.queue_table()?
                .insert(reference.h().to_raw(), row.as_encoded())
                .map_err(EngineError::Storage)?;
        }
        Ok(())
    }

    /// Connect, after the seal: the block that has just passed the undo
    /// retention of `tip` gives up the bodies its section names, unless the
    /// queue or an alternative block still holds one.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub(super) fn sweep_section(&self, tip: BlockHeight) -> Result<(), StoreError> {
        let retention = self.horizons().undo_retention();
        let Some(passed) = tip.checked_sub_count(retention) else {
            return Ok(());
        };
        let AtHeight::Recorded(Some(section)) =
            archival_reads::bundle_references_at(self.txn(), passed)
                .map_err(|fault| self.arm_read_fault(fault))?
        else {
            return Ok(());
        };
        let mut candidates = Vec::with_capacity(section.as_slice().len());
        for bytes in section.as_slice() {
            let Ok(reference) = BundleRef::decode(bytes) else {
                return Err(self.arm_read_fault(undecodable(
                    "archival_bundle_references",
                    shekyl_store_codec::CodecError::Invalid {
                        codec: "bundle_reference",
                        reason: "an admitted section's reference does not parse",
                    },
                )));
            };
            candidates.push((reference.h(), *reference.prunable_hash()));
        }
        self.drop_unheld(&candidates)
    }

    /// The bodies the store holds: every stored prunable hash, and the
    /// `h` each is for when a holder names it. A body no holder names has
    /// no `h` here.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub(super) fn named_bodies(&self) -> Result<BTreeSet<[u8; 32]>, StoreError> {
        let mut named = BTreeSet::new();
        for (_, queued) in self.queue_rows()? {
            named.insert(*queued.reference.prunable_hash());
        }
        if let Some(tip) = self.tip_height()? {
            let mut at = self.holder_floor(tip).to_raw().saturating_add(1);
            while at <= tip.to_raw() {
                if let AtHeight::Recorded(Some(section)) =
                    archival_reads::bundle_references_at(self.txn(), BlockHeight::from_raw(at))
                        .map_err(|fault| self.arm_read_fault(fault))?
                {
                    named.extend(
                        section
                            .as_slice()
                            .iter()
                            .filter_map(|bytes| named_hash(bytes)),
                    );
                }
                at += 1;
            }
        }
        for entry in self.alt_blocks()? {
            if let Some(section) = entry.block.bundle_references() {
                named.extend(
                    section
                        .as_slice()
                        .iter()
                        .filter_map(|bytes| named_hash(bytes)),
                );
            }
        }
        Ok(named)
    }

    /// The highest height a main-chain holder cannot be at: blocks above it
    /// are within the undo retention of `tip`.
    fn holder_floor(&self, tip: BlockHeight) -> BlockHeight {
        let retention = self.horizons().undo_retention();
        tip.checked_sub_count(retention)
            .unwrap_or(BlockHeight::ZERO)
    }

    /// Whether the section stored at `height` names `hash`.
    fn section_names(&self, height: BlockHeight, hash: &[u8; 32]) -> Result<bool, StoreError> {
        Ok(
            match archival_reads::bundle_references_at(self.txn(), height)
                .map_err(|fault| self.arm_read_fault(fault))?
            {
                AtHeight::Recorded(Some(section)) => section
                    .as_slice()
                    .iter()
                    .any(|bytes| named_hash(bytes).as_ref() == Some(hash)),
                AtHeight::Recorded(None) | AtHeight::AboveTip => false,
            },
        )
    }

    /// The references the block at `tip` admitted, opened, before a pop
    /// undoes its row. Empty when it admitted none.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode or a reference that does not
    /// parse (an admitted section's always does); engine faults.
    pub(super) fn popped_section(&self, tip: u64) -> Result<Vec<BundleRef>, StoreError> {
        let AtHeight::Recorded(Some(section)) =
            archival_reads::bundle_references_at(self.txn(), BlockHeight::from_raw(tip))
                .map_err(|fault| self.arm_read_fault(fault))?
        else {
            return Ok(Vec::new());
        };
        let mut refs = Vec::with_capacity(section.as_slice().len());
        for bytes in section.as_slice() {
            let Ok(reference) = BundleRef::decode(bytes) else {
                return Err(self.arm_read_fault(undecodable(
                    "archival_bundle_references",
                    shekyl_store_codec::CodecError::Invalid {
                        codec: "bundle_reference",
                        reason: "an admitted section's reference does not parse",
                    },
                )));
            };
            refs.push(reference);
        }
        Ok(refs)
    }

    /// The height and hash of the block below `tip`, which a pop of `tip`
    /// leaves as the tip. A popped tip above genesis has one.
    ///
    /// # Errors
    ///
    /// SI-7 when the row is missing or does not decode; engine faults.
    pub(super) fn parent_of(&self, tip: u64) -> Result<(BlockHeight, BlockHash), StoreError> {
        let parent = BlockHeight::from_raw(tip.saturating_sub(1));
        let view = super::view::BatchView::new(self);
        match shekyl_chain_rules::HeaderView::header_at(&view, parent)? {
            AtHeight::Recorded(header) => Ok((parent, header.hash)),
            AtHeight::AboveTip => {
                Err(self.arm_if_invariant(super::error::StoreInvariant::TipMismatch.into()))
            }
        }
    }

    /// The recorded tip's height, or `None` on an empty chain.
    fn tip_height(&self) -> Result<Option<BlockHeight>, StoreError> {
        Ok(super::chain_reads::tip_of(self.txn())
            .map_err(|fault| self.arm_read_fault(fault))?
            .map(|(tip, _)| BlockHeight::from_raw(tip)))
    }
}
