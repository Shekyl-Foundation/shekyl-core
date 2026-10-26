// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The bundle queue and the body store (`ARCHIVAL_SERVE_CREDIT_SPEC.md`
//! §7.5, `SO-D12` increment 4c).
//!
//! Two tables, one file:
//!
//! - `archival_bundle_queue[h]` — the reference of the one bundle for `h`
//!   the queue admitted, and the tip it was judged against
//!   ([`QueuedBundle`]).
//! - `archival_bundle_body[prunable_hash]` — that bundle's prunable bytes
//!   ([`QueuedBody`]).
//!
//! They are in the chain store and not the pool file because a body must
//! always have a holder, and the holders the specification names — the
//! queue, an alternative block, a main-chain block not past `D_max` — are
//! this file's. A discarded pool file would orphan the bodies it held.
//!
//! # What the store decides, and what it does not
//!
//! The store keeps the two tables to each other and to their bound. It
//! does not judge a bundle: admission is the bundle rule run against the
//! tip, by the ingest connector through this store's single writer
//! (`judge_bundles` over a `StoreBundleView` of the same batch), and only
//! an admitted bundle reaches [`WriteBatch::queue_bundle`]. After a reorg
//! the connector judges every entry again and removes the ones the rule
//! now refuses; when an entry's window closes it removes that one too.
//!
//! # SI-41: every body has a holder
//!
//! An entry and its body are written together and removed together. In
//! 4c the queue is the only holder kind that exists. An alternative block
//! and a main-chain block not past `D_max` become holders when references
//! travel (4b), and this module's check widens with them.
//!
//! - **At open**, [`WriteBatch::reconcile_bundle_queue`] drops a body no
//!   entry names and an entry whose body is gone, and returns what it
//!   dropped for the caller to log. The store does not log.
//! - **After open**, every read of the queue holds the two tables to each
//!   other, and a disagreement is SI-41: the write path never makes one,
//!   so one seen later is a store fault.
//!
//! # Not chain state, so not journaled
//!
//! As `alt_blocks` is (`store/alt.rs`): `Excluded` from every digest,
//! never pop-journaled, written between connects. A pop does not remove
//! an entry; the connector's re-check after a reorg does.

use redb::{ReadableTable, ReadableTableMetadata};
use shekyl_archival_retention::{BundleBody, BundleRef};
use shekyl_types::{BlockHash, BlockHeight};

use crate::codec::{Canonical, Coded, QueuedBody, QueuedBundle};
use crate::schema::{ARCHIVAL_BUNDLE_BODY, ARCHIVAL_BUNDLE_QUEUE};

use super::chain_reads::{undecodable, ReadFault, ReadTables};
use super::error::{BodyHolderFault, EngineError, QueueCannot, StoreError, StoreInvariant};
use super::keyed::check_row;
use super::read::ReadSnapshot;
use super::write::WriteBatch;

/// The queue table as faults name it.
const QUEUE_CELL: &str = "archival_bundle_queue";
/// The body table as faults name it.
const BODY_CELL: &str = "archival_bundle_body";

/// One queued bundle, read back whole.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueueEntry {
    /// The block the bundle is for.
    pub h: BlockHeight,
    /// The reference and the tip it was admitted against.
    pub queued: QueuedBundle,
    /// The body the reference names.
    pub body: BundleBody,
}

/// What [`WriteBatch::reconcile_bundle_queue`] dropped at open.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct QueueReconciled {
    /// Bodies no entry named, by prunable hash.
    pub bodies_without_holder: Vec<[u8; 32]>,
    /// Entries whose body was not stored, by `h`.
    pub entries_without_body: Vec<BlockHeight>,
}

impl QueueReconciled {
    /// Whether the open found the two tables in agreement.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.bodies_without_holder.is_empty() && self.entries_without_body.is_empty()
    }
}

fn queue_key(h: BlockHeight) -> u64 {
    h.to_raw()
}

/// Every entry, ascending by `h`, with the bodies held to them (SI-41).
fn queued_bundles<T: ReadTables>(txn: &T) -> Result<Vec<QueueEntry>, ReadFault> {
    let queue = txn.table(ARCHIVAL_BUNDLE_QUEUE)?;
    let bodies = txn.table(ARCHIVAL_BUNDLE_BODY)?;
    let mut out = Vec::new();
    for item in queue.range::<u64>(..)? {
        let (k, v) = item?;
        let h = BlockHeight::from_raw(k.value());
        let queued = v
            .value()
            .decode()
            .map_err(|cause| undecodable(QUEUE_CELL, cause))?;
        if queued.reference.h() != h {
            return Err(ReadFault::Invariant(StoreInvariant::BundleBodyHolder(
                BodyHolderFault::EntryNotItsHeight { h },
            )));
        }
        let Some(body) = bodies.get(*queued.reference.prunable_hash())? else {
            return Err(ReadFault::Invariant(StoreInvariant::BundleBodyHolder(
                BodyHolderFault::EntryWithoutBody { h },
            )));
        };
        let body = body
            .value()
            .decode()
            .map_err(|cause| undecodable(BODY_CELL, cause))?
            .0;
        out.push(QueueEntry { h, queued, body });
    }
    let held = out.len();
    let stored = usize::try_from(bodies.len()?).unwrap_or(usize::MAX);
    // Each entry found its own body above, and two entries cannot share
    // one: the body's witness signature covers its `h`. So more bodies
    // than entries is a body no entry names.
    if stored != held {
        return Err(ReadFault::Invariant(StoreInvariant::BundleBodyHolder(
            BodyHolderFault::BodyWithoutHolder,
        )));
    }
    Ok(out)
}

impl WriteBatch<'_, '_> {
    /// The queue table, never inside a connect's recording (module docs).
    fn queue_table(&self) -> Result<redb::Table<'_, u64, Coded<QueuedBundle>>, StoreError> {
        assert!(
            !self.journal().is_recording(),
            "the bundle queue is not chain state and must not be written inside a connect"
        );
        self.txn()
            .open_table(ARCHIVAL_BUNDLE_QUEUE)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// The body table, under [`Self::queue_table`]'s rule.
    fn body_table(&self) -> Result<redb::Table<'_, [u8; 32], Coded<QueuedBody>>, StoreError> {
        assert!(
            !self.journal().is_recording(),
            "the bundle body store is not chain state and must not be written inside a connect"
        );
        self.txn()
            .open_table(ARCHIVAL_BUNDLE_BODY)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Queue a bundle the caller admitted against the tip `(tip_height,
    /// tip_hash)` of this batch, with its body.
    ///
    /// The caller is the queue's admission: it ran the bundle rule over
    /// this batch's view and only then calls here. `capacity` is `W₂`, the
    /// bound the specification gives the queue: the window lets no more
    /// heights than that be open at once, so a full queue is a caller that
    /// did not remove a closed window first.
    ///
    /// # Errors
    ///
    /// [`QueueCannot::Held`] when the queue already holds a bundle for the
    /// reference's `h` (the first valid one wins);
    /// [`QueueCannot::BodyNotReferenced`] when the body does not hash to
    /// the reference's prunable hash; [`QueueCannot::Full`] at `capacity`;
    /// SI-41 when the tables already disagree; engine faults.
    pub fn queue_bundle(
        &self,
        reference: &BundleRef,
        body: &BundleBody,
        tip_height: BlockHeight,
        tip_hash: BlockHash,
        capacity: u64,
    ) -> Result<(), StoreError> {
        let h = reference.h();
        if body.prunable_hash() != *reference.prunable_hash() {
            return Err(QueueCannot::BodyNotReferenced { h }.into());
        }
        let entries = self.queued_bundles()?;
        if entries.iter().any(|entry| entry.h == h) {
            return Err(QueueCannot::Held { h }.into());
        }
        let held = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        if held >= capacity {
            return Err(QueueCannot::Full { capacity }.into());
        }
        let row = QueuedBundle {
            reference: reference.clone(),
            tip_height,
            tip_hash,
        }
        .encoded();
        let stored = QueuedBody(body.clone()).encoded();
        check_row::<Coded<QueuedBundle>>(QUEUE_CELL, &row.as_encoded())?;
        check_row::<Coded<QueuedBody>>(BODY_CELL, &stored.as_encoded())?;
        self.queue_table()?
            .insert(queue_key(h), row.as_encoded())
            .map_err(EngineError::Storage)?;
        self.body_table()?
            .insert(*reference.prunable_hash(), stored.as_encoded())
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// Remove the entry for `h` and its body. Whether the queue held one.
    ///
    /// # Errors
    ///
    /// SI-41 when the entry's body is not stored; engine faults.
    pub fn unqueue_bundle(&self, h: BlockHeight) -> Result<bool, StoreError> {
        let removed = self
            .queue_table()?
            .remove(queue_key(h))
            .map_err(EngineError::Storage)?
            .map(|row| row.value().decode());
        let Some(queued) = removed else {
            return Ok(false);
        };
        let queued = queued.map_err(|cause| self.arm_read_fault(undecodable(QUEUE_CELL, cause)))?;
        let body = self
            .body_table()?
            .remove(*queued.reference.prunable_hash())
            .map_err(EngineError::Storage)?
            .is_some();
        if !body {
            return Err(self.arm_if_invariant(
                StoreInvariant::BundleBodyHolder(BodyHolderFault::EntryWithoutBody { h }).into(),
            ));
        }
        Ok(true)
    }

    /// Every entry, ascending by `h`, each with its body.
    ///
    /// # Errors
    ///
    /// SI-41 when the two tables disagree, SI-7 for a row that does not
    /// decode; engine faults. Either invariant poisons this batch.
    pub fn queued_bundles(&self) -> Result<Vec<QueueEntry>, StoreError> {
        queued_bundles(self.txn()).map_err(|fault| self.arm_read_fault(fault))
    }

    /// The open's reconcile (module docs, SI-41): drop every body no entry
    /// names and every entry whose body is not stored, and say what went.
    /// A clean store drops nothing. The store opened by this binary at
    /// this layout never needs to; the reconcile is what makes that a
    /// checked fact rather than an assumption, and the caller logs a
    /// report that is not clean.
    ///
    /// # Errors
    ///
    /// SI-7 for a row that does not decode; engine faults.
    pub fn reconcile_bundle_queue(&self) -> Result<QueueReconciled, StoreError> {
        let mut report = QueueReconciled::default();
        let mut named = std::collections::BTreeSet::new();
        let mut entries = Vec::new();
        {
            let queue = self.queue_table()?;
            for item in queue.range::<u64>(..).map_err(EngineError::Storage)? {
                let (k, v) = item.map_err(EngineError::Storage)?;
                let queued = v
                    .value()
                    .decode()
                    .map_err(|cause| self.arm_read_fault(undecodable(QUEUE_CELL, cause)))?;
                entries.push((BlockHeight::from_raw(k.value()), queued));
            }
        }
        let mut bodies = self.body_table()?;
        for (h, queued) in entries {
            let hash = *queued.reference.prunable_hash();
            if bodies.get(hash).map_err(EngineError::Storage)?.is_some() {
                named.insert(hash);
            } else {
                report.entries_without_body.push(h);
            }
        }
        let mut orphans = Vec::new();
        for item in bodies.range::<[u8; 32]>(..).map_err(EngineError::Storage)? {
            let (k, _) = item.map_err(EngineError::Storage)?;
            let hash = k.value();
            if !named.contains(&hash) {
                orphans.push(hash);
            }
        }
        for hash in &orphans {
            bodies.remove(*hash).map_err(EngineError::Storage)?;
        }
        drop(bodies);
        let mut queue = self.queue_table()?;
        for h in &report.entries_without_body {
            queue.remove(queue_key(*h)).map_err(EngineError::Storage)?;
        }
        report.bodies_without_holder = orphans;
        Ok(report)
    }
}

/// The queue on a committed snapshot: the body the batch reads too.
impl ReadSnapshot<'_> {
    /// Every entry, ascending by `h`, each with its body.
    ///
    /// # Errors
    ///
    /// SI-41 when the two tables disagree, SI-7 for a row that does not
    /// decode; engine faults.
    pub fn queued_bundles(&self) -> Result<Vec<QueueEntry>, StoreError> {
        queued_bundles(self.txn()).map_err(ReadFault::into_plain)
    }
}
