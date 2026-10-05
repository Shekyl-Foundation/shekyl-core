// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file's write batch — P1 `insert`, P2 `update`, P3 `remove`
//! (`DRS_E1_SPOOL.md` §3.2).
//!
//! A [`PoolBatch`] exists only inside a [`PoolStore::write`](super::PoolStore::write)
//! closure (SPL-16): the store constructs it, runs the closure, and commits
//! on `Ok` or aborts on `Err` — no caller holds a batch it could drop.
//!
//! What a write refuses is the type's answer, not the batch's: an
//! [`update`](PoolBatch::update) stores a candidate record only when the
//! stored relay state says it [`follows`](crate::codec::RelayState::follows), and the
//! [`RelayRefusal`](crate::codec::RelayRefusal) it returns is the [`PoolCannot`] the caller gets.

use redb::{ReadableTable, Table, WriteTransaction};
use shekyl_store_codec::{Blob, BlobKind, Canonical, Coded, Raw};
use shekyl_types::TxHash;

use crate::store::{EngineError, PoolCannot, StoreError, StoreInvariant};

use super::schema::{PoolTxBytes, POOL_BLOB, POOL_META};
use super::{undecodable_meta, PoolRecord};

/// A write batch on the pool file — handed only to a
/// [`PoolStore::write`](super::PoolStore::write) closure, never returned to
/// a caller (SPL-16).
#[must_use = "a PoolBatch is only ever handed to a `PoolStore::write` closure"]
pub struct PoolBatch {
    txn: Option<WriteTransaction>,
}

impl core::fmt::Debug for PoolBatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolBatch").finish_non_exhaustive()
    }
}

/// Whether the two rows of one key are both present, both absent, or split
/// — SI-16's three observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RowPair {
    /// Neither table holds the key.
    Absent,
    /// Both tables hold the key: an entry.
    Held,
    /// Exactly one table holds the key: a write bypassed the store.
    Unpaired,
}

impl RowPair {
    /// Classify a key's presence in the two tables.
    pub(super) const fn of(has_meta: bool, has_blob: bool) -> Self {
        match (has_meta, has_blob) {
            (false, false) => Self::Absent,
            (true, true) => Self::Held,
            (true, false) | (false, true) => Self::Unpaired,
        }
    }
}

type MetaTable<'t> = Table<'t, [u8; 32], Coded<PoolRecord>>;
type BlobTable<'t> = Table<'t, [u8; 32], Blob<PoolTxBytes>>;

impl PoolBatch {
    pub(super) const fn new(txn: WriteTransaction) -> Self {
        Self { txn: Some(txn) }
    }

    fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("a live batch holds its transaction until complete")
    }

    fn meta(&self) -> Result<MetaTable<'_>, StoreError> {
        self.txn()
            .open_table(POOL_META)
            .map_err(|e| EngineError::Table(e).into())
    }

    fn blobs(&self) -> Result<BlobTable<'_>, StoreError> {
        self.txn()
            .open_table(POOL_BLOB)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// **P1.** Insert a new entry: both rows, in this batch.
    ///
    /// # Errors
    ///
    /// [`PoolCannot::AlreadyHeld`] if the pool holds `txid` (the C++
    /// `MDB_KEYEXIST` throw, typed and non-fatal — the pool upserts by
    /// removing first); [`PoolCannot::EmptyBlob`] if `blob` is empty;
    /// [`PoolCannot::NullFcmpCache`] if the record's verification cache is
    /// the null hash; [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if
    /// `txid` has a row in one table and not the other.
    pub fn insert(
        &mut self,
        txid: TxHash,
        record: &PoolRecord,
        blob: &[u8],
    ) -> Result<(), StoreError> {
        PoolTxBytes::well_formed(blob).map_err(|_| PoolCannot::EmptyBlob)?;
        refuse_null_cache(record)?;
        let key = txid.to_bytes();
        let mut meta = self.meta()?;
        let mut blobs = self.blobs()?;
        let has_meta = meta.get(key).map_err(EngineError::Storage)?.is_some();
        let has_blob = blobs.get(key).map_err(EngineError::Storage)?.is_some();
        match RowPair::of(has_meta, has_blob) {
            RowPair::Held => return Err(PoolCannot::AlreadyHeld.into()),
            RowPair::Absent => {}
            RowPair::Unpaired => return Err(StoreInvariant::PoolEntryUnpaired { txid }.into()),
        }
        meta.insert(key, record.encoded().as_encoded())
            .map_err(EngineError::Storage)?;
        blobs
            .insert(key, Raw::<PoolTxBytes>::new(blob))
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// **P2.** Overwrite an entry's record. The blob is immutable for the
    /// entry's life; the relay state must [`follow`](crate::codec::RelayState::follows)
    /// the stored one.
    ///
    /// # Errors
    ///
    /// [`PoolCannot::NotHeld`] if the pool does not hold `txid`;
    /// [`PoolCannot::Relay`] carrying the [`RelayRefusal`] — a changed
    /// origin (§92.4, `SPL-Q9`), a phase that is not the stored one or a
    /// forward step, a re-armed responsibility;
    /// [`PoolCannot::NullFcmpCache`] if the verification cache is the null
    /// hash; [`StoreInvariant::CellCorrupt`] if the stored row does not
    /// decode.
    ///
    /// [`RelayRefusal`]: crate::codec::RelayRefusal
    pub fn update(&mut self, txid: &TxHash, record: &PoolRecord) -> Result<(), StoreError> {
        refuse_null_cache(record)?;
        let key = txid.to_bytes();
        let mut meta = self.meta()?;
        let stored = {
            let Some(guard) = meta.get(key).map_err(EngineError::Storage)? else {
                return Err(PoolCannot::NotHeld.into());
            };
            guard.value().decode().map_err(undecodable_meta)?
        };
        stored
            .relay_state
            .follows(record.relay_state)
            .map_err(PoolCannot::Relay)?;
        meta.insert(key, record.encoded().as_encoded())
            .map_err(EngineError::Storage)?;
        Ok(())
    }

    /// **P3.** Remove an entry: both rows. Idempotent — an absent entry is
    /// not an error (the C++ ignores `MDB_NOTFOUND` on each).
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn remove(&mut self, txid: &TxHash) -> Result<(), StoreError> {
        let key = txid.to_bytes();
        self.meta()?.remove(key).map_err(EngineError::Storage)?;
        self.blobs()?.remove(key).map_err(EngineError::Storage)?;
        Ok(())
    }

    /// Commit on `Ok`, abort on `Err` — the store's decision at the
    /// closure's exit, never a caller's early return (SPL-16).
    pub(super) fn complete<R, E: From<StoreError>>(
        mut self,
        outcome: Result<R, E>,
    ) -> Result<R, E> {
        let txn = self.txn.take().expect("complete runs once");
        match outcome {
            Ok(r) => {
                txn.commit()
                    .map_err(|e| StoreError::from(EngineError::Commit(e)))?;
                Ok(r)
            }
            Err(e) => {
                // Dropping the transaction aborts it.
                drop(txn);
                Err(e)
            }
        }
    }
}

/// The null verification hash is absence spelled the C++ way; the record
/// spells absence as `None` (SPL-10). Refused at the write as at decode.
fn refuse_null_cache(record: &PoolRecord) -> Result<(), StoreError> {
    if record.has_null_fcmp_cache() {
        Err(PoolCannot::NullFcmpCache.into())
    } else {
        Ok(())
    }
}
