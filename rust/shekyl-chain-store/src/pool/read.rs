// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pool file's read snapshot — P4 `record`, P5 `blob`, P6 `len`, P7
//! `entries` (`DRS_E1_SPOOL.md` §3.2).
//!
//! None of these classifies, orders or parses: the class filter is
//! `record(h)?.filter(|r| r.matches(cat))` at the caller (SPL-3), the fee
//! order is the pool's in-memory index rebuilt from [`entries`](PoolSnapshot::entries)
//! (SPL-9), and the bytes are the consumer's to parse. SI-16 is observed
//! here in both directions: a key with a row in exactly one table is
//! [`StoreInvariant::PoolEntryUnpaired`], named by the read that found it.

use redb::{ReadOnlyTable, ReadTransaction, ReadableTableMetadata};
use shekyl_store_codec::{Blob, Coded};
use shekyl_types::TxHash;

use crate::store::{EngineError, StoreError, StoreInvariant};

use super::schema::{PoolTxBytes, POOL_BLOB, POOL_META};
use super::write::RowPair;
use super::{undecodable_meta, PoolRecord};

/// A read snapshot of the pool file.
pub struct PoolSnapshot {
    txn: ReadTransaction,
}

impl core::fmt::Debug for PoolSnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolSnapshot").finish_non_exhaustive()
    }
}

/// One enumerated entry (P7): the hash and its record. The blob is a second
/// read the consumer asks for ([`PoolEntry::blob`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolEntry {
    /// The transaction.
    pub txid: TxHash,
    /// Its record.
    pub record: PoolRecord,
}

impl PoolEntry {
    /// The entry's transaction bytes, from the same snapshot.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if the meta row this
    /// entry came from has no blob row — the C++ `DB_ERROR("Failed to find
    /// txpool tx blob to match metadata")`, named.
    pub fn blob(&self, snapshot: &PoolSnapshot) -> Result<Vec<u8>, StoreError> {
        snapshot
            .blob(&self.txid)?
            .ok_or_else(|| StoreInvariant::PoolEntryUnpaired { txid: self.txid }.into())
    }
}

type MetaTable = ReadOnlyTable<[u8; 32], Coded<PoolRecord>>;
type BlobTable = ReadOnlyTable<[u8; 32], Blob<PoolTxBytes>>;

impl PoolSnapshot {
    pub(super) const fn new(txn: ReadTransaction) -> Self {
        Self { txn }
    }

    fn meta(&self) -> Result<MetaTable, StoreError> {
        self.txn
            .open_table(POOL_META)
            .map_err(|e| EngineError::Table(e).into())
    }

    fn blobs(&self) -> Result<BlobTable, StoreError> {
        self.txn
            .open_table(POOL_BLOB)
            .map_err(|e| EngineError::Table(e).into())
    }

    /// **P4.** The entry's record, or `None` if the pool does not hold it.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::CellCorrupt`] (SI-7) if the row does not decode.
    pub fn record(&self, txid: &TxHash) -> Result<Option<PoolRecord>, StoreError> {
        let table = self.meta()?;
        let Some(guard) = table.get(txid.to_bytes()).map_err(EngineError::Storage)? else {
            return Ok(None);
        };
        guard.value().decode().map(Some).map_err(undecodable_meta)
    }

    /// **P5.** The entry's transaction bytes, unparsed, or `None` if neither
    /// row holds `txid`.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::PoolEntryUnpaired`] (SI-16) if exactly one of the
    /// two rows holds `txid`. Engine faults otherwise.
    pub fn blob(&self, txid: &TxHash) -> Result<Option<Vec<u8>>, StoreError> {
        let key = txid.to_bytes();
        let has_meta = self
            .meta()?
            .get(key)
            .map_err(EngineError::Storage)?
            .is_some();
        let bytes = self
            .blobs()?
            .get(key)
            .map_err(EngineError::Storage)?
            .map(|guard| guard.value().bytes().to_vec());
        match RowPair::of(has_meta, bytes.is_some()) {
            RowPair::Absent => Ok(None),
            RowPair::Held => Ok(bytes),
            RowPair::Unpaired => Err(StoreInvariant::PoolEntryUnpaired { txid: *txid }.into()),
        }
    }

    /// **P6.** How many entries the pool holds. A per-class count is the
    /// caller's fold over [`entries`](Self::entries) — the C++ already
    /// scanned for it.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn len(&self) -> Result<u64, StoreError> {
        self.meta()?
            .len()
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// Whether the pool holds no entry.
    ///
    /// # Errors
    ///
    /// Engine faults only.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        self.len().map(|n| n == 0)
    }

    /// **P7.** Every entry, in key order, each with its record. The class
    /// filter and any early exit are the consumer's; the blob is
    /// [`PoolEntry::blob`], a second read on demand.
    ///
    /// # Errors
    ///
    /// Opening the table; per item, [`StoreInvariant::CellCorrupt`] for a
    /// row that does not decode.
    pub fn entries(
        &self,
    ) -> Result<impl Iterator<Item = Result<PoolEntry, StoreError>> + '_, StoreError> {
        let table = self.meta()?;
        let range = table.range::<[u8; 32]>(..).map_err(EngineError::Storage)?;
        Ok(range.map(|item| {
            let (k, v) = item.map_err(EngineError::Storage)?;
            Ok(PoolEntry {
                txid: TxHash::from_bytes(k.value()),
                record: v.value().decode().map_err(undecodable_meta)?,
            })
        }))
    }
}
