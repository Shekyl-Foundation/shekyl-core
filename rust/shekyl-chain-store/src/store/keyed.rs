// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! Keyed-table write handles: one verb per handle (C2-R8 §7.3).
//!
//! A [`WriteBatch`](super::WriteBatch) opens a keyed table as either an
//! [`InsertTable`] (fatal on a present key; the `SI-` belt is bound at
//! open) or an [`UpsertTable`] (overwrite, declared). redb admits one
//! handle per table per transaction, so the verb is chosen when the table
//! is opened — not per call, and not as a flag on a common type. A
//! hard-fork that reclassifies a table from a set to a register opens the
//! other handle; the wrong verb does not compile.
//!
//! redb's own `insert` replaces silently and is not reachable. Reads are
//! inherent methods returning [`StoreError`]; the engine's `ReadableTable`
//! is not implemented, so a write closure can `?` a lookup.

use core::borrow::Borrow;
use core::ops::RangeBounds;

use redb::{
    AccessGuard, Key, Range, ReadableTable, ReadableTableMetadata, Table, TableStats, Value,
};

use super::error::{EngineError, StoreError, StoreInvariant};
use super::write::Poison;

/// This handle's value writes are insert-once, enforcing `row`.
pub struct InsertOnce {
    row: StoreInvariant,
}

/// This handle's value writes are declared overwrite.
pub struct Overwrite;

/// A keyed table opened for writing inside one
/// [`WriteBatch`](super::WriteBatch).
///
/// `W` is the write verb: [`InsertOnce`] or [`Overwrite`]. Reads are on
/// both. Call sites name the aliases [`InsertTable`] and [`UpsertTable`].
///
/// Borrows the batch for `'txn`, so it cannot outlive the closure that
/// opened it. Deletion is not a value write and is not offered here: the
/// pop path (C2-R8 Q5, register row SI-6) names its own verb and the row
/// it enforces when it lands, rather than this handle pre-provisioning one.
#[must_use = "a keyed-table handle is a loan on the batch; dropping it writes nothing"]
pub struct KeyedTable<'txn, K: Key + 'static, V: Value + 'static, W> {
    inner: Table<'txn, K, V>,
    poison: &'txn Poison,
    write: W,
}

/// Insert-once keyed table: a present key is the belt bound at open.
pub type InsertTable<'txn, K, V> = KeyedTable<'txn, K, V, InsertOnce>;

/// Overwrite keyed table: a present key is replaced, and the verb says so.
pub type UpsertTable<'txn, K, V> = KeyedTable<'txn, K, V, Overwrite>;

/// One stored pair, as [`KeyedTable::first`] / [`KeyedTable::last`] return it.
pub type TablePair<'a, K, V> = (AccessGuard<'a, K>, AccessGuard<'a, V>);

impl<'txn, K: Key + 'static, V: Value + 'static> InsertTable<'txn, K, V> {
    pub(super) const fn new_insert(
        inner: Table<'txn, K, V>,
        poison: &'txn Poison,
        row: StoreInvariant,
    ) -> Self {
        Self {
            inner,
            poison,
            write: InsertOnce { row },
        }
    }

    /// Write `key → value` where `key` must not already be present.
    ///
    /// A present key is a violation of the `SI-` row this handle was
    /// opened with (SI-1 for `spent_keys`, SI-3 for `tx_indices`, SI-4 for
    /// a curve-tree root, …). The table is left untouched, this call
    /// returns the violation, and the batch is **poisoned**: finishing
    /// the batch refuses with the same violation whether or not the
    /// closure propagates it, so nothing the batch wrote lands.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvariantViolated`] for the bound row if `key` was
    /// present; [`EngineError::Storage`] if the engine refused the lookup
    /// or the write.
    pub fn insert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
    ) -> Result<(), StoreError> {
        let row = self.write.row;
        if self
            .inner
            .get(key.borrow())
            .map_err(EngineError::Storage)?
            .is_some()
        {
            return Err(self.poison.arm(row));
        }
        self.inner
            .insert(key, value)
            .map(drop)
            .map_err(|e| EngineError::Storage(e).into())
    }
}

impl<'txn, K: Key + 'static, V: Value + 'static> UpsertTable<'txn, K, V> {
    pub(super) const fn new_upsert(inner: Table<'txn, K, V>, poison: &'txn Poison) -> Self {
        Self {
            inner,
            poison,
            write: Overwrite,
        }
    }

    /// Write `key → value`, replacing any present value — and say so.
    ///
    /// Returns the displaced value, if there was one.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the write.
    pub fn upsert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
    ) -> Result<Option<AccessGuard<'_, V>>, StoreError> {
        self.inner
            .insert(key, value)
            .map_err(|e| EngineError::Storage(e).into())
    }
}

impl<K: Key + 'static, V: Value + 'static, W> KeyedTable<'_, K, V, W> {
    /// Look up `key` as of this batch's writes.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn get<'a>(
        &self,
        key: impl Borrow<K::SelfType<'a>>,
    ) -> Result<Option<AccessGuard<'_, V>>, StoreError> {
        self.inner
            .get(key)
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// Iterate `range` as of this batch's writes.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn range<'a, KR>(
        &self,
        range: impl RangeBounds<KR> + 'a,
    ) -> Result<Range<'_, K, V>, StoreError>
    where
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        self.inner
            .range(range)
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// The first key/value pair, if any.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn first(&self) -> Result<Option<TablePair<'_, K, V>>, StoreError> {
        self.inner
            .first()
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// The last key/value pair, if any.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn last(&self) -> Result<Option<TablePair<'_, K, V>>, StoreError> {
        self.inner
            .last()
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// Number of stored key/value pairs.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn len(&self) -> Result<u64, StoreError> {
        self.inner.len().map_err(|e| EngineError::Storage(e).into())
    }

    /// Whether the table has no stored pairs.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// Engine table stats.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn stats(&self) -> Result<TableStats, StoreError> {
        self.inner
            .stats()
            .map_err(|e| EngineError::Storage(e).into())
    }
}
