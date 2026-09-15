// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The keyed-table write handle: two declared write verbs (C2-R8 §7.3).
//!
//! A [`WriteBatch`](super::WriteBatch) opens keyed tables as [`KeyedTable`],
//! never as a raw `redb::Table`, so the only value-writing verbs a site can
//! reach are [`insert`](KeyedTable::insert) and [`upsert`](KeyedTable::upsert).
//! redb's own `insert` replaces silently; that verb is not exposed. A site
//! that has not chosen whether overwrite is intended does not compile, and
//! the CEN-L14 class — a second write to a key that was meant to be
//! written once — is unrepresentable rather than caught.
//!
//! Reads are the engine's: `KeyedTable` implements [`ReadableTable`], so
//! `get` / `range` / `first` / `last` / `len` see the batch's own writes
//! exactly as a raw table would.

use core::borrow::Borrow;
use core::ops::RangeBounds;

use redb::{
    AccessGuard, Key, Range, ReadableTable, ReadableTableMetadata, Table, TableStats, Value,
};

use super::error::{EngineError, StoreError, StoreInvariant};
use super::write::Poison;

/// A keyed table opened for writing inside one
/// [`WriteBatch`](super::WriteBatch).
///
/// Borrows the batch for `'txn`, so it cannot outlive the closure that
/// opened it. Writes are the two verbs below; there is no third and no
/// flag. Deletion is not a value write and is not offered here: the pop
/// path (C2-R8 Q5, register row SI-6) names its own verb and the row it
/// enforces when it lands, rather than this handle pre-provisioning one.
///
/// The redb-shaped two-argument `insert` — replace silently — is the L14
/// hazard and does not exist on this type:
///
/// ```compile_fail,E0061
/// use redb::TableDefinition;
/// use shekyl_chain_store::store::{ChainStore, StoreError};
/// const T: TableDefinition<&str, u64> = TableDefinition::new("t");
/// let store = ChainStore::create("never-opened.redb").unwrap();
/// store.write(|batch| -> Result<(), StoreError> {
///     batch.open_table(T)?.insert("k", &1)?;
///     Ok(())
/// });
/// ```
#[must_use = "a KeyedTable is a handle on the batch's transaction; dropping it writes nothing"]
pub struct KeyedTable<'txn, K: Key + 'static, V: Value + 'static> {
    inner: Table<'txn, K, V>,
    poison: &'txn Poison,
}

impl<'txn, K: Key + 'static, V: Value + 'static> KeyedTable<'txn, K, V> {
    pub(super) const fn new(inner: Table<'txn, K, V>, poison: &'txn Poison) -> Self {
        Self { inner, poison }
    }

    /// Write `key → value` where `key` must not already be present.
    ///
    /// A present key is a violation of `row` — the `SI-` register row the
    /// call site names (SI-1 for `spent_keys`, SI-3 for `txs`, SI-4 for a
    /// curve-tree root, …). The table is left untouched, this call returns
    /// the violation, and the batch is **poisoned**: its commit refuses with
    /// the same violation whether or not the closure propagates it, so
    /// nothing the batch wrote lands.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvariantViolated`]`(row)` if `key` was present;
    /// [`EngineError::Storage`] if the engine refused the lookup or the
    /// write.
    pub fn insert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
        row: StoreInvariant,
    ) -> Result<(), StoreError> {
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

impl<K: Key + 'static, V: Value + 'static> ReadableTableMetadata for KeyedTable<'_, K, V> {
    fn stats(&self) -> redb::Result<TableStats> {
        self.inner.stats()
    }

    fn len(&self) -> redb::Result<u64> {
        self.inner.len()
    }
}

impl<K: Key + 'static, V: Value + 'static> ReadableTable<K, V> for KeyedTable<'_, K, V> {
    fn get<'a>(
        &self,
        key: impl Borrow<K::SelfType<'a>>,
    ) -> redb::Result<Option<AccessGuard<'_, V>>> {
        self.inner.get(key)
    }

    fn range<'a, KR>(&self, range: impl RangeBounds<KR> + 'a) -> redb::Result<Range<'_, K, V>>
    where
        KR: Borrow<K::SelfType<'a>> + 'a,
    {
        self.inner.range(range)
    }

    fn first(&self) -> redb::Result<Option<(AccessGuard<'_, K>, AccessGuard<'_, V>)>> {
        self.inner.first()
    }

    fn last(&self) -> redb::Result<Option<(AccessGuard<'_, K>, AccessGuard<'_, V>)>> {
        self.inner.last()
    }
}
