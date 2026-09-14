// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! A read snapshot. Concurrent with a live [`WriteBatch`](super::WriteBatch):
//! redb's MVCC readers do not take the write-held flag.

use core::marker::PhantomData;

use redb::{
    Key, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    TableDefinition, Value,
};

use super::error::StoreError;
use super::ChainStore;

/// A read snapshot of the store.
///
/// Table access goes through this type, not a raw `ReadTransaction`, so
/// later read paths cannot grow a second way to open tables.
pub struct ReadSnapshot<'store> {
    txn: ReadTransaction,
    _store: PhantomData<&'store ChainStore>,
}

impl ReadSnapshot<'_> {
    pub(super) fn new(txn: ReadTransaction) -> Self {
        Self {
            txn,
            _store: PhantomData,
        }
    }

    /// Open a table for reading.
    ///
    /// # Errors
    ///
    /// [`StoreError::Table`] if the table does not exist or the engine refuses.
    pub fn open_table<K, V>(
        &self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyTable<K, V>, StoreError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.txn.open_table(definition).map_err(StoreError::Table)
    }

    /// Open a multimap table for reading.
    ///
    /// # Errors
    ///
    /// [`StoreError::Table`] if the table does not exist or the engine refuses.
    pub fn open_multimap_table<K, V>(
        &self,
        definition: MultimapTableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyMultimapTable<K, V>, StoreError>
    where
        K: Key + 'static,
        V: Key + 'static,
    {
        self.txn
            .open_multimap_table(definition)
            .map_err(StoreError::Table)
    }
}
