// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The multimap write handle: a set of members per key.
//!
//! A multimap has no value to overwrite, so there is no verb to declare
//! (C2-R8 §7.3 is about keyed tables); `insert` either adds a member or
//! finds it already there, and says which. What the handle adds over the
//! raw engine table is the same as [`KeyedTable`](super::KeyedTable)'s:
//! errors are [`StoreError`], and a member that was *added* is journaled
//! while the batch is recording a pop journal, so `pop` can remove exactly
//! that member. A member that was already present is not journaled —
//! undoing the insert must leave it in place.

use core::borrow::Borrow;

use redb::{Key, MultimapTable, MultimapValue, ReadableMultimapTable, ReadableTableMetadata};

use crate::codec::UndoEntry;

use super::error::{EngineError, StoreError};
use super::keyed::Handles;

/// A multimap table opened for writing inside one
/// [`WriteBatch`](super::WriteBatch).
#[must_use = "a multimap handle is a loan on the batch; dropping it writes nothing"]
pub struct SetTable<'txn, K: Key + 'static, V: Key + 'static> {
    inner: MultimapTable<'txn, K, V>,
    batch: Handles<'txn>,
}

impl<'txn, K: Key + 'static, V: Key + 'static> SetTable<'txn, K, V> {
    pub(super) const fn new(inner: MultimapTable<'txn, K, V>, batch: Handles<'txn>) -> Self {
        Self { inner, batch }
    }

    /// Add `value` to the members of `key`.
    ///
    /// Returns `true` if the member was added, `false` if it was already
    /// present (and nothing changed). Only an added member is journaled.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the write.
    pub fn insert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
    ) -> Result<bool, StoreError> {
        super::keyed::check_width::<V>(self.batch.table_name(), value.borrow())?;
        let captured = self
            .batch
            .capture(K::as_bytes(key.borrow()))
            .zip(self.batch.capture(V::as_bytes(value.borrow())));
        let already_present = self
            .inner
            .insert(key, value)
            .map_err(EngineError::Storage)?;
        if already_present {
            return Ok(false);
        }
        if let Some((key, value)) = captured {
            self.batch
                .journal(|table| UndoEntry::MultiInserted { table, key, value });
        }
        Ok(true)
    }

    /// The members of `key`, as of this batch's writes.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the read.
    pub fn get<'a>(
        &self,
        key: impl Borrow<K::SelfType<'a>>,
    ) -> Result<MultimapValue<'_, V>, StoreError> {
        self.inner
            .get(key)
            .map_err(|e| EngineError::Storage(e).into())
    }

    /// Number of stored `(key, member)` pairs.
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
}
