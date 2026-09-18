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
//!
//! Both verbs **journal** themselves: while the batch is recording a pop
//! journal (`store::undo`), a successful `insert` records the key it added
//! and a successful `upsert` records the value it displaced, so `pop` can
//! reverse either without knowing which surface made the write.

use core::borrow::Borrow;
use core::ops::RangeBounds;

use redb::{
    AccessGuard, Key, Range, ReadableTable, ReadableTableMetadata, Table, TableStats, Value,
};

use crate::codec::{post_image, UndoEntry};
use crate::schema::TableOrdinal;

use super::error::{EngineError, StoreCannot, StoreError, StoreInvariant};
use super::undo::{Journal, Restorable};
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
/// only deleter in the store is the pop journal's replay (`store::undo`),
/// and S-CURVE names a journaling delete verb — with the row it enforces —
/// when the drain needs one, rather than this handle pre-provisioning it.
#[must_use = "a keyed-table handle is a loan on the batch; dropping it writes nothing"]
pub struct KeyedTable<'txn, K: Key + 'static, V: Value + 'static, W> {
    inner: Table<'txn, K, V>,
    batch: Handles<'txn>,
    write: W,
}

/// The batch state a table handle writes through: the fatal latch, the
/// pop journal, and this table's identity in the journal.
///
/// `ordinal` is `None` for a table outside the schema catalogue — a test
/// fixture. Such a table can be written while no journal is recording;
/// writing it *during* a recording is a bug in this crate (only `connect`
/// records, and it opens catalogued tables), so [`Handles::journal`]
/// panics rather than journal a row `pop` could never replay.
pub(super) struct Handles<'txn> {
    pub(super) poison: &'txn Poison,
    pub(super) journal: &'txn Journal,
    pub(super) ordinal: Option<TableOrdinal>,
    /// The table name, for the message when `ordinal` is `None` and a
    /// recording is live.
    pub(super) name: Box<str>,
}

impl Handles<'_> {
    /// The table's catalogue name, `'static` through its ordinal; a table
    /// outside the catalogue (a test fixture) is named as such.
    pub(super) fn table_name(&self) -> &'static str {
        self.ordinal
            .and_then(crate::schema::undo_target)
            .map_or("<uncatalogued table>", |t| t.name())
    }

    /// Record `entry(ordinal)` if the batch is recording.
    pub(super) fn journal(&self, entry: impl FnOnce(TableOrdinal) -> UndoEntry) {
        if !self.journal.is_recording() {
            return;
        }
        let ordinal = self.ordinal.unwrap_or_else(|| {
            panic!(
                "table `{}` is not in the schema catalogue and cannot be journaled; connect \
                 writes catalogued tables only",
                self.name
            )
        });
        self.journal.record(|| entry(ordinal));
    }

    /// `bytes` boxed, but only while the journal is recording — the copy
    /// is the price of a pop, and a non-recording batch does not pay it.
    pub(super) fn capture(&self, bytes: impl AsRef<[u8]>) -> Option<Box<[u8]>> {
        self.journal
            .is_recording()
            .then(|| Box::from(bytes.as_ref()))
    }
}

/// Insert-once keyed table: a present key is the belt bound at open.
pub type InsertTable<'txn, K, V> = KeyedTable<'txn, K, V, InsertOnce>;

/// Overwrite keyed table: a present key is replaced, and the verb says so.
pub type UpsertTable<'txn, K, V> = KeyedTable<'txn, K, V, Overwrite>;

/// One stored pair, as [`KeyedTable::first`] / [`KeyedTable::last`] return it.
pub type TablePair<'a, K, V> = (AccessGuard<'a, K>, AccessGuard<'a, V>);

impl<'txn, K: Key + Restorable + 'static, V: Restorable + 'static> InsertTable<'txn, K, V> {
    pub(super) const fn new_insert(
        inner: Table<'txn, K, V>,
        batch: Handles<'txn>,
        row: StoreInvariant,
    ) -> Self {
        Self {
            inner,
            batch,
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
    /// While the batch is recording a pop journal, a successful insert
    /// records the key so `pop` can remove it.
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
        check_row::<K>(self.batch.table_name(), key.borrow())?;
        check_row::<V>(self.batch.table_name(), value.borrow())?;
        let row = self.write.row;
        if self
            .inner
            .get(key.borrow())
            .map_err(EngineError::Storage)?
            .is_some()
        {
            return Err(self.batch.poison.arm(row));
        }
        let key_bytes = self.batch.capture(K::as_bytes(key.borrow()));
        // The post-image is what replay must find under the key to count
        // the removal as reversing *this* write (codec docs).
        let post = key_bytes
            .is_some()
            .then(|| post_image(V::as_bytes(value.borrow()).as_ref()));
        self.inner
            .insert(key, value)
            .map_err(EngineError::Storage)?;
        if let (Some(key), Some(post)) = (key_bytes, post) {
            self.batch
                .journal(|table| UndoEntry::Inserted { table, key, post });
        }
        Ok(())
    }
}

impl<'txn, K: Key + Restorable + 'static, V: Restorable + 'static> UpsertTable<'txn, K, V> {
    pub(super) const fn new_upsert(inner: Table<'txn, K, V>, batch: Handles<'txn>) -> Self {
        Self {
            inner,
            batch,
            write: Overwrite,
        }
    }

    /// Write `key → value`, replacing any present value — and say so.
    ///
    /// Returns the displaced value, if there was one. While the batch is
    /// recording a pop journal, the displaced value (or its absence) is
    /// recorded so `pop` can restore it.
    ///
    /// # Errors
    ///
    /// [`EngineError::Storage`] if the engine refused the write.
    pub fn upsert<'k, 'v>(
        &mut self,
        key: impl Borrow<K::SelfType<'k>>,
        value: impl Borrow<V::SelfType<'v>>,
    ) -> Result<Option<AccessGuard<'_, V>>, StoreError> {
        check_row::<K>(self.batch.table_name(), key.borrow())?;
        check_row::<V>(self.batch.table_name(), value.borrow())?;
        let key_bytes = self.batch.capture(K::as_bytes(key.borrow()));
        let post = key_bytes
            .is_some()
            .then(|| post_image(V::as_bytes(value.borrow()).as_ref()));
        let displaced = self
            .inner
            .insert(key, value)
            .map_err(EngineError::Storage)?;
        if let (Some(key), Some(post)) = (key_bytes, post) {
            let prior = displaced
                .as_ref()
                .map(|guard| Box::<[u8]>::from(V::as_bytes(&guard.value()).as_ref()));
            self.batch.journal(|table| UndoEntry::Replaced {
                table,
                key,
                prior,
                post,
            });
        }
        Ok(displaced)
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

/// The fallible insertion boundary for every value (and key) shape.
///
/// `redb::Value::from_bytes` is a public trait method, so an `Encoded<V>`
/// (or a `Raw<K>`, or a key) can be constructed over arbitrary bytes.
/// `Canonical::encoded` cannot produce a row that does not decode; the
/// engine's `LeafBuilder::append` **asserts** a fixed width and panics.
/// Every write through this crate's handles therefore checks here first:
///
/// - a declared `fixed_width` that the bytes miss is [`StoreCannot::RowWidth`];
/// - any other `Restorable::well_formed` refusal (a variable-width codec
///   that does not decode, a `BlobKind` that does not parse) is
///   [`StoreCannot::RowIllFormed`].
///
/// The file is not touched. SI-7 remains the read of a row that reached
/// the file around this boundary (a raw-engine plant, a damaged page).
pub(super) fn check_row<V: Restorable>(
    table: &'static str,
    value: &V::SelfType<'_>,
) -> Result<(), StoreError> {
    let bytes = V::as_bytes(value);
    let bytes = bytes.as_ref();
    if let Some(expected) = V::fixed_width() {
        if bytes.len() != expected {
            return Err(StoreCannot::RowWidth {
                table,
                expected,
                actual: bytes.len(),
            }
            .into());
        }
    }
    V::well_formed(bytes).map_err(|reason| StoreCannot::RowIllFormed { table, reason }.into())
}
