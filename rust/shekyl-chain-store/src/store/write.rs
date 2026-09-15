// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The write handle that discharges DRS-W3, branded per batch (C2-R8 Q3).
//!
//! Table modules take [`WriteBatch`], never a raw transaction. Opening a
//! table consults [`ApplyPolicy`](crate::apply_policy::ApplyPolicy) by name
//! so a stubbed family's apply cannot run — and cannot create the table
//! by opening it.
//!
//! A stubbed batch also **taints the file** when it commits: the
//! provenance cell is widened inside the batch's own transaction (see
//! [`commit`](WriteBatch::commit)), so the record that rows were written
//! under a stub lands with those rows or not at all. An aborted stubbed
//! batch leaves no trace, which is correct — it wrote nothing.
//!
//! # The brand
//!
//! `WriteBatch<'store, 'id>` carries an **invariant** lifetime `'id` that
//! no two batches share. It is minted only by
//! [`ChainStore::write`](super::ChainStore::write), whose closure is
//! higher-ranked over `'id`, so `'id` names *this call's* batch and nothing
//! outside the closure can be typed with it. Any type that borrows the
//! brand — the `ChainView<'id>` a validator reads, the `ChainValid<'id>` it
//! mints (DRS-E6) — can therefore only be consumed by the batch it came
//! from: handing one to another batch is a type error, not a runtime check.
//! `PhantomData<fn(&'id ()) -> &'id ()>` is what makes the parameter
//! invariant; a covariant brand would let two batches' regions coerce to a
//! common shorter one and the cross-handoff would type-check (the ruling's
//! rejected plain-lifetime shape).

use core::marker::PhantomData;

use redb::{
    Key, MultimapTable, MultimapTableDefinition, MultimapTableHandle, Table, TableDefinition,
    TableHandle, Value, WriteTransaction,
};

use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{ChainState, PropertyCell};
use crate::provenance::Provenance;
use crate::schema::PROPERTIES;

use super::error::StoreError;
use super::header;
use super::shared::Shared;

/// An open write transaction, branded with the lifetime `'id` of the
/// [`write`](super::ChainStore::write) call that opened it.
///
/// It cannot be default-constructed, cloned, or observed in a null state,
/// and it never leaves the closure it was handed to: the closure sees
/// `&mut WriteBatch`, and `'id` is bound inside the closure's own type, so
/// neither the batch nor anything carrying its brand can escape. The
/// closure returning `Ok` commits; returning `Err` — or unwinding — drops
/// the batch, and dropping **aborts** (redb rolls back on drop). That is
/// the DRS-W8 direction, where a C++ throw left the write transaction live
/// and poisoned every later block write.
///
/// Dropping also releases the store's write-held flag, so a later
/// [`write`](super::ChainStore::write) can proceed.
#[must_use = "a WriteBatch is only ever handed to a `ChainStore::write` closure"]
pub struct WriteBatch<'store, 'id> {
    txn: Option<WriteTransaction>,
    apply_policy: ApplyPolicy,
    shared: &'store Shared,
    _brand: PhantomData<fn(&'id ()) -> &'id ()>,
}

impl<'store, 'id> WriteBatch<'store, 'id> {
    pub(super) fn new(
        txn: WriteTransaction,
        apply_policy: ApplyPolicy,
        shared: &'store Shared,
    ) -> Self {
        Self {
            txn: Some(txn),
            apply_policy,
            shared,
            _brand: PhantomData,
        }
    }

    /// The policy this batch was begun under. Bound at construction so a
    /// run cannot change its own provenance halfway through.
    #[must_use]
    pub const fn apply_policy(&self) -> ApplyPolicy {
        self.apply_policy
    }

    fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("WriteBatch holds a transaction until commit consumes it")
    }

    /// The two by-name refusals every raw table open passes through.
    fn admit(&self, name: &str) -> Result<(), StoreError> {
        if name == PROPERTIES.name() {
            return Err(StoreError::PropertiesAreTyped);
        }
        if let Some(family) = ArchivalFamily::from_table(name) {
            if !self.apply_policy.applies(family) {
                return Err(StoreError::FamilyStubbed(family));
            }
        }
        Ok(())
    }

    /// Open a table for writing. Creates the table if it does not exist.
    ///
    /// Archival families whose apply is stubbed are refused *before* the
    /// engine sees the name, so a sufficiency run cannot accidentally
    /// create the table it is proving load-bearing. The `properties` table
    /// is refused outright: its cells are typed and written through
    /// [`put_property`](Self::put_property).
    ///
    /// # Errors
    ///
    /// [`StoreError::FamilyStubbed`] if this table is an archival family
    /// the policy skips; [`StoreError::PropertiesAreTyped`] for
    /// `properties`; [`StoreError::Table`] if the engine refuses.
    pub fn open_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<Table<'txn, K, V>, StoreError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.admit(definition.name())?;
        self.txn().open_table(definition).map_err(StoreError::Table)
    }

    /// Open a multimap table for writing. Same refusals as
    /// [`open_table`](Self::open_table).
    ///
    /// # Errors
    ///
    /// [`StoreError::FamilyStubbed`], [`StoreError::PropertiesAreTyped`]
    /// or [`StoreError::Table`].
    pub fn open_multimap_table<'txn, K, V>(
        &'txn self,
        definition: MultimapTableDefinition<'_, K, V>,
    ) -> Result<MultimapTable<'txn, K, V>, StoreError>
    where
        K: Key + 'static,
        V: Key + 'static,
    {
        self.admit(definition.name())?;
        self.txn()
            .open_multimap_table(definition)
            .map_err(StoreError::Table)
    }

    /// Read a typed `properties` cell, seeing this batch's own writes.
    ///
    /// Any scope may be read: a connect path that needs the layout version
    /// or the provenance can ask, it just cannot write them.
    ///
    /// # Errors
    ///
    /// [`StoreError::CellCorrupt`] if the cell is present but is not an
    /// encoding of `C::Value`; [`StoreError::Table`] / [`StoreError::Storage`]
    /// if the engine refuses. Absent is `Ok(None)`.
    pub fn get_property<C: PropertyCell>(&self) -> Result<Option<C::Value>, StoreError> {
        let table = self
            .txn()
            .open_table(PROPERTIES)
            .map_err(StoreError::Table)?;
        header::get::<C>(&table)
    }

    /// Write a typed **chain-state** `properties` cell.
    ///
    /// The bound is the permission: only `C: PropertyCell<Scope = ChainState>`
    /// compiles. The engine-local header cells (`schema_version`,
    /// `apply_policy`) have no public writer:
    ///
    /// ```compile_fail,E0271
    /// use shekyl_chain_store::codec::{SchemaVersion, SchemaVersionCell};
    /// use shekyl_chain_store::store::{ChainStore, StoreError};
    /// let store = ChainStore::create("never-opened.redb").unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.put_property::<SchemaVersionCell>(&SchemaVersion::new(9))
    /// });
    /// ```
    ///
    /// ```compile_fail,E0271
    /// use shekyl_chain_store::codec::ApplyPolicyCell;
    /// use shekyl_chain_store::family_set::FamilySet;
    /// use shekyl_chain_store::store::{ChainStore, StoreError};
    /// let store = ChainStore::create("never-opened.redb").unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.put_property::<ApplyPolicyCell>(&FamilySet::EMPTY)
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// [`StoreError::Table`] / [`StoreError::Storage`] if the engine refuses.
    pub fn put_property<C>(&self, value: &C::Value) -> Result<(), StoreError>
    where
        C: PropertyCell<Scope = ChainState>,
    {
        header::put::<C>(self.txn(), value)
    }

    /// Commit the batch, returning the file's [`Provenance`] as of this
    /// commit. Called by [`ChainStore::write`](super::ChainStore::write)
    /// when the closure returns `Ok`; there is no other caller.
    ///
    /// A stubbed batch widens the persisted provenance cell **in this
    /// transaction** before committing, so the taint is atomic with the
    /// rows. A `Full` batch leaves the cell as it found it.
    ///
    /// # Errors
    ///
    /// [`StoreError::Commit`] if the engine could not commit;
    /// [`StoreError::CellCorrupt`] / [`StoreError::Storage`] if the
    /// provenance cell could not be read back or widened (the batch is
    /// aborted, nothing lands). The transaction is consumed either way —
    /// DRS-W2's swallowed-`batch_stop` failure made unrepresentable.
    pub(super) fn commit(mut self) -> Result<Provenance, StoreError> {
        let txn = self
            .txn
            .take()
            .expect("WriteBatch commit runs once; the Option is Some until then");
        let provenance = header::widen(&txn, self.apply_policy)?;
        // The file is tainted when the engine commits; the mirror, when
        // `publish` assigns it. `Shared::publish` holds the mirror's write
        // lock across both, so `provenance()` cannot observe one without the
        // other — and a failed commit publishes nothing, so the mirror
        // cannot over-taint either.
        self.shared
            .publish(provenance, || txn.commit().map_err(StoreError::Commit))?;
        Ok(provenance)
    }
}

impl Drop for WriteBatch<'_, '_> {
    fn drop(&mut self) {
        // WriteTransaction::drop aborts if the txn is still present and not
        // completed. Clearing the flag after that so the next `write` is
        // not refused for a batch that no longer exists.
        self.txn.take();
        self.shared.release_write();
    }
}
