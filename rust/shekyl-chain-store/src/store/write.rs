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
//!
//! # The verbs
//!
//! Keyed tables open as [`KeyedTable`], which exposes exactly two value
//! writes — `insert` (fatal on a present key; the site names the `SI-`
//! row) and `upsert` (overwrite, declared) — and no raw `redb::Table`
//! (C2-R8 §7.3). Typed `properties` cells are registers and are written
//! through [`upsert_property`](WriteBatch::upsert_property). Multimap
//! tables are sets of values per key: there is no overwrite to declare,
//! so they open raw.
//!
//! # Poison
//!
//! An invariant violation is fatal to the batch, not just to the call that
//! hit it. Every `StoreInvariantViolated` produced or observed through the
//! batch arms a latch, and [`commit`](WriteBatch::commit) refuses with the
//! first armed row — so a closure that catches a violation and carries on
//! still cannot land anything. That is what makes "fatal, never
//! converted" (C2-R8 Q2) a property of the batch rather than a discipline
//! asked of every call site.

use core::cell::Cell;
use core::marker::PhantomData;

use redb::{
    Key, MultimapTable, MultimapTableDefinition, MultimapTableHandle, TableDefinition, TableHandle,
    Value, WriteTransaction,
};

use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{ChainState, PropertyCell};
use crate::provenance::Provenance;
use crate::schema::PROPERTIES;

use super::error::{EngineError, StoreCannot, StoreError, StoreInvariant};
use super::header;
use super::keyed::KeyedTable;
use super::shared::Shared;

/// The batch's fatal latch.
///
/// The first violation to arm it is kept; `Poison` never disarms. It is a
/// `Cell` because arming happens through shared borrows — a `KeyedTable`
/// holds `&'txn Poison` while the batch is also borrowed — and a batch is
/// single-threaded by construction (it lives inside one closure), so
/// interior mutability without a lock is the honest shape.
#[derive(Default)]
pub(super) struct Poison(Cell<Option<StoreInvariant>>);

impl Poison {
    /// Latch `row` (first one wins) and hand it back as the error the
    /// site returns, so arming and reporting cannot drift apart.
    pub(super) fn arm(&self, row: StoreInvariant) -> StoreError {
        if self.0.get().is_none() {
            self.0.set(Some(row));
        }
        row.into()
    }

    /// Route a store error through the latch: a violation arms it, any
    /// other error passes untouched.
    fn note(&self, e: StoreError) -> StoreError {
        match e {
            StoreError::InvariantViolated(row) => self.arm(row),
            other => other,
        }
    }

    fn armed(&self) -> Option<StoreInvariant> {
        self.0.get()
    }
}

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
    poison: Poison,
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
            poison: Poison::default(),
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
            return Err(StoreCannot::PropertiesAreTyped.into());
        }
        if let Some(family) = ArchivalFamily::from_table(name) {
            if !self.apply_policy.applies(family) {
                return Err(StoreCannot::FamilyStubbed(family).into());
            }
        }
        Ok(())
    }

    /// Open a keyed table for writing. Creates the table if it does not
    /// exist.
    ///
    /// The handle is a [`KeyedTable`]: reads are the engine's, writes are
    /// the two declared verbs. Archival families whose apply is stubbed
    /// are refused *before* the engine sees the name, so a sufficiency run
    /// cannot accidentally create the table it is proving load-bearing.
    /// The `properties` table is refused outright: its cells are typed and
    /// written through [`upsert_property`](Self::upsert_property).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::FamilyStubbed`] if this table is an archival family
    /// the policy skips; [`StoreCannot::PropertiesAreTyped`] for
    /// `properties`; [`EngineError::Table`] if the engine refuses.
    pub fn open_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<KeyedTable<'txn, K, V>, StoreError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.admit(definition.name())?;
        self.txn()
            .open_table(definition)
            .map(|table| KeyedTable::new(table, &self.poison))
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Open a multimap table for writing. Same refusals as
    /// [`open_table`](Self::open_table).
    ///
    /// The handle is raw: a multimap is a set of values per key, so an
    /// insert either adds a member or finds it present — there is no value
    /// to overwrite and no verb to declare (C2-R8 §7.3 is about keyed
    /// tables).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::FamilyStubbed`], [`StoreCannot::PropertiesAreTyped`]
    /// or [`EngineError::Table`].
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
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Read a typed `properties` cell, seeing this batch's own writes.
    ///
    /// Any scope may be read: a connect path that needs the layout version
    /// or the provenance can ask, it just cannot write them.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::CellCorrupt`] if the cell is present but is not an
    /// encoding of `C::Value` — and the batch is poisoned, so a caller that
    /// swallows this cannot commit; [`EngineError::Table`] /
    /// [`EngineError::Storage`] if the engine refuses. Absent is `Ok(None)`.
    pub fn get_property<C: PropertyCell>(&self) -> Result<Option<C::Value>, StoreError> {
        let table = self
            .txn()
            .open_table(PROPERTIES)
            .map_err(EngineError::Table)?;
        header::get::<C>(&table).map_err(|e| self.poison.note(e))
    }

    /// Upsert a typed **chain-state** `properties` cell.
    ///
    /// A `properties` cell is a register — the tip, a policy, a root
    /// pointer — so overwrite is the intended semantics and the verb says
    /// so (C2-R8 §7.3); there is no `insert_property`. Should a write-once
    /// cell ever be minted, the increment that mints it adds that verb and
    /// the register row it enforces.
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
    ///     batch.upsert_property::<SchemaVersionCell>(&SchemaVersion::new(9))
    /// });
    /// ```
    ///
    /// ```compile_fail,E0271
    /// use shekyl_chain_store::codec::ApplyPolicyCell;
    /// use shekyl_chain_store::family_set::FamilySet;
    /// use shekyl_chain_store::store::{ChainStore, StoreError};
    /// let store = ChainStore::create("never-opened.redb").unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.upsert_property::<ApplyPolicyCell>(&FamilySet::EMPTY)
    /// });
    /// ```
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] / [`EngineError::Storage`] if the engine refuses.
    pub fn upsert_property<C>(&self, value: &C::Value) -> Result<(), StoreError>
    where
        C: PropertyCell<Scope = ChainState>,
    {
        header::upsert::<C>(self.txn(), value)
    }

    /// Commit the batch, returning the file's [`Provenance`] as of this
    /// commit. Called by [`ChainStore::write`](super::ChainStore::write)
    /// when the closure returns `Ok`; there is no other caller.
    ///
    /// A poisoned batch does not commit: the first invariant violation seen
    /// through it is returned here and the transaction aborts on drop.
    /// Otherwise a stubbed batch widens the persisted provenance cell **in
    /// this transaction** before committing, so the taint is atomic with
    /// the rows. A `Full` batch leaves the cell as it found it.
    ///
    /// # Errors
    ///
    /// [`StoreError::InvariantViolated`] if the batch was poisoned;
    /// [`EngineError::Commit`] if the engine could not commit;
    /// [`StoreInvariant::CellCorrupt`] / [`EngineError::Storage`] if the
    /// provenance cell could not be read back or widened. In every `Err`
    /// case the batch is aborted and nothing lands. The transaction is
    /// consumed either way — DRS-W2's swallowed-`batch_stop` failure made
    /// unrepresentable.
    pub(super) fn commit(mut self) -> Result<Provenance, StoreError> {
        if let Some(row) = self.poison.armed() {
            // `self` drops on this return: the transaction aborts and the
            // write slot is released, exactly as for a closure `Err`.
            return Err(row.into());
        }
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
            .publish(provenance, || txn.commit().map_err(EngineError::Commit))?;
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
