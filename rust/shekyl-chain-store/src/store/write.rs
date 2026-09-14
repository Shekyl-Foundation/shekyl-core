// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The write handle that discharges DRS-W3.
//!
//! Table modules take [`WriteBatch`], never a raw transaction. Opening a
//! table consults [`ApplyPolicy`](crate::apply_policy::ApplyPolicy) by name
//! so a stubbed family's apply cannot run — and cannot create the table
//! by opening it.

use std::sync::atomic::{AtomicBool, Ordering};

use redb::{
    Durability, Key, MultimapTable, MultimapTableDefinition, MultimapTableHandle, Table,
    TableDefinition, TableHandle, Value, WriteTransaction,
};

use crate::apply_policy::{ApplyPolicy, ArchivalFamily};

use super::error::StoreError;
use super::{DURABILITY, TWO_PHASE_COMMIT};

/// An open write transaction.
///
/// It cannot be default-constructed, cloned, or observed in a null state;
/// [`commit`](Self::commit) and [`abort`](Self::abort) take `self` by value.
/// Dropping it without committing **aborts** it (redb rolls back on drop) —
/// the DRS-W8 direction, where a C++ throw left the write transaction live
/// and poisoned every later block write.
///
/// Dropping also releases the store's write-held flag, so a later
/// [`begin_batch`](super::ChainStore::begin_batch) can proceed.
#[must_use = "dropping a WriteBatch aborts it; call commit or abort"]
pub struct WriteBatch<'store> {
    txn: Option<WriteTransaction>,
    apply_policy: ApplyPolicy,
    durability: Durability,
    two_phase: bool,
    write_held: &'store AtomicBool,
}

impl<'store> WriteBatch<'store> {
    pub(super) fn new(
        txn: WriteTransaction,
        apply_policy: ApplyPolicy,
        write_held: &'store AtomicBool,
    ) -> Self {
        Self {
            txn: Some(txn),
            apply_policy,
            durability: DURABILITY,
            two_phase: TWO_PHASE_COMMIT,
            write_held,
        }
    }

    /// The policy this batch was begun under. Bound at construction so a
    /// run cannot change its own provenance halfway through.
    #[must_use]
    pub const fn apply_policy(&self) -> ApplyPolicy {
        self.apply_policy
    }

    /// Durability this batch was armed with. Recorded after the engine
    /// accepted [`DURABILITY`], so a test of this value is a test of the
    /// applied policy, not only of the token.
    #[must_use]
    pub const fn durability(&self) -> Durability {
        self.durability
    }

    /// Whether two-phase commit was armed on this batch.
    #[must_use]
    pub const fn two_phase_commit(&self) -> bool {
        self.two_phase
    }

    fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("WriteBatch holds a transaction until commit/abort consume it")
    }

    fn refuse_stubbed(&self, name: &str) -> Result<(), StoreError> {
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
    /// create the table it is proving load-bearing.
    ///
    /// # Errors
    ///
    /// [`StoreError::FamilyStubbed`] if this table is an archival family
    /// the policy skips; [`StoreError::Table`] if the engine refuses.
    pub fn open_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<Table<'txn, K, V>, StoreError>
    where
        K: Key + 'static,
        V: Value + 'static,
    {
        self.refuse_stubbed(definition.name())?;
        self.txn().open_table(definition).map_err(StoreError::Table)
    }

    /// Open a multimap table for writing. Same stubbing rule as
    /// [`open_table`](Self::open_table).
    ///
    /// # Errors
    ///
    /// [`StoreError::FamilyStubbed`] or [`StoreError::Table`].
    pub fn open_multimap_table<'txn, K, V>(
        &'txn self,
        definition: MultimapTableDefinition<'_, K, V>,
    ) -> Result<MultimapTable<'txn, K, V>, StoreError>
    where
        K: Key + 'static,
        V: Key + 'static,
    {
        self.refuse_stubbed(definition.name())?;
        self.txn()
            .open_multimap_table(definition)
            .map_err(StoreError::Table)
    }

    /// Commit the batch.
    ///
    /// # Errors
    ///
    /// [`StoreError::Commit`] if the engine could not commit. The
    /// transaction is consumed either way — DRS-W2's swallowed-`batch_stop`
    /// failure made unrepresentable.
    pub fn commit(mut self) -> Result<(), StoreError> {
        let txn = take_txn(&mut self.txn);
        txn.commit().map_err(StoreError::Commit)
    }

    /// Discard the batch explicitly.
    ///
    /// Equivalent to dropping it on the success path; provided so an
    /// intentional abort reads as a decision. Unlike drop, this surfaces
    /// an engine abort failure (DRS-W2's shape on the abort path).
    ///
    /// # Errors
    ///
    /// [`StoreError::Abort`] if the engine could not abort. The handle is
    /// gone either way.
    pub fn abort(mut self) -> Result<(), StoreError> {
        let txn = take_txn(&mut self.txn);
        txn.abort().map_err(StoreError::Abort)
    }
}

fn take_txn(txn: &mut Option<WriteTransaction>) -> WriteTransaction {
    txn.take()
        .expect("WriteBatch commit/abort run once; the Option is Some until then")
}

impl Drop for WriteBatch<'_> {
    fn drop(&mut self) {
        // WriteTransaction::drop aborts if the txn is still present and not
        // completed. Clearing the flag after that so the next begin_batch
        // is not refused for a batch that no longer exists.
        self.txn.take();
        self.write_held.store(false, Ordering::Release);
    }
}
