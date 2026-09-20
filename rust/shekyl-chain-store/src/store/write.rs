// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The write handle that discharges DRS-W3, branded per batch (C2-R8 Q3).
//!
//! Table modules take [`WriteBatch`], never a raw transaction. Opening a
//! table consults [`ApplyPolicy`] by name so a stubbed family's apply
//! cannot run — and cannot create the table by opening it.
//!
//! A stubbed batch also **taints the file** when it commits: the
//! provenance cell is widened inside the batch's own transaction, so the
//! record that rows were written under a stub lands with those rows or
//! not at all. An aborted stubbed batch leaves no trace, which is
//! correct — it wrote nothing.
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
//! Keyed tables open as one of two handles — [`InsertTable`] (fatal on a
//! present key; the `SI-` row is bound at open) or [`UpsertTable`]
//! (overwrite, declared) — never as a raw `redb::Table` (C2-R8 §7.3).
//! The verb is the handle: a set table cannot upsert, a register cannot
//! insert, and a hard-fork that reclassifies a table opens the other
//! handle. Typed `properties` cells are registers and are written
//! through [`upsert_property`](WriteBatch::upsert_property). There is no
//! multimap opener: the catalogue has had no multimap since S-OUT-KI's
//! layout commit made `output_amounts` a keyed `(amount, amount_index)`
//! table (SOK-1).
//!
//! # The pop journal
//!
//! Every one of those verbs journals its own pre-image while the batch is
//! recording ([`record_undo`](WriteBatch::record_undo), S-CHAIN-W); the
//! recording's `seal` writes `undo_log[height]`, and
//! [`replay_undo`](WriteBatch::replay_undo) walks such a row backwards
//! (`store::undo`). A recording that is dropped unsealed makes the batch
//! refuse to commit — writes with no pre-images never land.
//!
//! # Poison
//!
//! An invariant violation is fatal to the batch, not just to the call that
//! hit it. Every `StoreInvariantViolated` produced or observed through the
//! batch arms a latch, and finishing the batch refuses with the first
//! armed row **whether the closure returned `Ok` or some other `Err`** —
//! so a closure that catches a violation cannot convert it into a
//! different error, and nothing lands. That is what makes "fatal, never
//! converted" (C2-R8 Q2) a property of the batch rather than a discipline
//! asked of every call site.

use core::cell::Cell;
use core::marker::PhantomData;

use redb::{Key, ReadableTable, TableDefinition, TableHandle, WriteTransaction};

use crate::apply_policy::{ApplyPolicy, ArchivalFamily};
use crate::codec::{post_image, Canonical, ChainState, PropertyCell, UndoEntry};
use crate::schema::{self, BLOCK_INFO, PROPERTIES};

use shekyl_chain_rules::Corrupt;

use super::error::{EngineError, StoreCannot, StoreError, StoreInvariant};
use super::header;
use super::keyed::{Handles, InsertTable, UpsertTable};
use super::shared::Shared;
use super::undo::{self, Journal, Recording, Replayed, Restorable};
use super::view::BatchView;

/// The batch's fatal latch.
///
/// The first violation to arm it is kept; `Poison` never disarms. It is a
/// `Cell` because arming happens through shared borrows — an insert or
/// upsert handle holds `&'txn Poison` while the batch is also borrowed —
/// and a batch is single-threaded by construction (it lives inside one
/// closure), so interior mutability without a lock is the honest shape.
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
    journal: Journal,
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
            journal: Journal::default(),
            _brand: PhantomData,
        }
    }

    /// The latch, the journal and `name`'s ordinal, for a handle to write
    /// through.
    fn handles(&self, name: &str) -> Handles<'_> {
        Handles {
            poison: &self.poison,
            journal: &self.journal,
            ordinal: schema::ordinal_of(name),
            name: name.into(),
        }
    }

    /// The policy this batch was begun under. Bound at construction so a
    /// run cannot change its own provenance halfway through.
    #[must_use]
    pub const fn apply_policy(&self) -> ApplyPolicy {
        self.apply_policy
    }

    pub(super) fn txn(&self) -> &WriteTransaction {
        self.txn
            .as_ref()
            .expect("WriteBatch holds a transaction until commit consumes it")
    }

    /// The batch's fatal latch, for the projections that read through it.
    pub(super) const fn poison(&self) -> &Poison {
        &self.poison
    }

    /// The batch's pop journal, for `pop` to note the height it works at.
    pub(super) const fn journal(&self) -> &Journal {
        &self.journal
    }

    /// Route an error that may be an invariant violation through the fatal
    /// latch: a [`StoreError::InvariantViolated`] arms the poison (so
    /// `complete` halts the writer for it, §3.6.2) and is returned; any
    /// other error passes through unchanged. For the paths that read a
    /// typed cell without going through a handle that arms on its own
    /// (`header::widen_*`).
    pub(super) fn arm_if_invariant(&self, e: StoreError) -> StoreError {
        match e {
            StoreError::InvariantViolated(row) => self.poison.arm(row),
            other => other,
        }
    }

    /// The validator read this batch's view and found the store's record
    /// inconsistent: arm the fatal latch for what it saw, so `complete` halts
    /// the writer at the noted height exactly as a belt would have.
    ///
    /// A [`Corrupt`] is a store-invariant violation observed by the rules
    /// crate instead of by a store write site — CEN-D4's window walk over
    /// `BatchView` sees `block_info` rows whose cumulative work does not
    /// increase (SI-10), or an overflow the store's own fold would have
    /// caught had the store computed the value (SI-8). The store computes
    /// none of it (C2-R8 Q4), so the observation arrives here and the store
    /// supplies the consequence. The mapping is by arm:
    ///
    /// | `Corrupt` | `StoreInvariant` |
    /// | --- | --- |
    /// | `CumulativeDifficultyNotMonotone { at }` | `WorkNotIncreasing { height: at }` (SI-10) |
    /// | `ZeroTarget` | `WorkNotIncreasing { height: connecting }` (SI-10 — a full window with no increase, ending at the connecting height's parent) |
    /// | `CumulativeDifficultyOverflow` | `FoldOverflow { cell: "block_info.cumulative_difficulty" }` (SI-8) |
    ///
    /// Returns the `InvariantViolated` the caller propagates — the batch is
    /// poisoned either way, and `complete` refuses to commit it. **This is
    /// the one place the store names a validator fault type**, and it names
    /// only `Corrupt`: never `InvalidBlock` (the conversion ban), never
    /// `Stale` (unproven is not a store fault), never `Fault::View` (that is
    /// the store's own error coming back). The ingest pipeline is its caller
    /// (DRS-E2 RD-Q4; minted with that caller, as ruled 2026-09-19 — the API
    /// #785's commit 9 shed rather than guess at from the store side).
    ///
    /// Refusing a `Corrupt` **is chain work**: the validator read this
    /// store's chain to find it. So the connecting height is noted here if
    /// nothing in the batch noted it yet (normally `chain_view` already did,
    /// at `tip + 1`), and the writer halt fires at that height — §3.6.2's
    /// "a batch that did no chain work does not halt" cannot apply to a
    /// batch whose chain was just found inconsistent.
    pub fn refuse_corrupt(&self, corrupt: Corrupt) -> StoreError {
        if self.journal.height_hint().is_none() {
            self.note_chain_work();
        }
        let row = match corrupt {
            Corrupt::CumulativeDifficultyNotMonotone { at } => StoreInvariant::WorkNotIncreasing {
                height: at.to_raw(),
            },
            Corrupt::ZeroTarget => StoreInvariant::WorkNotIncreasing {
                height: self
                    .journal
                    .height_hint()
                    .expect("noted above: refusing a Corrupt is chain work"),
            },
            Corrupt::CumulativeDifficultyOverflow => StoreInvariant::FoldOverflow {
                cell: "block_info.cumulative_difficulty",
            },
        };
        self.poison.arm(row)
    }

    /// Project this batch as the [`ChainView`](shekyl_chain_rules::ChainView)
    /// a rule reads — including this batch's own uncommitted writes, so the
    /// second block of a batch is validated against the chain the first
    /// left (`store::view`). `'id` is the batch brand: a `ChainValid` minted
    /// against the returned view is accepted by this batch's `connect` and
    /// by nothing else.
    ///
    /// Obtaining the branded view is chain work: production validation
    /// reads through it **before** `connect` can run, so an SI-7 here must
    /// latch the writer halt even when `connect` is never reached. The
    /// height noted is the connecting height (`tip + 1`, or `0` on an empty
    /// chain). Table-level probes never call this, and still do not halt
    /// (§3.6.2; PR #757 review).
    pub fn chain_view(&self) -> BatchView<'_, 'id> {
        self.note_chain_work();
        BatchView::new(self)
    }

    /// Remember that this batch is chain work at `tip + 1`, so a poisoned
    /// validation read latches [`halt_for`](Self::halt_for).
    fn note_chain_work(&self) {
        let height = self
            .txn()
            .open_table(BLOCK_INFO)
            .ok()
            .and_then(|table| {
                table
                    .last()
                    .ok()
                    .flatten()
                    .map(|(h, _)| h.value().saturating_add(1))
            })
            .unwrap_or(0);
        self.journal.note_height(height);
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

    /// Open a keyed table whose value writes are insert-once.
    ///
    /// `row` is the `SI-` belt this table enforces (SI-1 for `spent_keys`,
    /// SI-3 for `tx_indices`, …). It is bound here, not on each insert, so a site
    /// cannot name a different belt for two writes to the same handle.
    /// The `insert` verb is the only value write on the returned type —
    /// `upsert` does not compile:
    ///
    /// ```compile_fail,E0599
    /// use redb::TableDefinition;
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// use shekyl_chain_store::store::{CellFault, ChainStore, StoreError, StoreInvariant};
    /// const T: TableDefinition<&str, u64> = TableDefinition::new("t");
    /// const ROW: StoreInvariant = StoreInvariant::CellCorrupt {
    ///     key: "t",
    ///     fault: CellFault::Absent,
    /// };
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.open_insert_table(T, ROW)?.upsert("k", &1)?;
    ///     Ok(())
    /// });
    /// ```
    ///
    /// Archival families whose apply is stubbed are refused *before* the
    /// engine sees the name. The `properties` table is refused outright:
    /// its cells are typed and written through
    /// [`upsert_property`](Self::upsert_property).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::FamilyStubbed`] if this table is an archival family
    /// the policy skips; [`StoreCannot::PropertiesAreTyped`] for
    /// `properties`; [`EngineError::Table`] if the engine refuses.
    pub fn open_insert_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
        row: StoreInvariant,
    ) -> Result<InsertTable<'txn, K, V>, StoreError>
    where
        K: Key + Restorable + 'static,
        V: Restorable + 'static,
    {
        self.admit(definition.name())?;
        let handles = self.handles(definition.name());
        self.txn()
            .open_table(definition)
            .map(|table| InsertTable::new_insert(table, handles, row))
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Open a keyed table whose value writes are declared overwrite.
    ///
    /// `insert` does not compile on the returned type — a register that
    /// was meant to be a set is opened with
    /// [`open_insert_table`](Self::open_insert_table) instead:
    ///
    /// ```compile_fail,E0599
    /// use redb::TableDefinition;
    /// use shekyl_chain_store::store::{ChainStore, StoreError};
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// const T: TableDefinition<&str, u64> = TableDefinition::new("t");
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.open_upsert_table(T)?.insert("k", &1)?;
    ///     Ok(())
    /// });
    /// ```
    ///
    /// Same by-name refusals as [`open_insert_table`](Self::open_insert_table).
    ///
    /// # Errors
    ///
    /// [`StoreCannot::FamilyStubbed`], [`StoreCannot::PropertiesAreTyped`]
    /// or [`EngineError::Table`].
    pub fn open_upsert_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<UpsertTable<'txn, K, V>, StoreError>
    where
        K: Key + Restorable + 'static,
        V: Restorable + 'static,
    {
        self.admit(definition.name())?;
        let handles = self.handles(definition.name());
        self.txn()
            .open_table(definition)
            .map(|table| UpsertTable::new_upsert(table, handles))
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
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.upsert_property::<SchemaVersionCell>(&SchemaVersion::new(9))
    /// });
    /// ```
    ///
    /// ```compile_fail,E0271
    /// use shekyl_chain_store::codec::ApplyPolicyCell;
    /// use shekyl_chain_store::family_set::FamilySet;
    /// use shekyl_chain_store::store::{ChainStore, StoreError};
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.upsert_property::<ApplyPolicyCell>(&FamilySet::EMPTY)
    /// });
    /// ```
    ///
    /// While the batch is recording a pop journal, the cell's prior bytes
    /// (or their absence) are journaled so `pop` restores the register.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] / [`EngineError::Storage`] if the engine refuses.
    pub fn upsert_property<C>(&self, value: &C::Value) -> Result<(), StoreError>
    where
        C: PropertyCell<Scope = ChainState>,
    {
        let prior = if self.journal.is_recording() {
            let table = self
                .txn()
                .open_table(PROPERTIES)
                .map_err(EngineError::Table)?;
            let prior = table
                .get(C::KEY)
                .map_err(EngineError::Storage)?
                .map(|guard| Box::<[u8]>::from(guard.value().bytes()));
            Some(prior)
        } else {
            None
        };
        header::put::<C>(self.txn(), value)?;
        if let Some(prior) = prior {
            let post = post_image(&value.encode());
            self.handles(PROPERTIES.name())
                .journal(|table| UndoEntry::Replaced {
                    table,
                    key: Box::from(C::KEY.as_bytes()),
                    prior,
                    post,
                });
        }
        Ok(())
    }

    /// Begin journaling this batch's declared writes as the pre-images of
    /// `height`, until the returned [`Recording`] is sealed.
    ///
    /// `connect`'s first act; its last is `seal`, which writes
    /// `undo_log[height]`. There is at most one live recording per batch
    /// (a second `record_undo` before `seal` is a bug in this crate and
    /// panics), and a recording dropped unsealed makes `complete` refuse
    /// with [`StoreCannot::UndoUnsealed`].
    pub(crate) fn record_undo(&self, height: u64) -> Recording<'_> {
        Recording::begin(&self.journal, &self.poison, self.txn(), height)
    }

    /// Reverse-replay `undo_log[height]` and delete the row.
    ///
    /// `pop`'s mechanism (C2-R8 Q5). Every SI-6 / SI-7 outcome poisons the
    /// batch. A recording must not be live: replay is not itself journaled.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::UndoLogIncoherent`] (SI-6) if an entry's target is
    /// not in the state the entry left; [`StoreInvariant::CellCorrupt`]
    /// (SI-7) if the row does not decode or names a table the catalogue
    /// lacks; engine errors.
    pub(crate) fn replay_undo(&self, height: u64) -> Result<Replayed, StoreError> {
        assert!(
            !self.journal.is_recording(),
            "replay_undo while a recording is live: pop does not run inside connect"
        );
        undo::replay(self.txn(), &self.poison, height)
    }

    /// Finish the batch given the closure's `outcome`.
    ///
    /// Poison wins on both arms: a violation seen through the batch is
    /// returned as `E` (via `From<StoreError>`) even when the closure
    /// returned a different `Err`, and the transaction aborts on drop.
    /// Only an unpoisoned `Ok` commits. An `Err` from the closure is
    /// returned **as the closure raised it**: a connect that refused a
    /// malformed block after it had started journaling leaves an unsealed
    /// recording behind, and that is the refusal's consequence, not a
    /// second error to report in its place — the unsealed refusal
    /// ([`StoreCannot::UndoUnsealed`]) is for a closure that swallowed the
    /// failure and returned `Ok`.
    pub(super) fn complete<R, E: From<StoreError>>(self, outcome: Result<R, E>) -> Result<R, E> {
        if let Some(row) = self.poison.armed() {
            self.halt_for(row);
            return Err(StoreError::from(row).into());
        }
        let value = outcome?;
        if let Some(height) = self.journal.abandoned() {
            return Err(StoreError::from(undo::unsealed(height)).into());
        }
        self.commit()?;
        Ok(value)
    }

    /// A violation on a connect, a pop, or a branded `chain_view` read
    /// (production validation) halts the writer (§3.6.2): the file's
    /// coherence is in doubt at that height and every later write would
    /// build on it. A violation in a batch that did none of those (a
    /// table-level test probe) aborts this batch only.
    fn halt_for(&self, row: StoreInvariant) {
        if let Some(at_height) = self.journal.height_hint() {
            self.shared.halt(at_height, row);
        }
    }

    /// Commit the batch. Called by [`complete`](Self::complete) on an
    /// unpoisoned `Ok`; there is no other caller.
    ///
    /// A stubbed batch widens the persisted provenance cell **in this
    /// transaction** before committing, so the taint is atomic with the
    /// rows, and publishes the widened [`Provenance`] to the store's
    /// mirror under the same lock — [`ChainStore::provenance`] is where a
    /// caller reads it. A `Full` batch leaves the cell as it found it.
    ///
    /// [`Provenance`]: crate::provenance::Provenance
    /// [`ChainStore::provenance`]: super::ChainStore::provenance
    ///
    /// # Errors
    ///
    /// [`EngineError::Commit`] if the engine could not commit;
    /// [`StoreInvariant::CellCorrupt`] / [`EngineError::Storage`] if the
    /// provenance cell could not be read back or widened. In every `Err`
    /// case the batch is aborted and nothing lands. The transaction is
    /// consumed either way — DRS-W2's swallowed-`batch_stop` failure made
    /// unrepresentable.
    fn commit(mut self) -> Result<(), StoreError> {
        let txn = self
            .txn
            .take()
            .expect("WriteBatch commit runs once; the Option is Some until then");
        // The commit-time widen reads a typed cell; an SI-7 here is a
        // violation this batch observed and halts the writer like one seen
        // inside the closure.
        let provenance = header::widen(&txn, self.apply_policy).map_err(|e| {
            if let StoreError::InvariantViolated(row) = e {
                self.halt_for(row);
            }
            e
        })?;
        // The file is tainted when the engine commits; the mirror, when
        // `publish` assigns it. `Shared::publish` holds the mirror's write
        // lock across both, so `provenance()` cannot observe one without the
        // other — and a failed commit publishes nothing, so the mirror
        // cannot over-taint either.
        self.shared
            .publish(provenance, || txn.commit().map_err(EngineError::Commit))
            .map_err(StoreError::from)
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
