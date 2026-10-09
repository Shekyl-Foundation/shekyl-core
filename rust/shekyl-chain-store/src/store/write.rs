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
//! Keyed tables open as one of four handles — [`InsertTable`] (fatal on a
//! present key; the `SI-` row is bound at open), [`UpsertTable`]
//! (overwrite, and may create), [`ReplaceTable`] (overwrite of a present
//! key only; an absent key is the row bound at open) or [`RemoveTable`]
//! (a journaling delete, fatal on an absent key; the row is bound at
//! open) — never as a raw `redb::Table` (C2-R8 §7.3). The verb is the
//! handle: a set table cannot upsert, a register cannot insert, a replace
//! cannot create, and a hard-fork that reclassifies a table opens the
//! other handle. Typed `properties` cells are registers and are written
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
use crate::codec::{
    post_image, Canonical, ChainState, CodecError, PropertyCell, TotalBurnedCell, UndoEntry,
};
use crate::schema::{self, BLOCK_INFO, PROPERTIES};

use super::chain_reads::ReadFault;
use super::prune::Horizons;

use shekyl_chain_rules::{
    Corrupt, FrontierFault, LeafInput, PerHeightRecord, RecordInvariant, SettlementCheck,
};
use shekyl_units::AtomicUnits;

use super::error::{
    CellFault, EngineError, SettlementFault, StoreCannot, StoreError, StoreInvariant,
};
use super::header;
use super::keyed::{Handles, InsertTable, RemoveTable, ReplaceTable, UpsertTable};
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
/// [`ChainStore::write`](super::ChainStore::write) commits an unpoisoned
/// `Ok`; [`ChainStore::inspect`](super::ChainStore::inspect) aborts it.
/// `Err` — or an unwind — drops the batch, and dropping **aborts** (redb
/// rolls back on drop). That is
/// the DRS-W8 direction, where a C++ throw left the write transaction live
/// and poisoned every later block write.
///
/// Dropping also releases the store's write-held flag, so a later
/// [`write`](super::ChainStore::write) can proceed.
#[must_use = "a WriteBatch is only ever handed to a `ChainStore::write` or `inspect` closure"]
pub struct WriteBatch<'store, 'id> {
    txn: Option<WriteTransaction>,
    apply_policy: ApplyPolicy,
    horizons: Horizons,
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
        horizons: Horizons,
    ) -> Self {
        Self {
            txn: Some(txn),
            apply_policy,
            horizons,
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

    /// The schedule and undo-log retention this batch prunes under
    /// (`store/prune.rs`). Bound at construction like the policy.
    #[must_use]
    pub const fn horizons(&self) -> Horizons {
        self.horizons
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

    /// The batch-side policy for a classified read fault (`chain_reads`):
    /// an invariant violation arms the fatal latch — a batch that read a
    /// corrupt row must not commit — and an engine fault passes through.
    /// The snapshot's policy is `ReadFault::into_plain`; this is the other
    /// half, in one place for every surface that reads through the batch
    /// (the alt store, the retention prune). Poison without a height hint
    /// aborts the batch and leaves the writer live — those rows are not
    /// chain work.
    pub(super) fn arm_read_fault(&self, fault: ReadFault) -> StoreError {
        match fault {
            ReadFault::Engine(e) => e.into(),
            ReadFault::Invariant(row) => self.arm_if_invariant(row.into()),
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
    /// | `CumulativeDifficultyOverflow` | `FoldOverflow { cell: "block_info.cumulative_difficulty" }` (SI-8) |
    /// | `BondRecordInvariant { which, .. }` | `CellCorrupt { key: "archival_bond", .. }` with `which` as the reason (SI-7) |
    /// | `BondHybridKeyMalformed { .. }` | `CellCorrupt { key: "archival_bond", .. }` the hybrid key is not canonical (SI-7) |
    /// | `AccrualOverflow { .. }` | `FoldOverflow { cell: "archival_budget_accruing" }` (SI-8) |
    /// | `SettlementIntegrity { epoch, check }` | `SettlementNotSound { epoch, .. }` with `check` as the fault (SI-25) |
    ///
    /// (The arms between are documented inline on the match.)
    ///
    /// A zero next-block target is **not** in this table and never was a
    /// store matter: LWMA-1 has no output floor and a conforming slow chain
    /// derives zero, so it is CEN-D6's refusal of the block — a verdict the
    /// validator returns, which the store never sees (RD-F17, 2026-09-20).
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
            Corrupt::CumulativeDifficultyOverflow => StoreInvariant::FoldOverflow {
                cell: "block_info.cumulative_difficulty",
            },
            Corrupt::TxCountNotMonotone { at } => StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_tx_count",
                height: at.to_raw(),
            },
            // The close's age operand could not be placed: the archival
            // fold `shard_close_height` searched does not cross a closed
            // shard's end at one height (DRS-E4 commit 4, on `SHT-Q2`'s
            // partition). The fold is non-decreasing on a conforming store,
            // so this is SI-13 read from the rule side, on the archival
            // cell — the same row the prune's descent arms when it finds
            // the fold going backwards.
            Corrupt::ShardCloseUnplaced { shard: _, at } => StoreInvariant::FoldNotMonotone {
                cell: "block_info.cumulative_archival_len",
                height: at.to_raw(),
            },
            // CEN-F17 read the `total_burned` register above the parent's
            // `coins_generated` (E6 slice 7 wave B). Burn destroys issued
            // coins, so the fold is bounded by the accumulator on every
            // conforming store (FL-R16c: a violation, never a zero supply);
            // a register holding more is a cell whose value the store's
            // own invariants rule out — SI-7's shape, on the register, with
            // the reason spelled. The store did not compute the pair; the
            // validator observed it and this is the halt.
            Corrupt::BurnExceedsEmission { .. } => StoreInvariant::CellCorrupt {
                key: "total_burned",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "total_burned",
                    reason: "the burned fold exceeds the parent's coins_generated (FL-R16c)",
                }),
            },
            // A rule read below the connecting height and the view answered
            // `AboveTip`: the same SI-7 row the store arms when it finds a
            // dense-range row missing — observed from the rule side this
            // time (E6 slice 6, 2026-09-24). The height is not on the row;
            // `CellCorrupt` names the cell the read was of, and the
            // connecting height the batch noted is the context. The record
            // selects the cell: a root hole reported as `block_info` would
            // halt the writer against the wrong table.
            Corrupt::HoleBelowTip { at: _, record } => StoreInvariant::CellCorrupt {
                key: match record {
                    PerHeightRecord::Block => "block_info",
                    PerHeightRecord::CurveTreeRoot => "curve_tree_roots",
                    PerHeightRecord::LeafCount => "curve_tree_leaf_counts",
                    PerHeightRecord::Outputs => "blocks",
                },
                fault: CellFault::Absent,
            },
            // The drain found a recorded point that does not decompress.
            // `O` and `C` are the `output_amounts` row; `CM` is the pruned
            // transaction's `0x07` field. The cell is the point's.
            Corrupt::LeafNotConstructible { output: _, input } => {
                let (key, codec, reason) = match input {
                    LeafInput::OutputKey => (
                        "output_amounts",
                        "output_key",
                        "the output key does not decompress",
                    ),
                    LeafInput::Commitment => (
                        "output_amounts",
                        "commitment",
                        "the amount commitment does not decompress",
                    ),
                    LeafInput::LeafCommitment => (
                        "txs_pruned",
                        "pqc_leaf_commitment",
                        "the leaf commitment does not decompress",
                    ),
                };
                StoreInvariant::CellCorrupt {
                    key,
                    fault: CellFault::Undecodable(CodecError::Invalid { codec, reason }),
                }
            }
            // A frontier the store's own read assembled. `NotOnCurve` is a
            // layer-table hash that decoded and is not a point of its curve.
            // `Shape` is the summary's leaf count disagreeing with the layer
            // count that count implies — the chunks were read; the count's
            // implication was not. An empty grow is not this arm.
            Corrupt::TreeUnservable { fault } => match fault {
                FrontierFault::NotOnCurve { .. } => StoreInvariant::CellCorrupt {
                    key: "curve_tree_layers",
                    fault: CellFault::Undecodable(CodecError::Invalid {
                        codec: "layer_hash",
                        reason: "a last chunk's hash is not a point of its layer's curve",
                    }),
                },
                FrontierFault::Shape { .. } => StoreInvariant::CellCorrupt {
                    key: "curve_tree_meta",
                    fault: CellFault::Undecodable(CodecError::Invalid {
                        codec: "curve_tree_state",
                        reason: "the frontier's layer count disagrees with the leaf count",
                    }),
                },
            },
            // The archival transition (DRS-E4 commit 4) read a bond record
            // the retention folds refuse as a record — a `bonded_total` off
            // its floor, two open intervals, a shard the record does not
            // hold. The record decoded; its values are ones no conforming
            // writer produces, so it is SI-7 on `archival_bond` with the
            // invariant named. The persona is not on the row: the noted
            // connecting height is the context, as for every arm here.
            Corrupt::BondRecordInvariant { persona: _, which } => StoreInvariant::CellCorrupt {
                key: "archival_bond",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "bond_record",
                    reason: match which {
                        RecordInvariant::FloorBroken => {
                            "bonded_total is below the floor its holdings imply"
                        }
                        RecordInvariant::MultipleOpenIntervals => {
                            "more than one bad interval is open"
                        }
                        RecordInvariant::IntervalOrdering => "the bad intervals are not in order",
                        RecordInvariant::CounterRange => {
                            "an interval bound is outside the epoch counter's range"
                        }
                        RecordInvariant::IntervalLogFull => {
                            "the bad-interval log is at its cap and a fold must append"
                        }
                        RecordInvariant::ShardNotHeld => {
                            "a slash names a shard the record does not hold"
                        }
                        RecordInvariant::BondedUnderflow => {
                            "bonded_total is below one bond floor at a slash"
                        }
                    },
                }),
            },
            // CEN-B4 read a bond record whose hybrid key is not the
            // canonical grammar. The record is bytes; the key type lives
            // above `shekyl-types`, so the cell can hold a key admission
            // would not have written. That is SI-7 on `archival_bond`, the
            // same cell as a fold invariant, and a different reason: the
            // key does not decode.
            Corrupt::BondHybridKeyMalformed { persona: _ } => StoreInvariant::CellCorrupt {
                key: "archival_bond",
                fault: CellFault::Undecodable(CodecError::Invalid {
                    codec: "bond_record",
                    reason: "the hybrid public key is not canonical",
                }),
            },
            // The open epoch's accruing budget plus this block's inflow does
            // not fit (CEN-L8's overflow clause). The validator computes the
            // post-image (`ARW-Q1`), so the SI-8 fold on
            // `archival_budget_accruing` is observed from the rule side.
            Corrupt::AccrualOverflow { epoch: _ } => StoreInvariant::FoldOverflow {
                cell: "archival_budget_accruing",
            },
            // Settlement's checks that have an operand
            // (`ARCHIVAL_SERVE_CREDIT_SPEC.md` §9.5, checks 1 and 3) and
            // the beacon guard. The validator derives the rows (`ARW-Q1`),
            // so it is the one that observes the index not folding to its
            // digest, its own fold overcounting, or a beacon block that is
            // not strictly below the connecting height. The block is not
            // invalid; this node cannot settle the epoch.
            Corrupt::SettlementIntegrity { epoch, check } => StoreInvariant::SettlementNotSound {
                epoch,
                observed: match check {
                    SettlementCheck::IssuedIndexDigest => SettlementFault::IndexDrift,
                    SettlementCheck::PassesExceedCounted { persona, shard } => {
                        SettlementFault::PassesExceedCounted { persona, shard }
                    }
                    SettlementCheck::BeaconNotRecorded => SettlementFault::BeaconNotRecorded,
                },
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

    /// Open a keyed table whose writes overwrite a present key only; an
    /// absent key is a violation of `row`, returned before any journal
    /// entry.
    ///
    /// `upsert` does not compile on the returned type — a register that
    /// may create its key is opened with
    /// [`open_upsert_table`](Self::open_upsert_table):
    ///
    /// ```compile_fail,E0599
    /// use redb::TableDefinition;
    /// use shekyl_chain_store::store::{ChainStore, StoreError, StoreInvariant};
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// const T: TableDefinition<&str, u64> = TableDefinition::new("t");
    /// const ROW: StoreInvariant = StoreInvariant::BondRecordAbsent;
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.open_replace_table(T, ROW)?.upsert("k", &1)?;
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
    pub fn open_replace_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
        row: StoreInvariant,
    ) -> Result<ReplaceTable<'txn, K, V>, StoreError>
    where
        K: Key + Restorable + 'static,
        V: Restorable + 'static,
    {
        self.admit(definition.name())?;
        let handles = self.handles(definition.name());
        self.txn()
            .open_table(definition)
            .map(|table| ReplaceTable::new_replace(table, handles, row))
            .map_err(|e| EngineError::Table(e).into())
    }

    /// Open a keyed table for journaling deletes of present keys; an
    /// absent key is a violation of `row`.
    ///
    /// Neither value verb compiles on the returned type:
    ///
    /// ```compile_fail,E0599
    /// use redb::TableDefinition;
    /// use shekyl_chain_store::store::{ChainStore, StoreError, StoreInvariant};
    /// use shekyl_chain_store::codec::SettlementEpochBlocks;
    /// const T: TableDefinition<&str, u64> = TableDefinition::new("t");
    /// const ROW: StoreInvariant = StoreInvariant::AccruingNotSingular {
    ///     observed: shekyl_chain_store::store::AccrualFault::AbsentAtClose,
    /// };
    /// let epoch = SettlementEpochBlocks::new(10_000).unwrap();
    /// let store = ChainStore::create("never-opened.redb", epoch).unwrap();
    /// store.write(|batch| -> Result<(), StoreError> {
    ///     batch.open_remove_table(T, ROW)?.upsert("k", &1)?;
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
    pub fn open_remove_table<'txn, K, V>(
        &'txn self,
        definition: TableDefinition<'_, K, V>,
        row: StoreInvariant,
    ) -> Result<RemoveTable<'txn, K, V>, StoreError>
    where
        K: Key + Restorable + 'static,
        V: Restorable + 'static,
    {
        self.admit(definition.name())?;
        let handles = self.handles(definition.name());
        self.txn()
            .open_table(definition)
            .map(|table| RemoveTable::new_remove(table, handles, row))
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

    /// The batch's view of [`ReadSnapshot::total_burned`]: `Σ fees_burned`
    /// over the connected chain as this write transaction sees it, `ZERO`
    /// when nothing has been connected. A producer assembling
    /// `ChainFacts` reads it here, under the same transaction as the tip
    /// and the windows it pairs it with, rather than through a snapshot
    /// taken before the batch opened (#852 review).
    ///
    /// [`ReadSnapshot::total_burned`]: super::read::ReadSnapshot::total_burned
    ///
    /// # Errors
    ///
    /// SI-7 if the cell does not decode (and the batch is poisoned); engine
    /// errors pass through.
    pub fn total_burned(&self) -> Result<AtomicUnits, StoreError> {
        Ok(self
            .get_property::<TotalBurnedCell>()?
            .unwrap_or(AtomicUnits::ZERO))
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
        if let Some(err) = self.halted() {
            return Err(err);
        }
        let value = outcome?;
        if let Some(height) = self.journal.abandoned() {
            return Err(StoreError::from(undo::unsealed(height)).into());
        }
        self.commit()?;
        Ok(value)
    }

    /// Finish a batch that must not land: poison still halts the writer,
    /// and the transaction is aborted on drop either way. The producer's
    /// read ([`ChainStore::inspect`](super::ChainStore::inspect)) uses this
    /// so a template read is not a commit.
    pub(super) fn abandon<R, E: From<StoreError>>(self, outcome: Result<R, E>) -> Result<R, E> {
        if let Some(err) = self.halted() {
            return Err(err);
        }
        outcome
    }

    /// Poison wins: the first armed row halts the writer and becomes the
    /// error, whichever arm the closure took.
    fn halted<E: From<StoreError>>(&self) -> Option<E> {
        let row = self.poison.armed()?;
        self.halt_for(row);
        Some(StoreError::from(row).into())
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
