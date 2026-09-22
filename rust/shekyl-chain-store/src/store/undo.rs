// Copyright (c) 2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! The pop journal: recording inside a batch, replay in reverse (C2-R8 Q5).
//!
//! # Recording is a property of the verb
//!
//! While a [`Recording`] is live on a batch, every declared write made
//! through that batch — [`InsertTable::insert`](super::InsertTable::insert),
//! [`UpsertTable::upsert`](super::UpsertTable::upsert),
//! [`WriteBatch::upsert_property`](super::WriteBatch::upsert_property) —
//! pushes its own pre-image as a side effect of succeeding. There is no
//! "journaled" flavour of a verb to forget to call: the handle records or
//! the write does not happen through the handle. Sealing the recording
//! writes the accumulated [`UndoLog`] as `undo_log[height]` and is the last
//! thing a connect does, so the row's own insert is not in the row.
//!
//! What is *not* recorded: the store's own header writes (`seal`, `widen`),
//! which are engine-local and never popped, and any write made while no
//! recording is live. `connect` is the only chain-state writer and it holds
//! the recording for the whole block, so "not live" means "not a
//! chain-state write" by construction.
//!
//! # Replay is the only deleter
//!
//! [`replay`] reads one height's row, walks its entries **from the back**,
//! and applies each entry's inverse through the table the entry's ordinal
//! names — then deletes the row. Nothing else in the store removes a key:
//! `KeyedTable` has no `remove`, and does not gain one here (S-CURVE names
//! a journaling delete when the drain needs it). Every inverse asserts the
//! state it expects to find (the inserted key present, the replaced key
//! present) and a miss is SI-6 — the journal has stopped describing the
//! tables, and the batch is poisoned.
//!
//! # `from_bytes` is not a decoder
//!
//! redb's `Value::from_bytes` is documented as allowed to assume its input
//! came from `as_bytes`, and the fixed-width and `&str` impls panic
//! otherwise. A journal row is a file cell that could be damaged, so every
//! recorded key or value passes [`Restorable::well_formed`] first; a byte
//! string that would panic the engine's decoder is SI-7 instead.

use core::cell::{Cell, RefCell};

use redb::{
    Key, ReadTransaction, ReadableTable, TableDefinition, TableHandle, Value, WriteTransaction,
};

use crate::codec::{
    post_image, Blob, BlobKind, Canonical, CodecError, Coded, Present, UndoEntry, UndoLog, Unshaped,
};
use crate::lmdb_order::LmdbHashKey;
use crate::schema::{self, UNDO_LOG};

use super::error::{CellFault, EngineError, StoreCannot, StoreError, StoreInvariant, UndoFault};
use super::write::Poison;

/// A stored type whose bytes can be checked before `Value::from_bytes`.
///
/// Implemented for exactly the key types `schema.rs` uses and the four
/// map-value shapes (`codec::shape`); a table declared over a type without
/// this impl does not compile into `UNDO_TARGETS`, so a table the journal
/// could not safely replay is a build error. The default is the
/// fixed-width check, which is what every panicking `from_bytes` among
/// the keys (`u64`, `LmdbHashKey`, [`Present`]) needs; `&str` adds UTF-8; the
/// byte-string key accepts anything. A `Coded<V>` row is checked by
/// `V::decode` itself — the same strict decode the read path runs.
pub trait Restorable: Value {
    /// Whether a table over this value type has a writer and is therefore
    /// **created by the seal** (S-CHAIN-R amendment A2). `true` for every
    /// shape but [`Unshaped`]: the seal set is derived from the value
    /// shapes, never kept as a second list (`schema` module docs, *The seal
    /// creates every table with a writer*).
    const SEALED: bool = true;

    /// `Err(reason)` if `from_bytes` would panic or misread `bytes`.
    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        match Self::fixed_width() {
            Some(width) if bytes.len() != width => Err("wrong width for a fixed-width type"),
            _ => Ok(()),
        }
    }
}

// Key types. The tuple key is `output_amounts`' `(amount, amount_index)`
// (S-OUT-KI SOK-1): redb's tuple `from_bytes` slices its components at
// their fixed widths, so the well-formedness check is the default
// fixed-width one — 16 bytes — which `Value::fixed_width` derives for a
// tuple of fixed-width parts.
impl Restorable for u64 {}
impl Restorable for (u64, u64) {}
// `curve_tree_layers`' `(layer, chunk)` (S-CURVE `SCU-Q3`): 9 fixed bytes.
impl Restorable for (u8, u64) {}
// `curve_tree_meta`'s unit key (S-CURVE `SCU-Q1`): the one-row table.
impl Restorable for () {}
impl Restorable for LmdbHashKey {}
impl Restorable for &[u8] {}

// The four map-value shapes (`codec::shape`). A codec row is well-formed iff
// it decodes — strictly, under its own codec, which is a stronger check
// than the width the default performs and the one the read path makes; a
// blob row iff its kind says so; a set-table row iff it is zero-width; an
// unshaped table has no rows at all, so a journal entry naming one is
// malformed by construction.
impl Restorable for Present {}
impl<V: Canonical + 'static> Restorable for Coded<V> {
    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        V::decode(bytes)
            .map(drop)
            .map_err(|_| "row does not decode under the table's codec")
    }
}

impl<K: BlobKind> Restorable for Blob<K> {
    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        K::well_formed(bytes)
    }
}

impl Restorable for Unshaped {
    const SEALED: bool = false;

    fn well_formed(_bytes: &[u8]) -> Result<(), &'static str> {
        Err("an unshaped table has no rows")
    }
}

impl Restorable for &str {
    fn well_formed(bytes: &[u8]) -> Result<(), &'static str> {
        core::str::from_utf8(bytes)
            .map(drop)
            .map_err(|_| "not UTF-8")
    }
}

/// What replaying one entry against its table found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Undone {
    /// The inverse applied and found the state the entry described.
    Reversed,
    /// The target key or member was absent where the entry said it was
    /// present (SI-6).
    TargetMismatch,
    /// The key was present, but the value under it was not the one the
    /// journaled write left — its post-image digest disagrees (SI-6):
    /// something wrote around the journal, or the file is corrupt.
    PostImageMismatch,
    /// The entry names an unshaped table, or its bytes would not decode
    /// (SI-7).
    Malformed(&'static str),
}

/// A table as the catalogue dispatches to it: a replay target (from a
/// [`TableOrdinal`] to a typed `open_table`) and, since S-CHAIN-R amendment
/// A2, a **seal** target — created at `ChainStore::create` and required by
/// `header::verify` iff its value shape has a writer
/// ([`Restorable::SEALED`]). Implemented for both definition shapes;
/// object-safe so the schema can hold every table in one
/// `&[&dyn UndoTarget]`.
pub(crate) trait UndoTarget {
    /// The table name, as the definition declares it.
    fn name(&self) -> &str;

    /// Apply `entry`'s inverse in `txn`.
    ///
    /// # Errors
    ///
    /// Only engine errors; the journal-level outcomes are the [`Undone`]
    /// value, so the caller names the row.
    fn undo(&self, txn: &WriteTransaction, entry: &UndoEntry) -> Result<Undone, StoreError>;

    /// Whether the seal creates this table (its value shape has a writer).
    fn sealed(&self) -> bool;

    /// Open — and so create — the table in the seal transaction. A no-op
    /// for a table the seal does not cover.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] if the engine refuses.
    fn create(&self, txn: &WriteTransaction) -> Result<(), EngineError>;

    /// Whether the table exists in `txn`'s view of the file.
    ///
    /// # Errors
    ///
    /// [`EngineError::Table`] on any refusal other than *does not exist*.
    fn exists(&self, txn: &ReadTransaction) -> Result<bool, EngineError>;
}

/// Map redb's *does not exist* onto `false`, every other refusal onto the
/// engine error, for the two `exists` impls.
fn exists_or<T>(opened: Result<T, redb::TableError>) -> Result<bool, EngineError> {
    match opened {
        Ok(_) => Ok(true),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
        Err(e) => Err(EngineError::Table(e)),
    }
}

impl<K, V> UndoTarget for TableDefinition<'static, K, V>
where
    K: Key + Restorable + 'static,
    V: Value + Restorable + 'static,
{
    fn name(&self) -> &str {
        TableHandle::name(self)
    }

    fn sealed(&self) -> bool {
        V::SEALED
    }

    fn create(&self, txn: &WriteTransaction) -> Result<(), EngineError> {
        if V::SEALED {
            txn.open_table(*self).map_err(EngineError::Table)?;
        }
        Ok(())
    }

    fn exists(&self, txn: &ReadTransaction) -> Result<bool, EngineError> {
        exists_or(txn.open_table(*self))
    }

    fn undo(&self, txn: &WriteTransaction, entry: &UndoEntry) -> Result<Undone, StoreError> {
        // An `Unshaped` table has no writer, so no journal row can name it
        // honestly; refuse before `remove` could reach the uninhabited
        // `from_bytes`. `well_formed` alone guards only `prior`, and an
        // `Inserted` entry has none.
        if !V::SEALED {
            return Ok(Undone::Malformed("journal entry names an unshaped table"));
        }
        let (key, prior, post) = match entry {
            UndoEntry::Inserted { key, post, .. } => (key, None, post),
            UndoEntry::Replaced {
                key, prior, post, ..
            } => (key, prior.as_deref(), post),
        };
        if let Err(reason) = K::well_formed(key) {
            return Ok(Undone::Malformed(reason));
        }
        if let Some(reason) = prior.and_then(|p| V::well_formed(p).err()) {
            return Ok(Undone::Malformed(reason));
        }
        let mut table = txn.open_table(*self).map_err(EngineError::Table)?;
        let key = K::from_bytes(key);
        // The inverse displaces whatever is under the key now; that value
        // is compared against the journaled post-image **after** the
        // displacement, inside the same transaction — a mismatch poisons
        // the batch and nothing lands, so verify-after-displace costs no
        // extra read.
        let displaced: Option<[u8; 32]> = match prior {
            // Undo of an insert, or of an overwrite that found nothing:
            // the key must be present now, and goes.
            None => table
                .remove(&key)
                .map_err(EngineError::Storage)?
                .map(|guard| post_image(V::as_bytes(&guard.value()).as_ref())),
            // Undo of an overwrite that displaced `prior`: the key must be
            // present now, and gets `prior` back.
            Some(prior) => table
                .insert(&key, V::from_bytes(prior))
                .map_err(EngineError::Storage)?
                .map(|guard| post_image(V::as_bytes(&guard.value()).as_ref())),
        };
        Ok(match displaced {
            None => Undone::TargetMismatch,
            Some(found) if found == *post => Undone::Reversed,
            Some(_) => Undone::PostImageMismatch,
        })
    }
}

/// The batch's journal slot: at most one live [`Recording`].
///
/// A `RefCell` because writes reach it through the shared `&'txn` the
/// table handles hold, and a batch is single-threaded by construction
/// (the same shape as [`Poison`]).
#[derive(Default)]
pub(super) struct Journal {
    live: RefCell<Option<Live>>,
    /// Set when a [`Recording`] was dropped without [`Recording::seal`]:
    /// the writes it recorded may have landed in the transaction with no
    /// row to undo them, so `complete` refuses to commit.
    abandoned: Cell<Option<u64>>,
    /// The height the most recent connect, pop, or branded `chain_view`
    /// in this batch worked at — what the writer halt reports as
    /// `at_height` if the batch is poisoned. `None` for a batch that did
    /// none of those, which does not halt the writer (§3.6.2).
    height_hint: Cell<Option<u64>>,
}

struct Live {
    height: u64,
    entries: Vec<UndoEntry>,
}

impl Journal {
    /// Push `entry` if a recording is live; a no-op otherwise. `entry` is
    /// a closure so a handle pays for the byte copy only when recording.
    pub(super) fn record(&self, entry: impl FnOnce() -> UndoEntry) {
        if let Some(live) = self.live.borrow_mut().as_mut() {
            live.entries.push(entry());
        }
    }

    /// Whether a recording is live — the moment at which an uncatalogued
    /// table's handle cannot be written through.
    pub(super) fn is_recording(&self) -> bool {
        self.live.borrow().is_some()
    }

    /// The height of a recording that was dropped unsealed, if any.
    pub(super) fn abandoned(&self) -> Option<u64> {
        self.abandoned.get()
    }

    /// Remember that a connect, pop, or branded `chain_view` is working at
    /// `height`.
    pub(super) fn note_height(&self, height: u64) {
        self.height_hint.set(Some(height));
    }

    /// The height chain work in this batch was at, if any.
    pub(super) fn height_hint(&self) -> Option<u64> {
        self.height_hint.get()
    }
}

/// A live journal for one height, handed out by
/// [`WriteBatch::record_undo`](super::WriteBatch::record_undo).
///
/// Sealing writes the row; dropping without sealing marks the batch's
/// journal abandoned and `complete` then refuses with
/// [`StoreCannot::UndoUnsealed`] — writes with no pre-images must not
/// land. There is at most one live recording per batch; beginning a second
/// is a bug in this crate and panics with the height that was still open.
#[must_use = "a Recording must be sealed, or the batch refuses to commit"]
pub(crate) struct Recording<'txn> {
    journal: &'txn Journal,
    poison: &'txn Poison,
    txn: &'txn WriteTransaction,
    /// The height this recording is for — kept on the recording itself so
    /// `Drop` can mark the journal abandoned even after `seal` has taken
    /// the live slot and then failed to write the row.
    height: u64,
    /// Set only once the row's insert has **succeeded**: every failed seal
    /// leaves the recording unsealed, and `Drop` marks it abandoned.
    sealed: bool,
}

impl<'txn> Recording<'txn> {
    pub(super) fn begin(
        journal: &'txn Journal,
        poison: &'txn Poison,
        txn: &'txn WriteTransaction,
        height: u64,
    ) -> Self {
        let mut slot = journal.live.borrow_mut();
        assert!(
            slot.is_none(),
            "a journal recording is already live on this batch (height {}); connect seals \
             before the next begins",
            slot.as_ref().map_or(0, |l| l.height)
        );
        *slot = Some(Live {
            height,
            entries: Vec::new(),
        });
        drop(slot);
        journal.note_height(height);
        Self {
            journal,
            poison,
            txn,
            height,
            sealed: false,
        }
    }

    /// Write `undo_log[height]` and end the recording. Returns the number
    /// of entries the row carries.
    ///
    /// The row's insert is the one write of the connect that is **not**
    /// journaled: the recording is taken out of the slot before it runs.
    ///
    /// # Errors
    ///
    /// [`StoreInvariant::UndoLogIncoherent`] (SI-6, poisons the batch) if a
    /// row is already recorded at this height; [`EngineError::Table`] /
    /// [`EngineError::Storage`] if the engine refuses.
    pub(crate) fn seal(mut self) -> Result<usize, StoreError> {
        let Live { height, entries } = self
            .journal
            .live
            .borrow_mut()
            .take()
            .expect("a Recording holds the journal slot until it is sealed or dropped");
        debug_assert_eq!(height, self.height);
        let count = entries.len();
        let mut table = self.txn.open_table(UNDO_LOG).map_err(EngineError::Table)?;
        if table.get(height).map_err(EngineError::Storage)?.is_some() {
            return Err(self.poison.arm(StoreInvariant::UndoLogIncoherent {
                height,
                fault: UndoFault::RowAlreadyRecorded,
            }));
        }
        table
            .insert(height, UndoLog(entries).encoded().as_encoded())
            .map_err(EngineError::Storage)?;
        // Only now: an open/read/insert failure above returns with
        // `sealed == false`, so a caller that swallows the error still
        // cannot commit the journaled writes without their row.
        self.sealed = true;
        Ok(count)
    }
}

impl Drop for Recording<'_> {
    fn drop(&mut self) {
        if self.sealed {
            return;
        }
        // The live slot may already be empty (a `seal` that failed after
        // taking it); the height on the recording is what `complete` names.
        self.journal.live.borrow_mut().take();
        self.journal.abandoned.set(Some(self.height));
    }
}

/// What [`replay`] found at a height.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Replayed {
    /// The row existed; this many entries were reversed and the row deleted.
    Entries(usize),
    /// No row at that height — the pop floor (`pop` names it
    /// `StoreCannot::PopBelowFloor`).
    NoRow,
}

/// Reverse-replay `undo_log[height]` in `txn` and delete the row.
///
/// Not itself journaled: the caller (`pop`) holds no recording, and the
/// entries being reversed *are* the journal. Every SI-6 / SI-7 outcome is
/// routed through `poison` so the batch cannot commit past it.
///
/// # Errors
///
/// [`StoreInvariant::CellCorrupt`] (SI-7) if the row does not decode or an
/// entry names a table the catalogue does not have or bytes its table
/// cannot restore; [`StoreInvariant::UndoLogIncoherent`] (SI-6) if an
/// entry's target is not in the state the entry left; engine errors.
pub(super) fn replay(
    txn: &WriteTransaction,
    poison: &Poison,
    height: u64,
) -> Result<Replayed, StoreError> {
    let row = {
        let table = txn.open_table(UNDO_LOG).map_err(EngineError::Table)?;
        let Some(guard) = table.get(height).map_err(EngineError::Storage)? else {
            return Ok(Replayed::NoRow);
        };
        guard
            .value()
            .decode()
            .map_err(|cause| poison.arm(corrupt(cause)))?
    };
    for (index, entry) in row.0.iter().enumerate().rev() {
        let index = u32::try_from(index).expect("a decoded row has a u32 count");
        let Some(target) = schema::undo_target(entry.table()) else {
            return Err(poison.arm(corrupt(CodecError::Invalid {
                codec: UndoLog::NAME,
                reason: "entry names a table ordinal the catalogue does not have",
            })));
        };
        match target.undo(txn, entry)? {
            Undone::Reversed => {}
            Undone::TargetMismatch => {
                return Err(poison.arm(StoreInvariant::UndoLogIncoherent {
                    height,
                    fault: UndoFault::EntryNotReversible { index },
                }))
            }
            Undone::PostImageMismatch => {
                return Err(poison.arm(StoreInvariant::UndoLogIncoherent {
                    height,
                    fault: UndoFault::PostImageMismatch { index },
                }))
            }
            Undone::Malformed(reason) => {
                return Err(poison.arm(corrupt(CodecError::Invalid {
                    codec: UndoLog::NAME,
                    reason,
                })))
            }
        }
    }
    let mut table = txn.open_table(UNDO_LOG).map_err(EngineError::Table)?;
    table
        .remove(height)
        .map_err(EngineError::Storage)?
        .expect("the row was read at the top of replay and nothing else deletes it");
    Ok(Replayed::Entries(row.0.len()))
}

/// The pop journal's row named as the typed cell SI-7 covers.
const fn corrupt(cause: CodecError) -> StoreInvariant {
    StoreInvariant::CellCorrupt {
        key: "undo_log",
        fault: CellFault::Undecodable(cause),
    }
}

/// The refusal `complete` returns for an abandoned recording, so the two
/// sites that name it cannot drift.
pub(super) const fn unsealed(height: u64) -> StoreCannot {
    StoreCannot::UndoUnsealed { height }
}
