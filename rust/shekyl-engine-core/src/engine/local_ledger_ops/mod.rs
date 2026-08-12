// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! User-authored, crash-atomic ledger mutations that are **not** transfer,
//! scan, or stake pipelines (`ENGINE_COMPOSITION_DECOMPOSITION.md` §2).
//!
//! These ops share a mechanical shape (one ledger write guard → mutate →
//! `drive_persistence` → fail-closed rollback) and a product shape (local
//! UX / journal intent the chain cannot reconstruct). They are grouped here
//! so the composition root (`engine/mod.rs`) registers **one** workflow
//! tree rather than accreting a top-level `pub mod` per small operation.
//!
//! | Module | Surface |
//! |--------|---------|
//! | [`abandon_tx`] | Send-journal abandon (P3-4 / SJ-DQ-8) |
//! | [`set_tx_note`] | Per-txid annotation (SJ-DQ-7) |
//!
//! Inherent `Engine` methods still live on the orchestrator type (same as
//! `payment_requests` / `message_signing`'s thin façade); this directory is
//! ownership of the **workflow code**, not a second type parameter on
//! `Engine`.
//!
//! The shared half of that shape is [`Engine::save_or_rollback`] below —
//! owned once here rather than copied into each member. Naming a shape in
//! prose and then implementing it N times is how the copies drift: the whole
//! value of the fail-closed contract is that *every* op honours it, and a
//! contract enforced by N independent copies is only as strong as the one
//! someone forgets to update.

pub mod abandon_tx;
pub mod set_tx_note;

pub use abandon_tx::{AbandonTxError, AbandonTxOutcome};
pub use set_tx_note::SetTxNoteError;

use crate::engine::error::PersistenceError;
use crate::engine::lifecycle::drive_persistence;
use crate::engine::local_ledger::LedgerState;
use crate::engine::traits::{DaemonEngine, PendingTxEngine, PersistenceEngine, RefreshEngine};
use crate::engine::{Engine, EngineSignerKind, LocalLedger};

#[allow(private_bounds)]
impl<
        S: EngineSignerKind,
        D: DaemonEngine,
        E: crate::engine::traits::EconomicsEngine,
        R: RefreshEngine,
        P: PendingTxEngine,
        F: PersistenceEngine,
    > Engine<S, D, LocalLedger, E, R, P, F>
{
    /// Durably commit the ledger the caller has already mutated, or undo that
    /// mutation and refuse (fail closed).
    ///
    /// Takes the caller's write guard by `&mut` rather than acquiring its
    /// own. That is the invariant this helper exists to own: mutation, save,
    /// and rollback must be one exclusive critical section, so a concurrent
    /// refresh merge or watchdog cannot interleave between the failed save
    /// and the undo and have the undo clobber its edge. Re-locking here would
    /// make that split representable — and would deadlock on a caller that
    /// still holds the guard, which every caller does.
    ///
    /// `undo` runs on save failure, under that same guard, and must restore
    /// the pre-mutation shape — but **only when the failed save left the
    /// on-disk file unchanged**. `WalletFile::save_state` writes via
    /// `atomic_write_file` (temp → fsync → `rename(2)` → parent fsync); every
    /// failure up to and including the `rename` leaves the target
    /// byte-unchanged, so undo restores the state that is still on disk. The
    /// **one exception** is a post-rename parent-directory fsync failure: the
    /// rename already committed the new file, so an undo would diverge memory
    /// from the now-current disk. In that case the mutation is kept (memory
    /// still matches disk) and the error is still returned — the write is
    /// applied but its crash-durability is unconfirmed, and a fail-closed
    /// retry re-runs the save and re-establishes durability idempotently.
    /// [`PersistenceError::target_replaced`] draws that line.
    ///
    /// # Errors
    ///
    /// [`PersistenceError`] when the durable save failed. For a
    /// target-unchanged failure the undo has run, so the wallet is back at
    /// its pre-mutation state and a retry starts from there; for the
    /// post-rename durability failure the mutation stands and a retry
    /// re-confirms durability. Callers wrap this in their own
    /// `…::Persistence` arm so each op keeps its own refusal vocabulary.
    pub(crate) fn save_or_rollback(
        &self,
        guard: &mut std::sync::RwLockWriteGuard<'_, LedgerState>,
        undo: impl FnOnce(&mut LedgerState),
    ) -> Result<(), PersistenceError> {
        let save_result = drive_persistence(
            self.persistence
                .save_state(self.state_wrap_key(), &guard.ledger),
        );
        if let Err(e) = save_result {
            let e: PersistenceError = e.into();
            // Undo only when the on-disk file is unchanged; keep the mutation
            // when the write already reached disk (post-rename fsync failure)
            // so memory does not diverge from it.
            if !e.target_replaced() {
                undo(guard);
            }
            return Err(e);
        }
        Ok(())
    }
}
