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
    /// `undo` runs **only** on save failure, under that same guard, and must
    /// restore the pre-mutation shape. `WalletFile::save_state` returns `Err`
    /// only for a failure that left the on-disk state **byte-unchanged**: its
    /// `atomic_write_file` reports a completed write whose post-rename
    /// durability fsync failed as `Ok`, not `Err`, so an error here always
    /// means the target was never replaced — which is what makes an in-memory
    /// undo sufficient rather than a partial repair.
    ///
    /// # Errors
    ///
    /// [`PersistenceError`] when the durable save failed. The undo has
    /// already run, so the wallet is back at its pre-mutation state and a
    /// retry starts from there. Callers wrap this in their own
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
            undo(guard);
            return Err(e.into());
        }
        Ok(())
    }
}
