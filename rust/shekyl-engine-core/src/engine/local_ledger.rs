// Copyright (c) 2025-2026, The Shekyl Foundation
//
// All rights reserved.
// BSD-3-Clause

//! `LocalLedger`: the Stage 1 in-process implementor of [`LedgerEngine`].
//!
//! Per `docs/design/STAGE_1_PR_2_LEDGER_ENGINE.md` §3.1, `LocalLedger`
//! aggregates the wallet's [`WalletLedger`] and [`LedgerIndexes`] under
//! a single [`std::sync::RwLock`] so the existing in-process orchestration
//! can call into [`LedgerEngine`] methods through `&self` rather than
//! `&mut self`. The `&self` shape matches the trait surface (§3.1) and,
//! transitively, the Stage 4 actor swap-in.
//!
//! # Aggregation rationale (§3.3)
//!
//! [`WalletLedger`] (the persisted scanner-derived slice) and
//! [`LedgerIndexes`] (the runtime-only index projection rebuilt at
//! every open) are mutated together by the merge body in
//! `apply_scan_result_to_state`. The 2026-04-25 `RuntimeWalletState
//! audit` Decision Log entry establishes that the indexes shadow
//! `WalletLedger`'s outputs and must not drift from them; co-locating
//! both behind the same lock is the structural guarantee of that
//! invariant. Splitting them across two locks would re-introduce the
//! drift risk by allowing the two halves to be taken in different
//! orders.
//!
//! # Lock shape (§3.2)
//!
//! [`LocalLedger`] uses `std::sync::RwLock<LedgerState>` (synchronous,
//! not `tokio::sync::RwLock`) because:
//!
//! - The merge body in `apply_scan_result_to_state` is purely
//!   synchronous: it computes invariants, applies per-height events,
//!   and returns. No `.await` runs while the write guard is held.
//! - The read paths (`synced_height`, `snapshot`, `balance`) are
//!   pure projections over the borrowed state and never `.await`
//!   either. Per-transaction history is read directly from the
//!   underlying [`LedgerBlock`](shekyl_engine_state::LedgerBlock)'s
//!   `transfers()` slice accessor rather than through the trait
//!   surface — see the Phase 0c amendment in
//!   `docs/V3_ENGINE_TRAIT_BOUNDARIES.md` §2.2.
//!
//! Holding a `std::sync::RwLock` guard across `.await` would risk a
//! deadlock once Stage 4's actor surface introduces async handlers;
//! the trait surface (`apply_scan_result` returns `impl Future`) is
//! shaped such that the implementor — not the caller — chooses when
//! to acquire the lock, so the synchronous lock stays inside the
//! synchronous merge body and never crosses an await boundary.
//!
//! If a future read or write method needs to hold the lock across
//! `await`, swap to `tokio::sync::RwLock` at that time. The trait
//! surface does not change.
//!
//! # Lock-poisoning policy (§5.1)
//!
//! Lock poisoning indicates that a previous holder of the write guard
//! panicked mid-merge — by definition leaving wallet state in an
//! ambiguous condition that the merge invariants cannot recover from.
//! [`LocalLedger::read`] and [`LocalLedger::write`] therefore panic
//! on poisoning rather than surfacing the [`PoisonError`]: the
//! correct response to corrupt wallet state is process termination,
//! not silent continuation. This matches the §5.1 `RuntimeFailure`
//! discipline that treats lock poisoning as a wallet-state defect,
//! not a recoverable error.
//!
//! # Stage-4 swap-in
//!
//! At Stage 4, [`LocalLedger`] is replaced by `ActorRef<LedgerActor>`
//! at `LedgerEngine` bound sites. [`LocalLedger`] itself is deleted.
//! The [`LedgerState`] aggregate becomes the actor's owned state; the
//! `RwLock` is removed because the actor mailbox serializes access.
//! Trait method signatures do not change.
//!
//! [`LedgerEngine`]: super::traits::LedgerEngine
//! [`WalletLedger`]: shekyl_engine_state::WalletLedger
//! [`LedgerIndexes`]: shekyl_engine_state::LedgerIndexes
//! [`PoisonError`]: std::sync::PoisonError

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use shekyl_engine_state::{LedgerIndexes, WalletLedger};
use shekyl_scanner::{BalanceSummary, LedgerBlockExt};

use super::{
    error::{LedgerError, RefreshError},
    merge::apply_scan_result_to_state,
    refresh::LedgerSnapshot,
    traits::LedgerEngine,
};
use crate::scan::ScanResult;

/// The wallet's confirmed-chain state, paired with the runtime-only
/// [`LedgerIndexes`] derived from it.
///
/// `LedgerState` is the inner aggregate that [`LocalLedger`]'s
/// [`RwLock`] guards. Both fields are accessed together by the merge
/// body in [`super::merge::apply_scan_result_to_state`]; the
/// matured-output index in [`LedgerIndexes`] is the index projection
/// of [`WalletLedger`]'s outputs and must not drift from it.
///
/// At Stage 4 this aggregate moves into `LedgerActor` as owned state;
/// the lock disappears because the actor mailbox serializes access.
pub(crate) struct LedgerState {
    /// The persisted wallet-state slice the merge body writes and
    /// the projection methods (`balance`, `snapshot`) read.
    pub(crate) ledger: WalletLedger,
    /// Runtime indexes derived from `ledger`. Mutated together with
    /// `ledger` under the write guard; rebuilt on every
    /// `Engine::open*`.
    pub(crate) indexes: LedgerIndexes,
}

/// Stage 1 implementor of [`LedgerEngine`](super::traits::LedgerEngine).
///
/// Wraps [`LedgerState`] in a synchronous [`RwLock`] so the existing
/// `Engine<S, D>` call sites can read and write the wallet ledger
/// through `&self` rather than `&mut self`.
///
/// # Why `pub(crate)`
///
/// Stage 1 holds external visibility of the trait at `pub(crate)`
/// per the design doc §1.4 visibility policy. Once Stage 1 is
/// complete and the `Engine<S, D, L: LedgerEngine>` generic surface
/// is promoted to `pub` in V3.2, [`LocalLedger`] is promoted
/// alongside it — at which point external callers constructing an
/// `Engine` choose between [`LocalLedger`] (the default) and
/// `ActorRef<LedgerActor>` (Stage 4).
pub(crate) struct LocalLedger {
    state: RwLock<LedgerState>,
}

impl LocalLedger {
    /// Wrap the given [`WalletLedger`] / [`LedgerIndexes`] pair under
    /// a fresh [`RwLock`].
    ///
    /// Used by the engine constructors (`Engine::create`,
    /// `Engine::open_full`) when assembling the engine from
    /// freshly-loaded persisted state.
    pub(crate) fn new(ledger: WalletLedger, indexes: LedgerIndexes) -> Self {
        Self {
            state: RwLock::new(LedgerState { ledger, indexes }),
        }
    }

    /// Acquire a read guard over the wallet's ledger state.
    ///
    /// # Panics
    ///
    /// Panics on lock poisoning per the module-level lock-poisoning
    /// policy: a previous panic mid-merge has left wallet state in
    /// an ambiguous condition that the read methods cannot
    /// distinguish from valid state.
    pub(crate) fn read(&self) -> RwLockReadGuard<'_, LedgerState> {
        self.state.read().expect("LocalLedger lock poisoned")
    }

    /// Acquire a write guard over the wallet's ledger state.
    ///
    /// # Panics
    ///
    /// Panics on lock poisoning per the module-level lock-poisoning
    /// policy.
    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, LedgerState> {
        self.state.write().expect("LocalLedger lock poisoned")
    }
}

/// Stage 1 in-process implementation of [`LedgerEngine`].
///
/// Each method acquires its own [`RwLock`] guard for the duration of
/// the call. The three read methods take a [`RwLockReadGuard`] and
/// project owned values (`u64`, [`LedgerSnapshot`],
/// [`BalanceSummary`]); the lone mutator takes a
/// [`RwLockWriteGuard`] and delegates to
/// [`apply_scan_result_to_state`], the merge body shared with
/// [`Engine::apply_scan_result`](super::Engine::apply_scan_result).
///
/// The mutator returns an `impl Future` rather than `async fn` to
/// match the trait declaration verbatim. The future body is wholly
/// synchronous — no `.await` runs while the write guard is held —
/// so the synchronous [`std::sync::RwLock`] is sound (per the
/// module-level lock-shape rationale).
impl LedgerEngine for LocalLedger {
    type Error = LedgerError;

    fn synced_height(&self) -> u64 {
        self.read().ledger.ledger.height()
    }

    fn snapshot(&self) -> LedgerSnapshot {
        let guard = self.read();
        LedgerSnapshot::from_ledger(&guard.ledger.ledger)
    }

    fn balance(&self) -> BalanceSummary {
        let guard = self.read();
        let ledger = &guard.ledger.ledger;
        ledger.balance(ledger.height())
    }

    async fn apply_scan_result(&self, scan_result: ScanResult) -> Result<(), RefreshError> {
        let mut guard = self.write();
        let state = &mut *guard;
        apply_scan_result_to_state(&mut state.ledger.ledger, &mut state.indexes, scan_result)
    }
}
